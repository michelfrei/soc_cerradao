// Testes contra um PostgreSQL real preparado com postgres/bootstrap.sql e as migrações.
// Rodam só quando SOC_TEST_PG_HOST está definido (ver scripts/test-integration.ps1).
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensurePartitions, insertEvents, setCheckpoint, getCheckpoint, upsertObjects, withTransaction, type RunCounters } from '../src/db.js';
import { parseSources, type HuntingSourceConfig } from '../src/config.js';
import type { GraphClient } from '../src/graph/client.js';
import type { Logger } from '../src/logger.js';
import { collectHunting, toEventRow } from '../src/sources/hunting.js';
import { toObjectRow } from '../src/sources/objects.js';

const host = process.env.SOC_TEST_PG_HOST;
const port = Number(process.env.SOC_TEST_PG_PORT ?? 5432);

// Mesma consulta usada pelo Logstash (logstash/pipeline/soc-publication.conf).
const LOGSTASH_QUERY = `
SELECT id, txid::text::bigint AS txid, entity, dataset, doc_id
FROM soc.publication
WHERE txid > ($1::bigint)::text::xid8
  AND txid < pg_snapshot_xmin(pg_current_snapshot())
ORDER BY txid, id`;

describe.skipIf(!host)('PostgreSQL (integração)', () => {
  let collector: pg.Pool;
  let logstash: pg.Pool;

  beforeAll(() => {
    const base = { host, port, database: 'soc', ssl: false as const };
    collector = new pg.Pool({ ...base, user: 'soc_collector', password: process.env.SOC_TEST_COLLECTOR_PASSWORD });
    logstash = new pg.Pool({ ...base, user: 'soc_logstash', password: process.env.SOC_TEST_LOGSTASH_PASSWORD });
  });

  afterAll(async () => {
    await collector?.end();
    await logstash?.end();
  });

  async function lastTxid(): Promise<number> {
    const r = await logstash.query<{ txid: string }>(LOGSTASH_QUERY, [0]);
    return r.rows.length ? Number(r.rows.at(-1)!.txid) : 0;
  }

  it('insere eventos, ignora repetidos e publica só os novos', async () => {
    const rows = [
      { Timestamp: '2026-09-30T23:59:59.9999999Z', DeviceId: 'd1', ReportId: 1, ActionType: 'LogonSuccess' },
      { Timestamp: '2026-10-01T00:00:00Z', DeviceId: 'd1', ReportId: 2, ActionType: 'LogonFailed' },
    ].map((r) => toEventRow('DeviceLogonEvents', r));

    await ensurePartitions(collector, new Date('2026-09-30T23:59:59Z'), new Date('2026-10-01T00:00:00Z'));
    const before = await lastTxid();

    const first = await withTransaction(collector, (c) => insertEvents(c, 'test', 'DeviceLogonEvents', rows));
    const again = await withTransaction(collector, (c) => insertEvents(c, 'test', 'DeviceLogonEvents', [...rows, ...rows]));
    expect(first).toBe(2);
    expect(again).toBe(0);

    const pub = await logstash.query(LOGSTASH_QUERY, [before]);
    expect(pub.rows.filter((r) => r.entity === 'event')).toHaveLength(2);
    expect(pub.rows[0]!.dataset).toBe('devicelogonevents');
  });

  it('grava versões apenas quando o incidente muda', async () => {
    const v1 = { id: 'inc-1', displayName: 'Teste', status: 'active', lastUpdateDateTime: '2026-10-20T10:00:00Z' };
    const v2 = { ...v1, status: 'resolved', lastUpdateDateTime: '2026-10-20T11:00:00Z' };

    const c1 = await withTransaction(collector, (c) => upsertObjects(c, 'incident', [toObjectRow('incidents', v1)]));
    const c2 = await withTransaction(collector, (c) => upsertObjects(c, 'incident', [toObjectRow('incidents', v1)]));
    const c3 = await withTransaction(collector, (c) => upsertObjects(c, 'incident', [toObjectRow('incidents', v2)]));
    // Resposta antiga chegando depois não pode voltar o estado.
    const c4 = await withTransaction(collector, (c) => upsertObjects(c, 'incident', [toObjectRow('incidents', { ...v1, severity: 'low' })]));
    expect([c1, c2, c3, c4]).toEqual([1, 0, 1, 0]);

    const state = await collector.query('SELECT status FROM soc.security_object WHERE kind = $1 AND id = $2', ['incident', 'inc-1']);
    expect(state.rows[0]!.status).toBe('resolved');
    const versions = await collector.query('SELECT count(*)::int AS n FROM soc.security_object_version WHERE id = $1', ['inc-1']);
    expect(versions.rows[0]!.n).toBe(2);
  });

  it('checkpoint fica na mesma transação dos dados', async () => {
    const row = toEventRow('DeviceLogonEvents', { Timestamp: '2026-10-01T01:00:00Z', DeviceId: 'd9', ReportId: 9 });
    await expect(
      withTransaction(collector, async (c) => {
        await insertEvents(c, 'test', 'DeviceLogonEvents', [row]);
        await setCheckpoint(c, 'rollback-test', new Date('2026-10-01T02:00:00Z'));
        throw new Error('falha simulada');
      }),
    ).rejects.toThrow('falha simulada');
    expect(await getCheckpoint(collector, 'rollback-test')).toBeNull();
    const n = await collector.query('SELECT count(*)::int AS n FROM soc.raw_event WHERE device_id = $1', ['d9']);
    expect(n.rows[0]!.n).toBe(0);
  });

  it('o Logstash não avança sobre transação ainda aberta', async () => {
    await ensurePartitions(collector, new Date('2026-10-02T00:00:00Z'), new Date('2026-10-02T00:00:00Z'));
    const before = await lastTxid();
    const a = await collector.connect();
    const b = await collector.connect();
    try {
      // A obtém xid primeiro e fica aberta; B obtém xid depois e confirma.
      await a.query('BEGIN');
      await insertEvents(a, 'test', 'DeviceLogonEvents', [toEventRow('DeviceLogonEvents', { Timestamp: '2026-10-02T00:00:00Z', DeviceId: 'A', ReportId: 1 })]);
      await b.query('BEGIN');
      await insertEvents(b, 'test', 'DeviceLogonEvents', [toEventRow('DeviceLogonEvents', { Timestamp: '2026-10-02T00:00:00Z', DeviceId: 'B', ReportId: 1 })]);
      await b.query('COMMIT');

      // B já está confirmada, mas fica retida enquanto A estiver aberta.
      const during = await logstash.query(LOGSTASH_QUERY, [before]);
      expect(during.rows).toHaveLength(0);

      await a.query('COMMIT');
      const after = await logstash.query(LOGSTASH_QUERY, [before]);
      expect(after.rows).toHaveLength(2);
    } finally {
      await a.query('ROLLBACK').catch(() => undefined);
      a.release();
      b.release();
    }
  });

  it('divide a janela, grava cada parte e só então avança o checkpoint', async () => {
    // Graph simulado: um evento por minuto; respostas com >= maxRows forçam a divisão.
    const queries: string[] = [];
    const graph = {
      async request(_m: string, _p: string, stats: { apiCalls: number }, body: { Query: string }) {
        stats.apiCalls++;
        queries.push(body.Query);
        const [, a, b] = /datetime\((.+?)\).*datetime\((.+?)\)/.exec(body.Query)!;
        const results = [];
        for (let t = Date.parse(a!); t < Date.parse(b!); t += 60_000) {
          results.push({ Timestamp: new Date(t).toISOString(), DeviceId: 'split', ReportId: t, ActionType: 'LogonSuccess' });
        }
        return { results };
      },
    } as unknown as GraphClient;
    const log = { info() {}, warn() {}, error() {}, debug() {} } as unknown as Logger;
    const src = {
      ...parseSources(
        { sources: [{ name: 'test.split', type: 'hunting', table: 'DeviceLogonEvents', queryFile: 'x.kql',
          initialLookbackHours: 2, ingestionLagMinutes: 0, overlapMinutes: 0, maxWindowMinutes: 120,
          minWindowMinutes: 1, maxRows: 100, maxWindowsPerRun: 1 }] },
        () => 'DeviceLogonEvents | where Timestamp >= datetime({{start}}) and Timestamp < datetime({{end}})',
      )[0]!,
    } as HuntingSourceConfig;
    const counters: RunCounters = { fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 };

    await collectHunting(src, { pool: collector, graph, log }, counters);

    // 120 min com maxRows 100: a primeira resposta (120) é descartada e a janela vira 2 x 60.
    expect(queries.length).toBe(3);
    expect(counters.inserted).toBe(120);
    expect(counters.fetched).toBe(120);
    const cp = await getCheckpoint(collector, 'test.split');
    expect(cp?.toISOString()).toBe(counters.windowEnd!.toISOString());
    const n = await collector.query("SELECT count(*)::int AS n FROM soc.raw_event WHERE device_id = 'split'");
    expect(n.rows[0]!.n).toBe(120);
  });

  it('o usuário do Logstash só lê a publicação', async () => {
    await expect(logstash.query('SELECT 1 FROM soc.raw_event LIMIT 1')).rejects.toThrow(/permission denied/);
    await expect(logstash.query("INSERT INTO soc.collector_checkpoint VALUES ('x', now())")).rejects.toThrow(/permission denied/);
  });
});
