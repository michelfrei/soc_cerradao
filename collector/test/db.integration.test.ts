// Testes contra um PostgreSQL real preparado com postgres/bootstrap.sql e as migrações.
// Rodam só quando SOC_TEST_PG_HOST está definido (ver scripts/test-integration.ps1).
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ensurePartitions, insertEvents, setCheckpoint, getCheckpoint, upsertObjects, withTransaction, type RunCounters } from '../src/db.js';
import { parseSources, type HuntingSourceConfig, type InventorySourceConfig, type SnapshotSourceConfig } from '../src/config.js';
import type { GraphClient } from '../src/graph/client.js';
import type { Logger } from '../src/logger.js';
import { collectHunting, toEventRow } from '../src/sources/hunting.js';
import { toObjectRow } from '../src/sources/objects.js';
import { collectInventory } from '../src/sources/inventory.js';
import { collectSnapshot, snapshotRows, storeSnapshot } from '../src/sources/snapshot.js';
import { storeInsights } from '../src/sources/insights.js';
import { EMPTY_CATALOG } from '../src/insights/catalog.js';
import { insightId } from '../src/insights/engine.js';
import type { InsightsSourceConfig } from '../src/config.js';

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

  it('inventário promove esperado sem duplicar publicação e mantém silencioso', async () => {
    const src = parseSources({ sources: [{ name: 'test.inventory', type: 'inventory' }] },
      () => 'DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId')[0] as InventorySourceConfig;
    let results: Record<string, unknown>[] = [];
    const graph = { request: async () => ({ results }) } as unknown as GraphClient;
    const log = { info() {}, warn() {}, error() {}, debug() {} } as unknown as Logger;
    const deps = { pool: collector, graph, log, assets: [{ name: 'srv-inventory-test', owner: 'SOC' }] };
    const counters = (): RunCounters => ({ fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 });
    await collectInventory(src, deps, counters());
    results = [{ DeviceId: 'inventory-test-id', DeviceName: 'SRV-INVENTORY-TEST',
      Timestamp: '2026-10-21T10:00:00.1234567Z', OSPlatform: 'WindowsServer2022' }];
    await collectInventory(src, deps, counters());
    results = [];
    await collectInventory(src, deps, counters());
    const state = await collector.query(`SELECT inventory_key, payload FROM soc.device_inventory
      WHERE device_id = 'inventory-test-id' OR inventory_key = 'expected:srv-inventory-test'`);
    expect(state.rows).toHaveLength(1);
    expect(state.rows[0]).toMatchObject({ inventory_key: 'expected:srv-inventory-test', payload: {
      SOCExpected: true, SOCObserved: false, SOCOwner: 'SOC', Timestamp: '2026-10-21T10:00:00.1234567Z',
    } });
    const pub = await logstash.query(`SELECT DISTINCT doc_id FROM soc.publication WHERE entity='device'
      AND payload->>'DeviceId'='inventory-test-id'`);
    expect(pub.rows).toEqual([{ doc_id: 'expected:srv-inventory-test' }]);
    await expect(logstash.query('SELECT * FROM soc.device_inventory')).rejects.toThrow(/permission denied/);
  });

  it('telemetria usa último run concluído, IDs por minuto e capacidade de partições sem acesso a raw', async () => {
    await collector.query(`INSERT INTO soc.collector_run (source, status, started_at, finished_at, fetched)
      VALUES ('test.telemetry', 'success', now() - interval '2 minutes', now() - interval '1 minute', 7),
             ('test.telemetry', 'running', now(), NULL, 999)`);
    const sample = await logstash.query(`SELECT dataset, doc_id, payload_json FROM soc.v_telemetry`);
    const status = sample.rows.find((r) => JSON.parse(r.payload_json).source === 'test.telemetry');
    expect(JSON.parse(status.payload_json)).toMatchObject({ status: 'success', fetched: 7, lag_seconds: null });
    const capacity = sample.rows.find((r) => r.dataset === 'database_capacity');
    expect(JSON.parse(capacity.payload_json)).toMatchObject({ source: 'database.capacity' });
    expect(Number(JSON.parse(capacity.payload_json).raw_bytes)).toBeGreaterThan(0);
    expect(Number(JSON.parse(capacity.payload_json).database_bytes)).toBeGreaterThan(0);
    const repeated = await logstash.query(`SELECT doc_id FROM soc.v_telemetry WHERE dataset='database_capacity'`);
    expect(repeated.rows[0].doc_id).toBe(capacity.doc_id);
  });

  it('snapshot completo publica observados, tombstone somente de recém-ausente e reaparece na mesma identidade', async () => {
    const src = parseSources({ sources: [{ name: 'test.posture.lifecycle', type: 'snapshot',
      table: 'DeviceTvmSoftwareVulnerabilities', queryFile: 'tvm.kql', maxRows: 100 }] },
    () => 'DeviceTvmSoftwareVulnerabilities')[0] as SnapshotSourceConfig;
    const dataset = src.table.toLowerCase();
    const first = { DeviceId: 'posture-test-device', DeviceName: 'srv-posture-test', CveId: 'CVE-2026-0001',
      SoftwareVendor: 'Test', SoftwareName: 'App', SoftwareVersion: '1.0' };
    const second = { ...first, SoftwareVersion: '2.0' };
    const t0 = new Date('2026-10-21T10:00:00Z');
    const t1 = new Date('2026-10-21T11:00:00Z');
    const t2 = new Date('2026-10-21T12:00:00Z');
    const t3 = new Date('2026-10-21T13:00:00Z');
    const save = async (raw: Record<string, unknown>[], at: Date) =>
      withTransaction(collector, (client) => storeSnapshot(client, src, snapshotRows(src, raw, at), at));
    expect(await save([first, second], t0)).toEqual({ inserted: 2, changed: 2 });
    expect(await save([first], t1)).toEqual({ inserted: 0, changed: 2 });
    const secondKey = snapshotRows(src, [second], t0)[0]!.key;
    const state = await collector.query('SELECT active, payload FROM soc.posture_state WHERE dataset=$1 AND doc_id=$2', [dataset, secondKey]);
    expect(state.rows[0]).toMatchObject({ active: false, payload: {
      SOCActive: false, SOCState: 'no_longer_reported', SOCSnapshotAt: t1.toISOString(),
    } });
    // Uma ausência já publicada não ganha data nova a cada snapshot seguinte.
    expect(await save([first], t2)).toEqual({ inserted: 0, changed: 1 });
    const oldTombstone = await collector.query('SELECT snapshot_at FROM soc.posture_state WHERE dataset=$1 AND doc_id=$2', [dataset, secondKey]);
    expect(oldTombstone.rows[0].snapshot_at.toISOString()).toBe(t1.toISOString());
    expect(await save([first, second], t3)).toEqual({ inserted: 0, changed: 2 });
    const restored = await collector.query('SELECT active, payload FROM soc.posture_state WHERE dataset=$1 AND doc_id=$2', [dataset, secondKey]);
    expect(restored.rows[0]).toMatchObject({ active: true, payload: { SOCActive: true, SOCState: 'observed' } });
    const pub = await logstash.query(`SELECT payload FROM soc.publication WHERE entity='posture' AND dataset=$1 AND doc_id=$2 ORDER BY id`, [dataset, secondKey]);
    expect(pub.rows.map((r) => r.payload.SOCState)).toEqual(['observed', 'no_longer_reported', 'observed']);
    await expect(logstash.query('SELECT * FROM soc.posture_state')).rejects.toThrow(/permission denied/);
  });

  it('falha/limite/parcial e rollback preservam snapshot/checkpoint/publicação; staleguard vale por dataset', async () => {
    const src = parseSources({ sources: [{ name: 'test.posture.transaction', type: 'snapshot',
      table: 'DeviceTvmSecureConfigurationAssessment', queryFile: 'tvm.kql', maxRows: 100 }] },
    () => 'DeviceTvmSecureConfigurationAssessment')[0] as SnapshotSourceConfig;
    const raw = { DeviceId: 'posture-config-device', DeviceName: 'fisico-posture-test', ConfigurationId: 'scid-test',
      Timestamp: '2026-10-21T14:00:00.1234567Z', Context: { b: 2, a: 1 }, IsApplicable: true, IsCompliant: false };
    const t0 = new Date('2026-10-21T14:30:00Z');
    const dataset = src.table.toLowerCase();
    const rows = snapshotRows(src, [raw], t0);
    await withTransaction(collector, (client) => storeSnapshot(client, src, rows, t0));
    const pubCount = async () => {
      const result = await logstash.query(`SELECT count(*)::int AS n FROM soc.publication WHERE entity='posture' AND dataset=$1`, [dataset]);
      return result.rows[0].n;
    };
    const before = await pubCount();
    const t1 = new Date('2026-10-21T15:30:00Z');
    await expect(withTransaction(collector, async (client) => {
      await storeSnapshot(client, src, [], t1);
      throw new Error('falha depois de gravar tombstone');
    })).rejects.toThrow(/falha depois/);
    expect(await pubCount()).toBe(before);
    expect((await getCheckpoint(collector, src.name))?.toISOString()).toBe(t0.toISOString());
    expect((await collector.query('SELECT active FROM soc.posture_state WHERE dataset=$1 AND doc_id=$2', [dataset, rows[0]!.key])).rows[0].active).toBe(true);
    // Alias sem checkpoint próprio não pode voltar o estado do dataset.
    await expect(withTransaction(collector, (client) => storeSnapshot(client, { ...src, name: 'test.posture.alias' }, [],
      new Date('2026-10-21T13:30:00Z')))).rejects.toThrow(/anterior/);
    const counters = (): RunCounters => ({ fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 });
    const log = { info() {}, warn() {}, error() {}, debug() {} } as unknown as Logger;
    for (const reply of [
      { results: Array.from({ length: 100 }, () => raw) },
      { results: [], error: { code: 'PartialError' } },
    ]) {
      const graph = { request: async () => reply } as unknown as GraphClient;
      await expect(collectSnapshot(src, { pool: collector, graph, log }, counters())).rejects.toThrow(/recusado/);
    }
    const graph = { request: async () => { throw new Error('Graph 403 tabela indisponível'); } } as unknown as GraphClient;
    await expect(collectSnapshot(src, { pool: collector, graph, log }, counters())).rejects.toThrow(/403/);
    expect(await pubCount()).toBe(before);
    expect((await getCheckpoint(collector, src.name))?.toISOString()).toBe(t0.toISOString());
    // Vazio válido publica ausência sem dizer que a configuração foi corrigida.
    await withTransaction(collector, (client) => storeSnapshot(client, src, [], t1));
    const final = await collector.query('SELECT payload FROM soc.posture_state WHERE dataset=$1 AND doc_id=$2', [dataset, rows[0]!.key]);
    expect(final.rows[0].payload).toMatchObject({ SOCState: 'no_longer_reported', SOCActive: false,
      IsCompliant: false, Timestamp: raw.Timestamp });
  });

  it('processo/rede validam nomes localmente sem allowlist do inventário', async () => {
    for (const table of ['DeviceProcessEvents', 'DeviceNetworkEvents']) {
      const src = parseSources({ sources: [{ name: `test.scope.${table.toLowerCase()}`, type: 'hunting', table,
        queryFile: 'test.kql', initialLookbackHours: 1, overlapMinutes: 0, ingestionLagMinutes: 0,
        maxWindowMinutes: 15, maxWindowsPerRun: 1 }] },
      () => `${table} | where Timestamp >= datetime({{start}}) and Timestamp < datetime({{end}})`)[0] as HuntingSourceConfig;
      const graph = { request: async () => ({ results: [
        { DeviceId: `new-${table}`, DeviceName: 'SRV-UNKNOWN-TO-CATALOG', Timestamp: '2026-10-21T14:00:00Z', ReportId: 1 },
        { DeviceId: `excluded-note-${table}`, DeviceName: 'srv-note', Timestamp: '2026-10-21T14:00:00Z', ReportId: 2 },
        { DeviceId: `excluded-micro-${table}`, DeviceName: 'fisico-micro', Timestamp: '2026-10-21T14:00:00Z', ReportId: 3 },
      ] }) } as unknown as GraphClient;
      const log = { info() {}, warn() {}, error() {}, debug() {} } as unknown as Logger;
      const counters: RunCounters = { fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 };
      await collectHunting(src, { pool: collector, graph, log }, counters);
      expect(counters.inserted).toBe(1);
      const result = await collector.query('SELECT device_name FROM soc.raw_event WHERE table_name=$1 AND source=$2', [table, src.name]);
      expect(result.rows).toEqual([{ device_name: 'SRV-UNKNOWN-TO-CATALOG' }]);
    }
  });
  it('insights: exigem snapshots, publicam na mesma transação e encerram como no_longer_reported', async () => {
    const snap = (name: string, table: string) => ({ name, type: 'snapshot', table, queryFile: 'q.kql', maxRows: 100 });
    const parsed = parseSources({ sources: [
      snap('test.insights.vuln', 'DeviceTvmSoftwareVulnerabilities'),
      snap('test.insights.config', 'DeviceTvmSecureConfigurationAssessment'),
      { name: 'test.insights', type: 'insights', vulnerabilitySource: 'test.insights.vuln',
        configurationSource: 'test.insights.config', softwareInventorySource: null },
    ] }, (f) => (f === 'q.kql' ? 'DeviceTvmSoftwareVulnerabilities' : ''));
    const vulnSrc = parsed[0] as SnapshotSourceConfig;
    const configSrc = { ...vulnSrc, name: 'test.insights.config', table: 'DeviceTvmSecureConfigurationAssessment' } as SnapshotSourceConfig;
    const src = parsed[2] as InsightsSourceConfig;
    const t0 = new Date('2026-12-01T10:00:00Z');
    const t1 = new Date('2026-12-01T16:00:00Z');
    const run = (at: Date) => withTransaction(collector, (client) => storeInsights(client, src, EMPTY_CATALOG, at));

    await expect(run(t0)).rejects.toThrow(/sem snapshot concluído/);
    expect((await collector.query("SELECT 1 FROM soc.collector_checkpoint WHERE source='test.insights'")).rowCount).toBe(0);

    const row = { DeviceId: 'insight-dev', DeviceName: 'srv-insight', CveId: 'CVE-2026-9999',
      SoftwareVendor: 'insightvendor', SoftwareName: 'insightapp', SoftwareVersion: '1.0', IsExploitAvailable: true };
    const save = (s: SnapshotSourceConfig, raw: Record<string, unknown>[], at: Date) =>
      withTransaction(collector, (client) => storeSnapshot(client, s, snapshotRows(s, raw, at), at));
    await save(vulnSrc, [row], t0);
    await save(configSrc, [], t0);
    const before = await lastTxid();
    const first = await run(t0);
    expect(first.inserted).toBeGreaterThanOrEqual(1);
    const id = insightId('application_update', 'insightvendor|insightapp');
    const state = await collector.query('SELECT status, first_seen, payload FROM soc.remediation_insight WHERE insight_id=$1', [id]);
    expect(state.rows[0]).toMatchObject({ status: 'open', payload: { exploit_available: true, affected_device_count: 1, cve_ids: ['CVE-2026-9999'] } });
    const pub = await logstash.query(LOGSTASH_QUERY, [before]);
    expect(pub.rows.some((r) => r.entity === 'insight' && r.doc_id === id)).toBe(true);

    await save(vulnSrc, [], t1);
    await run(t1);
    const closed = await collector.query('SELECT status, first_seen, payload FROM soc.remediation_insight WHERE insight_id=$1', [id]);
    expect(closed.rows[0]).toMatchObject({ status: 'no_longer_reported', payload: { status: 'no_longer_reported',
      resolved_at: t1.toISOString(), first_seen: t0.toISOString(), last_seen: t0.toISOString(), affected_device_count: 1 } });
    // Execução mais antiga não sobrescreve estado mais novo.
    await expect(run(t0)).rejects.toThrow(/anterior ao último cálculo/);
    const kept = await collector.query('SELECT status FROM soc.remediation_insight WHERE insight_id=$1', [id]);
    expect(kept.rows[0].status).toBe('no_longer_reported');
    await expect(logstash.query('SELECT * FROM soc.remediation_insight')).rejects.toThrow(/permission denied/);
  });
});
