import { describe, expect, it } from 'vitest';
import { parseSources } from '../src/config.js';
import { fetchFlows, flowDoc, flowQuery, plannedHours, toFlowRow } from '../src/sources/fwflows.js';
import type { ElasticSearcher } from '../src/elastic/client.js';

const src = { lagMinutes: 15, initialLookbackHours: 6, maxHoursPerRun: 24, recomputeHours: 1 };
const iso = (d: Date[]) => d.map((h) => h.toISOString().slice(11, 16));

describe('horas planejadas', () => {
  const now = new Date('2026-10-27T15:10:00Z');

  it('sem checkpoint: lookback inicial só com horas completas antes do atraso', () => {
    // 15:10 - 15 min = 14:55: a hora 14h ainda não fechou.
    expect(iso(plannedHours(null, now, src))).toEqual(['08:00', '09:00', '10:00', '11:00', '12:00', '13:00']);
  });

  it('com checkpoint recalcula a hora anterior e segue até a última completa', () => {
    expect(iso(plannedHours(new Date('2026-10-27T12:00:00Z'), now, src))).toEqual(['11:00', '12:00', '13:00']);
    expect(iso(plannedHours(new Date('2026-10-27T14:00:00Z'), now, src))).toEqual(['13:00']);
  });

  it('limita horas por execução', () => {
    expect(plannedHours(new Date('2026-10-20T00:00:00Z'), now, { ...src, maxHoursPerRun: 3 })).toHaveLength(4);
  });
});

describe('consulta e linhas', () => {
  const hour = new Date('2026-10-27T13:00:00Z');

  it('server filtra por CIDR em origem ou destino; source não', () => {
    const q = JSON.stringify(flowQuery('server', hour, ['172.16.159.0/24']));
    expect(q).toContain('"source.ip":"172.16.159.0/24"');
    expect(q).toContain('"destination.ip":"172.16.159.0/24"');
    expect(q).toContain('"gte":"2026-10-27T13:00:00.000Z","lt":"2026-10-27T14:00:00.000Z"');
    expect(JSON.stringify(flowQuery('source', hour, ['172.16.159.0/24']))).not.toContain('172.16.159.0/24');
  });

  it('bucket vira linha com ID estável e documento publicado', () => {
    const b = { key: { source_ip: '172.20.15.99', direction: 'outbound', verdict: 'blocked' }, doc_count: 12,
      sent: { value: 1440 }, received: { value: 1400.4 }, destinations: { value: 3 },
      users: { buckets: [{ key: 'fulano' }] }, categories: { buckets: [{ key: 'SITES_BLOQUEADOS' }] }, rules: { buckets: [] } };
    const a = toFlowRow('source', hour, b);
    expect(a).toMatchObject({ kind: 'source', source_ip: '172.20.15.99', destination_ip: null, verdict: 'blocked', sessions: 12,
      bytes_sent: 1440, bytes_received: 1400, destinations: 3, users: ['fulano'], categories: ['SITES_BLOQUEADOS'] });
    expect(toFlowRow('source', hour, b).flow_id).toBe(a.flow_id);
    expect(toFlowRow('source', hour, { ...b, key: { ...b.key, verdict: 'allowed' } }).flow_id).not.toBe(a.flow_id);
    const doc = flowDoc(a, new Date('2026-10-27T14:20:00Z'), false);
    expect(doc).toMatchObject({ '@timestamp': '2026-10-27T13:00:00.000Z', kind: 'source', source: { ip: '172.20.15.99' },
      soc: { fw: { verdict: 'blocked' } }, fw: { sessions: 12, bytes_total: 2840 } });
    expect(doc.destination).toBeUndefined();
  });

  it('pagina o composite e marca a hora como truncada no limite', async () => {
    const page = (n: number, after?: Record<string, unknown>) => ({ aggregations: { flows: {
      buckets: Array.from({ length: n }, (_, i) => ({ key: { source_ip: `10.0.0.${i}`, destination_ip: '172.16.159.10', destination_port: 443,
        transport: 'tcp', direction: 'inbound', verdict: 'allowed' }, doc_count: 1 })), ...(after ? { after_key: after } : {}) } } });
    const calls: unknown[] = [];
    const es: ElasticSearcher = { search: async (_i, body) => { calls.push(body); return calls.length === 1 ? page(3, { x: 1 }) : page(2); } };
    const r = await fetchFlows(es, 'fw-logs-fortigate', 'server', hour, ['172.16.159.0/24'], 100);
    expect([r.rows.length, r.truncated, r.requests]).toEqual([5, false, 2]);
    expect(JSON.stringify(calls[1])).toContain('"after":{"x":1}');
    calls.length = 0;
    const limited = await fetchFlows(es, 'fw-logs-fortigate', 'server', hour, ['172.16.159.0/24'], 2);
    expect([limited.rows.length, limited.truncated]).toEqual([2, true]);
  });
});

describe('configuração', () => {
  it('padrões da fonte e CIDR validado', () => {
    const [s] = parseSources({ sources: [{ name: 'fw.flows', type: 'fwflows' }] }, () => '');
    expect(s).toMatchObject({ type: 'fwflows', index: 'fw-logs-fortigate', intervalSeconds: 3600, serverCidrs: ['172.16.159.0/24'], retentionDays: 30 });
    expect(() => parseSources({ sources: [{ name: 'fw.flows', type: 'fwflows', serverCidrs: ['172.16.159.0'] }] }, () => '')).toThrow(/CIDR/);
  });
});
