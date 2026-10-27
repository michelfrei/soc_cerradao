import type { FwFlowsSourceConfig } from '../config.js';
import { getCheckpoint, setCheckpoint, withTransaction, type Client, type Pool, type RunCounters } from '../db.js';
import type { ElasticSearcher } from '../elastic/client.js';
import type { Logger } from '../logger.js';
import { hashPayload, sha256 } from '../util.js';

const HOUR = 3_600_000;
export const SCHEMA_VERSION = '1.0';

export type FlowKind = 'source' | 'server';

export interface FlowRow {
  hour: string;
  kind: FlowKind;
  flow_id: string;
  source_ip: string;
  destination_ip: string | null;
  destination_port: number | null;
  transport: string | null;
  direction: string;
  verdict: 'allowed' | 'blocked';
  sessions: number;
  bytes_sent: number;
  bytes_received: number;
  destinations: number | null;
  users: string[];
  categories: string[];
  rules: string[];
}

/**
 * Horas inteiras a calcular: as `recomputeHours` anteriores ao checkpoint (dados que
 * chegaram atrasados ou após uma parada do Logstash) e as novas até now - lag.
 */
export function plannedHours(checkpoint: Date | null, now: Date, src: Pick<FwFlowsSourceConfig, 'lagMinutes' | 'initialLookbackHours' | 'maxHoursPerRun' | 'recomputeHours'>): Date[] {
  const limit = Math.floor((now.getTime() - src.lagMinutes * 60_000) / HOUR) * HOUR; // fim exclusivo
  const first = checkpoint
    ? Math.floor(checkpoint.getTime() / HOUR) * HOUR - src.recomputeHours * HOUR
    : limit - src.initialLookbackHours * HOUR;
  const hours: Date[] = [];
  for (let h = first; h + HOUR <= limit && hours.length < src.maxHoursPerRun + src.recomputeHours; h += HOUR) hours.push(new Date(h));
  return hours;
}

const terms = (field: string) => ({ terms: { field } });

/** Composite por hora: kind source agrupa por origem; server só fluxos de/para as redes de servidores. */
export function flowQuery(kind: FlowKind, hour: Date, serverCidrs: string[], after?: Record<string, unknown>, size = 1000): Record<string, unknown> {
  const filter: unknown[] = [
    { range: { '@timestamp': { gte: hour.toISOString(), lt: new Date(hour.getTime() + HOUR).toISOString() } } },
    { term: { 'event.dataset': 'fortigate.traffic' } },
    { exists: { field: 'source.ip' } },
  ];
  if (kind === 'server') {
    filter.push({ bool: { minimum_should_match: 1, should: serverCidrs.flatMap((c) => [{ term: { 'source.ip': c } }, { term: { 'destination.ip': c } }]) } });
  }
  const sources = kind === 'source'
    ? [{ source_ip: terms('source.ip') }, { direction: terms('network.direction') }, { verdict: terms('soc.fw.verdict') }]
    : [{ source_ip: terms('source.ip') }, { destination_ip: terms('destination.ip') },
        { destination_port: { terms: { field: 'destination.port', missing_bucket: true } } },
        { transport: { terms: { field: 'network.transport', missing_bucket: true } } },
        { direction: terms('network.direction') }, { verdict: terms('soc.fw.verdict') }];
  return {
    size: 0, track_total_hits: false, query: { bool: { filter } },
    aggs: { flows: { composite: { size, sources, ...(after ? { after } : {}) }, aggs: {
      sent: { sum: { field: 'source.bytes' } }, received: { sum: { field: 'destination.bytes' } },
      ...(kind === 'source' ? { destinations: { cardinality: { field: 'destination.ip' } } } : {}),
      users: { terms: { field: 'user.name', size: 5 } },
      categories: { terms: { field: 'fortinet.firewall.catdesc', size: 5 } },
      rules: { terms: { field: 'rule.name', size: 5 } },
    } } },
  };
}

interface Bucket {
  key: Record<string, string | number | null>;
  doc_count: number;
  sent?: { value: number | null };
  received?: { value: number | null };
  destinations?: { value: number };
  users?: { buckets: { key: string }[] };
  categories?: { buckets: { key: string }[] };
  rules?: { buckets: { key: string }[] };
}

const keys = (agg?: { buckets: { key: string }[] }) => (agg?.buckets ?? []).map((b) => String(b.key));

export function toFlowRow(kind: FlowKind, hour: Date, b: Bucket): FlowRow {
  const k = b.key;
  const verdict = k.verdict === 'blocked' ? 'blocked' : 'allowed';
  const identity = kind === 'source'
    ? [k.source_ip, k.direction, verdict]
    : [k.source_ip, k.destination_ip, k.destination_port ?? '', k.transport ?? '', k.direction, verdict];
  return {
    hour: hour.toISOString(), kind, flow_id: sha256(`${hour.toISOString()}|${kind}|${identity.join('|')}`).slice(0, 40),
    source_ip: String(k.source_ip),
    destination_ip: kind === 'server' ? String(k.destination_ip) : null,
    destination_port: kind === 'server' && typeof k.destination_port === 'number' ? k.destination_port : null,
    transport: kind === 'server' && k.transport != null ? String(k.transport) : null,
    direction: String(k.direction ?? 'unknown'), verdict,
    sessions: b.doc_count, bytes_sent: Math.round(b.sent?.value ?? 0), bytes_received: Math.round(b.received?.value ?? 0),
    destinations: kind === 'source' ? (b.destinations?.value ?? null) : null,
    users: keys(b.users), categories: keys(b.categories), rules: keys(b.rules),
  };
}

/** Pagina o composite; para em maxBuckets e informa se a hora ficou incompleta. */
export async function fetchFlows(es: ElasticSearcher, index: string, kind: FlowKind, hour: Date, serverCidrs: string[], maxBuckets: number):
  Promise<{ rows: FlowRow[]; truncated: boolean; requests: number }> {
  const rows: FlowRow[] = [];
  let after: Record<string, unknown> | undefined;
  let requests = 0;
  for (;;) {
    const res = await es.search(index, flowQuery(kind, hour, serverCidrs, after));
    requests++;
    const agg = (res.aggregations as { flows?: { buckets: Bucket[]; after_key?: Record<string, unknown> } } | undefined)?.flows;
    for (const b of agg?.buckets ?? []) rows.push(toFlowRow(kind, hour, b));
    if (rows.length >= maxBuckets) return { rows: rows.slice(0, maxBuckets), truncated: true, requests };
    if (!agg?.after_key || (agg.buckets ?? []).length === 0) return { rows, truncated: false, requests };
    after = agg.after_key;
  }
}

/** Documento publicado em soc-fw-flows-*. */
export function flowDoc(r: FlowRow, computedAt: Date, truncated: boolean): Record<string, unknown> {
  return {
    '@timestamp': r.hour, schema_version: SCHEMA_VERSION, kind: r.kind, flow_id: r.flow_id, computed_at: computedAt.toISOString(), truncated,
    source: { ip: r.source_ip },
    ...(r.destination_ip ? { destination: { ip: r.destination_ip, ...(r.destination_port != null ? { port: r.destination_port } : {}) } } : {}),
    network: { direction: r.direction, ...(r.transport ? { transport: r.transport } : {}) },
    soc: { fw: { verdict: r.verdict } },
    fw: { sessions: r.sessions, bytes_sent: r.bytes_sent, bytes_received: r.bytes_received, bytes_total: r.bytes_sent + r.bytes_received,
      ...(r.destinations != null ? { destinations: r.destinations } : {}), users: r.users, categories: r.categories, rules: r.rules },
  };
}

/**
 * Regrava a hora inteira no PostgreSQL e publica só os agregados novos ou alterados
 * (hash do conteúdo), para o recálculo das últimas horas não republicar tudo.
 */
export async function storeHour(client: Client, srcName: string, hour: Date, rows: FlowRow[], truncated: boolean, computedAt: Date, advanceTo: Date | null):
  Promise<{ published: number }> {
  const previous = await client.query<{ flow_id: string; content_hash: string }>(
    'SELECT flow_id, content_hash FROM soc.fw_flow_hourly WHERE hour = $1', [hour]);
  const known = new Map(previous.rows.map((r) => [r.flow_id, r.content_hash]));
  await client.query('DELETE FROM soc.fw_flow_hourly WHERE hour = $1', [hour]);
  const hashed = rows.map((row) => ({ ...row, content_hash: hashPayload({ ...row, truncated }) }));
  let published = 0;
  for (let i = 0; i < hashed.length; i += 2_000) {
    const chunk = hashed.slice(i, i + 2_000);
    const changed = chunk.filter((row) => known.get(row.flow_id) !== row.content_hash);
    await client.query(`
      INSERT INTO soc.fw_flow_hourly (hour, kind, flow_id, source_ip, destination_ip, destination_port, transport, direction, verdict,
        sessions, bytes_sent, bytes_received, destinations, users, categories, rules, content_hash, computed_at)
      SELECT hour, kind, flow_id, source_ip::inet, destination_ip::inet, destination_port, transport, direction, verdict,
        sessions, bytes_sent, bytes_received, destinations, users, categories, rules, content_hash, $2
      FROM jsonb_to_recordset($1::jsonb) AS r(hour timestamptz, kind text, flow_id text, source_ip text, destination_ip text,
        destination_port integer, transport text, direction text, verdict text, sessions bigint, bytes_sent bigint, bytes_received bigint,
        destinations integer, users text[], categories text[], rules text[], content_hash text)`, [JSON.stringify(chunk), computedAt]);
    if (!changed.length) continue;
    published += changed.length;
    await client.query(`
      INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
      SELECT 'fwflow', r.payload->>'kind', r.payload->>'flow_id', $2, r.payload FROM jsonb_to_recordset($1::jsonb) AS r(payload jsonb)`,
    [JSON.stringify(changed.map((row) => ({ payload: flowDoc(row, computedAt, truncated) }))), hour]);
  }
  if (advanceTo) await setCheckpoint(client, srcName, advanceTo);
  return { published };
}

export interface FwFlowsDeps { pool: Pool; log: Logger; elastic: ElasticSearcher | null }

export async function collectFwFlows(src: FwFlowsSourceConfig, deps: FwFlowsDeps, counters: RunCounters, now = new Date()): Promise<void> {
  if (!deps.elastic) throw new Error('fonte fwflows sem acesso ao Elasticsearch (ES_URL/ES_PASSWORD_FILE)');
  const checkpoint = await getCheckpoint(deps.pool, src.name);
  const hours = plannedHours(checkpoint, now, src);
  if (!hours.length) return;
  counters.windowStart = hours[0];
  counters.windowEnd = new Date(hours.at(-1)!.getTime() + HOUR);
  for (const hour of hours) {
    const computedAt = new Date();
    const source = await fetchFlows(deps.elastic, src.index, 'source', hour, src.serverCidrs, src.maxBucketsPerHour);
    const server = await fetchFlows(deps.elastic, src.index, 'server', hour, src.serverCidrs, src.maxBucketsPerHour);
    counters.apiCalls += source.requests + server.requests;
    const rows = [...source.rows, ...server.rows];
    const truncated = source.truncated || server.truncated;
    if (truncated) deps.log.warn({ source: src.name, hour: hour.toISOString(), limit: src.maxBucketsPerHour }, 'agregados da hora limitados por maxBucketsPerHour');
    const end = new Date(hour.getTime() + HOUR);
    // O checkpoint só avança; horas recalculadas não o fazem voltar.
    const advance = !checkpoint || end > checkpoint ? end : null;
    const stored = await withTransaction(deps.pool, (client) => storeHour(client, src.name, hour, rows, truncated, computedAt, advance));
    counters.fetched += rows.length;
    counters.changed += stored.published;
  }
  const removed = await deps.pool.query('DELETE FROM soc.fw_flow_hourly WHERE hour < $1', [new Date(now.getTime() - src.retentionDays * 24 * HOUR)]);
  deps.log.info({ source: src.name, hours: hours.length, rows: counters.fetched, published: counters.changed, removed: removed.rowCount ?? 0 }, 'agregados da firewall calculados');
}
