import type { FwSessionsSourceConfig } from '../config.js';
import { setCheckpoint, withTransaction, type Client, type Pool, type RunCounters } from '../db.js';
import type { ElasticSearcher } from '../elastic/client.js';
import type { Logger } from '../logger.js';
import { hashPayload } from '../util.js';

const HOUR = 3_600_000;
export const SCHEMA_VERSION = '1.0';

export type SessionState = 'open' | 'closed' | 'stale' | 'unknown';
export const STATE_LABEL: Record<SessionState, string> = {
  open: 'Aberta', closed: 'Encerrada', stale: 'Sem fechamento registrado', unknown: 'Sem registro recente',
};

/** Campos lidos do último evento (e do último evento de abertura) de cada sessão. */
const SOURCE_FIELDS = ['@timestamp', 'event.duration', 'soc.fw.session.state', 'soc.fw.access.kind', 'soc.fw.access.channel', 'soc.fw.access.user',
  'source.ip', 'source.bytes', 'destination.bytes', 'fortinet.firewall.tunnelip', 'fortinet.firewall.vpntunnel', 'fortinet.firewall.profile'];

export function sessionQuery(since: Date, now: Date, after?: Record<string, unknown>, size = 1000): Record<string, unknown> {
  const hit = (order: 'asc' | 'desc') => ({ top_hits: { size: 1, sort: [{ '@timestamp': { order } }], _source: { includes: SOURCE_FIELDS } } });
  return {
    size: 0, track_total_hits: false,
    query: { bool: { filter: [
      { range: { '@timestamp': { gte: since.toISOString(), lte: now.toISOString() } } },
      { exists: { field: 'soc.fw.session.id' } },
    ] } },
    aggs: { sessions: { composite: { size, sources: [{ id: { terms: { field: 'soc.fw.session.id' } } }], ...(after ? { after } : {}) }, aggs: {
      latest: hit('desc'),
      first: { min: { field: '@timestamp' } },
      opened: { filter: { term: { 'soc.fw.session.state': 'open' } }, aggs: { at: { max: { field: '@timestamp' } }, event: hit('desc') } },
    } } },
  };
}

type Source = Record<string, unknown>;
const get = (o: Source | undefined, path: string): unknown => path.split('.').reduce<unknown>((n, k) => (n && typeof n === 'object' ? (n as Source)[k] : undefined), o);
const str = (v: unknown): string | null => (typeof v === 'string' && v.trim() ? v : null);
const isIp = (v: string): boolean => /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]*$/i.test(v);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

export interface SessionBucket {
  key: { id: string };
  latest?: { hits: { hits: { _source: Source }[] } };
  first?: { value_as_string?: string; value: number | null };
  opened?: { doc_count: number; at?: { value: number | null }; event?: { hits: { hits: { _source: Source }[] } } };
}

export interface SessionDoc extends Record<string, unknown> {
  session_id: string;
  kind: string;
  state: SessionState;
  last_seen: string;
}

/** Estado atual: aberta até o fechamento; sem evento há staleHours vira "sem fechamento registrado". */
export function toSession(b: SessionBucket, now: Date, src: Pick<FwSessionsSourceConfig, 'adminStaleHours' | 'vpnStaleHours'>): SessionDoc | null {
  const latest = b.latest?.hits.hits[0]?._source;
  if (!latest) return null;
  const opening = b.opened?.event?.hits.hits[0]?._source;
  const pick = (path: string) => get(latest, path) ?? get(opening, path);
  const kind = str(pick('soc.fw.access.kind')) ?? 'desconhecido';
  const lastSeen = str(get(latest, '@timestamp'))!;
  const lastState = str(get(latest, 'soc.fw.session.state'));
  const openedAt = num(b.opened?.at?.value);
  // Sem o evento de abertura na janela (sessão anterior ao início da coleta), o tunnel-stats
  // e o tunnel-down trazem há quanto tempo o túnel está ativo (event.duration, em ns).
  const elapsedNs = num(get(latest, 'event.duration'));
  let startedAt: Date | null = null;
  if (openedAt != null) startedAt = new Date(openedAt);
  else if (elapsedNs != null) startedAt = new Date(Date.parse(lastSeen) - Math.round(elapsedNs / 1e6));
  else if (num(b.first?.value) != null) startedAt = new Date(b.first!.value!);
  const staleHours = kind === 'admin' ? src.adminStaleHours : src.vpnStaleHours;
  let state: SessionState;
  if (lastState === 'close') state = 'closed';
  else if (now.getTime() - Date.parse(lastSeen) > staleHours * HOUR) state = 'stale';
  else state = 'open';
  const end = state === 'closed' ? new Date(lastSeen) : null;
  const duration = startedAt ? Math.max(0, Math.round(((end ?? now).getTime() - startedAt.getTime()) / 1000)) : null;
  const doc: SessionDoc = {
    schema_version: SCHEMA_VERSION, session_id: b.key.id, kind, state, state_label: STATE_LABEL[state], last_seen: lastSeen,
    ...(str(pick('soc.fw.access.channel')) ? { channel: pick('soc.fw.access.channel') } : {}),
    // Túnel IPsec entre sites traz o IP remoto no campo de usuário: não é uma pessoa.
    ...(str(pick('soc.fw.access.user')) && !isIp(String(pick('soc.fw.access.user'))) ? { user: pick('soc.fw.access.user') } : {}),
    ...(str(pick('source.ip')) ? { source: { ip: pick('source.ip') } } : {}),
    ...(str(pick('fortinet.firewall.tunnelip')) ? { tunnel_ip: pick('fortinet.firewall.tunnelip') } : {}),
    ...(str(pick('fortinet.firewall.vpntunnel')) ? { vpn_tunnel: pick('fortinet.firewall.vpntunnel') } : {}),
    ...(str(pick('fortinet.firewall.profile')) ? { profile: pick('fortinet.firewall.profile') } : {}),
    ...(startedAt ? { started_at: startedAt.toISOString() } : {}),
    ...(end ? { ended_at: end.toISOString() } : {}),
    ...(duration != null ? { duration_seconds: duration } : {}),
    ...(state === 'closed' && num(get(latest, 'source.bytes')) != null ? { bytes_sent: get(latest, 'source.bytes') } : {}),
    ...(state === 'closed' && num(get(latest, 'destination.bytes')) != null ? { bytes_received: get(latest, 'destination.bytes') } : {}),
  };
  return doc;
}

export async function fetchSessions(es: ElasticSearcher, index: string, since: Date, now: Date, maxSessions: number):
  Promise<{ buckets: SessionBucket[]; truncated: boolean; requests: number }> {
  const buckets: SessionBucket[] = [];
  let after: Record<string, unknown> | undefined;
  let requests = 0;
  for (;;) {
    const res = await es.search(index, sessionQuery(since, now, after));
    requests++;
    const agg = (res.aggregations as { sessions?: { buckets: SessionBucket[]; after_key?: Record<string, unknown> } } | undefined)?.sessions;
    buckets.push(...(agg?.buckets ?? []));
    if (buckets.length >= maxSessions) return { buckets: buckets.slice(0, maxSessions), truncated: true, requests };
    if (!agg?.after_key || !(agg.buckets ?? []).length) return { buckets, truncated: false, requests };
    after = agg.after_key;
  }
}

/**
 * Grava o estado e publica só o que mudou. Sessão aberta que saiu da janela consultada
 * sem fechamento vira "sem registro recente" (unknown), em vez de continuar aberta.
 */
export async function storeSessions(client: Client, src: FwSessionsSourceConfig, docs: SessionDoc[], computedAt: Date): Promise<{ published: number; expired: number }> {
  const known = new Map((await client.query<{ session_id: string; content_hash: string; state: string; payload: SessionDoc }>(
    'SELECT session_id, content_hash, state, payload FROM soc.fw_session_state')).rows.map((r) => [r.session_id, r]));
  const seen = new Set(docs.map((d) => d.session_id));
  const expired = [...known.values()].filter((r) => !seen.has(r.session_id) && ['open', 'stale'].includes(r.state))
    .map((r) => ({ ...r.payload, state: 'unknown' as const, state_label: STATE_LABEL.unknown }));
  const changed = [...docs, ...expired].map((d) => ({ doc: d, hash: hashPayload(d) })).filter((x) => known.get(x.doc.session_id)?.content_hash !== x.hash);
  for (let i = 0; i < changed.length; i += 1_000) {
    const chunk = changed.slice(i, i + 1_000);
    await client.query(`
      INSERT INTO soc.fw_session_state (session_id, kind, state, last_seen, content_hash, payload, updated_at)
      SELECT r.session_id, r.kind, r.state, r.last_seen, r.content_hash, r.payload, $2
      FROM jsonb_to_recordset($1::jsonb) AS r(session_id text, kind text, state text, last_seen timestamptz, content_hash text, payload jsonb)
      ON CONFLICT (session_id) DO UPDATE SET kind = EXCLUDED.kind, state = EXCLUDED.state, last_seen = EXCLUDED.last_seen,
        content_hash = EXCLUDED.content_hash, payload = EXCLUDED.payload, updated_at = EXCLUDED.updated_at`,
    [JSON.stringify(chunk.map(({ doc, hash }) => ({ session_id: doc.session_id, kind: doc.kind, state: doc.state, last_seen: doc.last_seen,
      content_hash: hash, payload: doc }))), computedAt]);
    await client.query(`
      INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
      SELECT 'fwsession', 'state', r.payload->>'session_id', $2, r.payload FROM jsonb_to_recordset($1::jsonb) AS r(payload jsonb)`,
    [JSON.stringify(chunk.map(({ doc }) => ({ payload: { ...doc, '@timestamp': doc.last_seen, computed_at: computedAt.toISOString() } }))), computedAt]);
  }
  await client.query(`DELETE FROM soc.fw_session_state WHERE state IN ('closed', 'unknown') AND last_seen < $1`,
    [new Date(computedAt.getTime() - src.retentionDays * 24 * HOUR)]);
  await setCheckpoint(client, src.name, computedAt);
  return { published: changed.length, expired: expired.length };
}

export interface FwSessionsDeps { pool: Pool; log: Logger; elastic: ElasticSearcher | null }

export async function collectFwSessions(src: FwSessionsSourceConfig, deps: FwSessionsDeps, counters: RunCounters, now = new Date()): Promise<void> {
  if (!deps.elastic) throw new Error('fonte fwsessions sem acesso ao Elasticsearch (ES_URL/ES_PASSWORD_FILE)');
  const since = new Date(now.getTime() - src.lookbackHours * HOUR);
  counters.windowStart = since;
  counters.windowEnd = now;
  const r = await fetchSessions(deps.elastic, src.index, since, now, src.maxSessions);
  counters.apiCalls += r.requests;
  // Sem a lista completa, sessões ausentes não podem ser dadas como expiradas.
  if (r.truncated) throw new Error(`mais de ${src.maxSessions} sessões na janela; aumente maxSessions`);
  const docs = r.buckets.map((b) => toSession(b, now, src)).filter((d): d is SessionDoc => d !== null);
  const stored = await withTransaction(deps.pool, (client) => storeSessions(client, src, docs, now));
  counters.fetched = docs.length;
  counters.changed = stored.published;
  const byState = docs.reduce<Record<string, number>>((acc, d) => ({ ...acc, [`${d.kind}_${d.state}`]: (acc[`${d.kind}_${d.state}`] ?? 0) + 1 }), {});
  deps.log.info({ source: src.name, sessions: docs.length, published: stored.published, expired: stored.expired, ...byState }, 'sessões da firewall atualizadas');
}
