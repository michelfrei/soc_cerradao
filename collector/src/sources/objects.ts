import { z } from 'zod';
import type { ObjectSourceConfig } from '../config.js';
import { getCheckpoint, setCheckpoint, upsertObjects, withTransaction, type Pool, type RunCounters, type SecurityObjectRow } from '../db.js';
import type { GraphClient } from '../graph/client.js';
import type { Logger } from '../logger.js';
import { addHours, addMinutes, hashPayload, isoUtc, parseTimestamp } from '../util.js';

// Campos usados pela plataforma; os demais seguem intactos no payload.
const GraphObject = z
  .object({
    id: z.string().min(1),
    lastUpdateDateTime: z.string(),
    createdDateTime: z.string().nullish(),
    status: z.string().nullish(),
    severity: z.string().nullish(),
    classification: z.string().nullish(),
    determination: z.string().nullish(),
    assignedTo: z.string().nullish(),
  })
  .passthrough();

const Incident = GraphObject.extend({
  displayName: z.string().nullish(),
  incidentWebUrl: z.string().nullish(),
});

const Alert = GraphObject.extend({
  title: z.string().nullish(),
  serviceSource: z.string().nullish(),
  incidentId: z.string().nullish(),
  alertWebUrl: z.string().nullish(),
});

const ENDPOINTS = {
  incidents: { kind: 'incident', path: '/security/incidents', defaultTop: 50 },
  alerts: { kind: 'alert', path: '/security/alerts_v2', defaultTop: 500 },
} as const;

export function toObjectRow(type: 'incidents' | 'alerts', raw: unknown): SecurityObjectRow {
  const base = {
    payload_hash: hashPayload(raw),
    payload: raw as Record<string, unknown>,
  };
  if (type === 'incidents') {
    const o = Incident.parse(raw);
    return {
      ...base,
      id: o.id,
      title: o.displayName ?? null,
      status: o.status ?? null,
      severity: o.severity ?? null,
      classification: o.classification ?? null,
      determination: o.determination ?? null,
      assigned_to: o.assignedTo ?? null,
      service_source: null,
      incident_id: o.id,
      web_url: o.incidentWebUrl ?? null,
      created_at: o.createdDateTime ?? null,
      last_update_at: parseTimestamp(o.lastUpdateDateTime).toISOString(),
    };
  }
  const o = Alert.parse(raw);
  return {
    ...base,
    id: o.id,
    title: o.title ?? null,
    status: o.status ?? null,
    severity: o.severity ?? null,
    classification: o.classification ?? null,
    determination: o.determination ?? null,
    assigned_to: o.assignedTo ?? null,
    service_source: o.serviceSource ?? null,
    incident_id: o.incidentId ?? null,
    web_url: o.alertWebUrl ?? null,
    created_at: o.createdDateTime ?? null,
    last_update_at: parseTimestamp(o.lastUpdateDateTime).toISOString(),
  };
}

/** Mantém só a versão mais recente de cada id dentro de uma página. */
export function latestById(rows: SecurityObjectRow[]): SecurityObjectRow[] {
  const map = new Map<string, SecurityObjectRow>();
  for (const r of rows) {
    const prev = map.get(r.id);
    if (!prev || prev.last_update_at <= r.last_update_at) map.set(r.id, r);
  }
  return [...map.values()];
}

/**
 * Coleta incremental por lastUpdateDateTime, com sobreposição.
 * Cada página é gravada na própria transação; reprocessar é seguro porque
 * versões são identificadas pelo hash do payload. O checkpoint avança só na
 * transação da última página, depois que todos os dados foram gravados.
 */
export async function collectObjects(
  src: ObjectSourceConfig & { type: 'incidents' | 'alerts' },
  deps: { pool: Pool; graph: GraphClient; log: Logger },
  counters: RunCounters,
): Promise<void> {
  const { pool, graph, log } = deps;
  const ep = ENDPOINTS[src.type];
  const now = new Date();
  const checkpoint = await getCheckpoint(pool, src.name);
  const watermark = checkpoint ?? addHours(now, -src.initialLookbackHours);
  const from = addMinutes(watermark, -src.overlapMinutes);
  counters.windowStart = from;
  counters.windowEnd = now;

  const filter = `lastUpdateDateTime ge ${isoUtc(from)}`;
  const top = src.pageSize ?? ep.defaultTop;
  const path = `${ep.path}?$filter=${encodeURIComponent(filter)}&$top=${top}`;

  let maxSeen = watermark;
  let pending: SecurityObjectRow[] | undefined;

  const flush = async (rows: SecurityObjectRow[], final: boolean): Promise<void> => {
    await withTransaction(pool, async (client) => {
      counters.changed += await upsertObjects(client, ep.kind, latestById(rows));
      if (final) await setCheckpoint(client, src.name, maxSeen);
    });
  };

  const stats = counters;
  for await (const page of graph.paginate(path, stats)) {
    const rows: SecurityObjectRow[] = [];
    for (const raw of page) {
      try {
        rows.push(toObjectRow(src.type, raw));
      } catch (err) {
        // Um item fora do formato não pode travar a fila inteira; fica registrado.
        log.error({ source: src.name, err: (err as Error).message, id: (raw as { id?: unknown })?.id }, 'item ignorado: formato inesperado');
      }
    }
    counters.fetched += page.length;
    for (const r of rows) {
      const t = new Date(r.last_update_at);
      if (t > maxSeen) maxSeen = t;
    }
    // Grava a página anterior; a última fica para a transação com o checkpoint.
    if (pending) await flush(pending, false);
    pending = rows;
  }
  await flush(pending ?? [], true);
}
