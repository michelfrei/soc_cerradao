import type { SnapshotSourceConfig } from '../config.js';
import { setCheckpoint, withTransaction, type Client, type Pool, type RunCounters } from '../db.js';
import type { GraphClient } from '../graph/client.js';
import { completeHuntingResults } from '../graph/hunting-results.js';
import type { Logger } from '../logger.js';
import { isServerInScope } from '../scope.js';
import { canonicalJson, parseTimestamp, sha256 } from '../util.js';

export interface PostureRow {
  key: string;
  deviceId: string;
  payload: Record<string, unknown>;
}

function required(row: Record<string, unknown>, field: string): string {
  const value = row[field];
  if (typeof value !== 'string' || !value.trim()) throw new Error(`snapshot: campo obrigatório ausente/inválido: ${field}`);
  return value;
}

function component(row: Record<string, unknown>, field: string): string {
  if (typeof row[field] !== 'string') throw new Error(`snapshot: componente ausente/inválido: ${field}`);
  return row[field];
}

function context(value: unknown): unknown {
  if (typeof value !== 'string') return value ?? null;
  try { return JSON.parse(value); } catch { return value; }
}

export function postureKey(table: SnapshotSourceConfig['table'], row: Record<string, unknown>): string {
  const device = required(row, 'DeviceId');
  const identity = table === 'DeviceTvmSoftwareVulnerabilities'
    ? [required(row, 'CveId'), required(row, 'SoftwareName'), component(row, 'SoftwareVendor'), component(row, 'SoftwareVersion')]
    : table === 'DeviceTvmSoftwareInventory'
      ? [required(row, 'SoftwareName'), component(row, 'SoftwareVendor'), component(row, 'SoftwareVersion')]
      : [required(row, 'ConfigurationId'), context(row.Context)];
  return sha256(canonicalJson([table.toLowerCase(), device, ...identity]));
}

/** Valida completude antes de filtrar escopo, deduplicar ou tocar no PostgreSQL. */
export function snapshotRows(src: SnapshotSourceConfig, raw: unknown, snapshot: Date): PostureRow[] {
  if (!Array.isArray(raw)) throw new Error(`${src.name}: Graph não retornou lista results`);
  if (raw.length >= src.maxRows) throw new Error(`${src.name}: limite ${src.maxRows} atingido; snapshot incompleto recusado`);
  const rows = new Map<string, PostureRow>();
  for (const item of raw) {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) throw new Error(`${src.name}: linha inválida`);
    const row = item as Record<string, unknown>;
    const name = required(row, 'DeviceName');
    if (!isServerInScope(name)) continue;
    const key = postureKey(src.table, row);
    if (src.table === 'DeviceTvmSecureConfigurationAssessment') parseTimestamp(row.Timestamp);
    const payload = { ...row, SOCActive: true, SOCSnapshotAt: snapshot.toISOString(), SOCState: 'observed' };
    const previous = rows.get(key);
    if (previous && canonicalJson({ ...previous.payload, Context: context(previous.payload.Context) }) !==
        canonicalJson({ ...payload, Context: context(row.Context) })) {
      throw new Error(`${src.name}: duas linhas divergentes para a mesma identidade; snapshot recusado`);
    }
    rows.set(key, { key, deviceId: required(row, 'DeviceId'), payload });
  }
  return [...rows.values()];
}

/** Executada com a transação do checkpoint: falha reverte estado e publicações. */
export async function storeSnapshot(client: Client, src: SnapshotSourceConfig, rows: PostureRow[], snapshot: Date): Promise<{ inserted: number; changed: number }> {
  const dataset = src.table.toLowerCase();
  await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`soc.posture_state:${dataset}`]);
  // Uma execução iniciada antes de outra não pode desativar uma visão mais recente.
  const checkpoint = await client.query<{ watermark: Date | null }>(`SELECT greatest(
    (SELECT watermark FROM soc.collector_checkpoint WHERE source=$1),
    (SELECT max(snapshot_at) FROM soc.posture_state WHERE dataset=$2)) AS watermark`, [src.name, dataset]);
  if (checkpoint.rows[0]?.watermark && checkpoint.rows[0].watermark > snapshot) throw new Error(`${src.name}: snapshot anterior ao checkpoint/estado; recusado`);
  const existing = await client.query<{ doc_id: string }>('SELECT doc_id FROM soc.posture_state WHERE dataset=$1', [dataset]);
  const known = new Set(existing.rows.map((r) => r.doc_id));
  const saved = await client.query<{ changed: number }>(`
    WITH rows AS (
      SELECT * FROM jsonb_to_recordset($2::jsonb) AS r(key text, "deviceId" text, payload jsonb)
    ), current AS (
      INSERT INTO soc.posture_state AS p (dataset, doc_id, device_id, active, snapshot_at, payload)
      SELECT $1, key, "deviceId", true, $3::timestamptz, payload FROM rows
      ON CONFLICT (dataset, doc_id) DO UPDATE SET
        device_id=EXCLUDED.device_id, active=true, snapshot_at=EXCLUDED.snapshot_at, payload=EXCLUDED.payload
      RETURNING doc_id, snapshot_at, payload
    ), removed AS (
      UPDATE soc.posture_state p SET active=false, snapshot_at=$3::timestamptz,
        payload=p.payload || jsonb_build_object('SOCActive', false, 'SOCSnapshotAt', $4::text, 'SOCState', 'no_longer_reported')
      WHERE p.dataset=$1 AND p.active AND NOT EXISTS (SELECT 1 FROM rows r WHERE r.key=p.doc_id)
      RETURNING p.doc_id, p.snapshot_at, p.payload
    ), publication AS (
      INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
      SELECT 'posture', $1, doc_id, snapshot_at, payload FROM current
      UNION ALL
      SELECT 'posture', $1, doc_id, snapshot_at, payload FROM removed
      RETURNING 1
    )
    SELECT count(*)::int AS changed FROM publication`,
  [dataset, JSON.stringify(rows), snapshot, snapshot.toISOString()]);
  await setCheckpoint(client, src.name, snapshot);
  return { inserted: rows.filter((r) => !known.has(r.key)).length, changed: saved.rows[0]?.changed ?? 0 };
}

export async function collectSnapshot(
  src: SnapshotSourceConfig, deps: { pool: Pool; graph: GraphClient; log: Logger }, counters: RunCounters,
): Promise<void> {
  const snapshot = new Date();
  counters.windowStart = snapshot;
  counters.windowEnd = snapshot;
  // Tabela ausente, licença insuficiente e erro da API propagam à execução da fonte.
  const response = await deps.graph.request('POST', '/security/runHuntingQuery', counters, { Query: src.query });
  const results = completeHuntingResults(response, src.maxRows, src.name);
  const rows = snapshotRows(src, results, snapshot);
  counters.fetched = results.length;
  const result = await withTransaction(deps.pool, (client) => storeSnapshot(client, src, rows, snapshot));
  counters.inserted += result.inserted;
  counters.changed += result.changed;
}
