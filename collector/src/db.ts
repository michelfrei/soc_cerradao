import pg from 'pg';
import type { Config } from './config.js';

export type Pool = pg.Pool;
export type Client = pg.PoolClient;

export function createPool(cfg: Config['pg']): pg.Pool {
  let ssl: pg.PoolConfig['ssl'];
  if (cfg.sslmode === 'require') ssl = { rejectUnauthorized: false };
  else if (cfg.sslmode === 'verify-full') ssl = { rejectUnauthorized: true, ...(cfg.sslRootCert ? { ca: cfg.sslRootCert } : {}) };
  else ssl = false;

  return new pg.Pool({
    host: cfg.host,
    port: cfg.port,
    database: cfg.database,
    user: cfg.user,
    password: cfg.password,
    ssl,
    max: cfg.poolMax,
    application_name: 'soc-collector',
    connectionTimeoutMillis: 15_000,
    idleTimeoutMillis: 60_000,
  });
}

export async function withTransaction<T>(pool: pg.Pool, fn: (client: Client) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

// Checkpoints -------------------------------------------------------------------

export async function getCheckpoint(db: pg.Pool, source: string): Promise<Date | null> {
  const r = await db.query<{ watermark: Date }>('SELECT watermark FROM soc.collector_checkpoint WHERE source = $1', [source]);
  return r.rows[0]?.watermark ?? null;
}

/** Deve ser chamado na mesma transação que grava os dados correspondentes. */
export async function setCheckpoint(client: Client, source: string, watermark: Date): Promise<void> {
  await client.query(
    `INSERT INTO soc.collector_checkpoint (source, watermark, updated_at)
     VALUES ($1, $2, now())
     ON CONFLICT (source) DO UPDATE SET watermark = EXCLUDED.watermark, updated_at = now()`,
    [source, watermark],
  );
}

// Execuções ---------------------------------------------------------------------

export interface RunCounters {
  windowStart?: Date;
  windowEnd?: Date;
  fetched: number;
  inserted: number;
  changed: number;
  apiCalls: number;
  throttled: number;
}

export async function startRun(pool: pg.Pool, source: string): Promise<number> {
  const r = await pool.query<{ id: string }>(
    `INSERT INTO soc.collector_run (source, status) VALUES ($1, 'running') RETURNING id`,
    [source],
  );
  return Number(r.rows[0]!.id);
}

export async function finishRun(pool: pg.Pool, id: number, c: RunCounters, error?: string): Promise<void> {
  await pool.query(
    `UPDATE soc.collector_run
        SET finished_at = now(), status = $2, window_start = $3, window_end = $4,
            fetched = $5, inserted = $6, changed = $7, api_calls = $8, throttled = $9, error = $10
      WHERE id = $1`,
    [id, error ? 'failed' : 'success', c.windowStart ?? null, c.windowEnd ?? null,
      c.fetched, c.inserted, c.changed, c.apiCalls, c.throttled, error?.slice(0, 4000) ?? null],
  );
}

// Eventos de Advanced Hunting ---------------------------------------------------

export interface EventRow {
  key: string;
  ts: string;
  device_id: string | null;
  device_name: string | null;
  action_type: string | null;
  payload: Record<string, unknown>;
}

const INSERT_EVENTS = `
WITH rows AS (
    SELECT r.key, r.ts::timestamptz AS occurred_at, r.device_id, r.device_name, r.action_type, r.payload
    FROM jsonb_to_recordset($1::jsonb)
         AS r(key text, ts text, device_id text, device_name text, action_type text, payload jsonb)
), ins AS (
    INSERT INTO soc.raw_event (event_key, occurred_at, source, table_name, device_id, device_name, action_type, payload)
    SELECT key, occurred_at, $2, $3, device_id, device_name, action_type, payload FROM rows
    ON CONFLICT (event_key, occurred_at) DO NOTHING
    RETURNING event_key, occurred_at, payload
)
INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
SELECT 'event', $4, event_key, occurred_at, payload FROM ins`;

/** Insere eventos ignorando os já existentes e publica somente os novos. */
export async function insertEvents(client: Client, source: string, table: string, rows: EventRow[], chunkSize = 2_000): Promise<number> {
  let inserted = 0;
  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);
    const r = await client.query(INSERT_EVENTS, [JSON.stringify(chunk), source, table, table.toLowerCase()]);
    inserted += r.rowCount ?? 0;
  }
  return inserted;
}

export async function ensurePartitions(pool: pg.Pool, from: Date, to: Date): Promise<void> {
  await pool.query('SELECT soc.ensure_raw_event_partitions($1, $2)', [from, to]);
}

// Incidentes e alertas ----------------------------------------------------------

export interface SecurityObjectRow {
  id: string;
  title: string | null;
  status: string | null;
  severity: string | null;
  classification: string | null;
  determination: string | null;
  assigned_to: string | null;
  service_source: string | null;
  incident_id: string | null;
  web_url: string | null;
  created_at: string | null;
  last_update_at: string;
  payload_hash: string;
  payload: Record<string, unknown>;
}

const UPSERT_OBJECTS = `
WITH rows AS (
    SELECT * FROM jsonb_to_recordset($2::jsonb) AS r(
        id text, title text, status text, severity text, classification text, determination text,
        assigned_to text, service_source text, incident_id text, web_url text,
        created_at timestamptz, last_update_at timestamptz, payload_hash text, payload jsonb)
), up AS (
    INSERT INTO soc.security_object AS o (
        kind, id, title, status, severity, classification, determination, assigned_to,
        service_source, incident_id, web_url, created_at, last_update_at, payload_hash, payload)
    SELECT $1, id, title, status, severity, classification, determination, assigned_to,
           service_source, incident_id, web_url, created_at, last_update_at, payload_hash, payload
    FROM rows
    ON CONFLICT (kind, id) DO UPDATE SET
        title = EXCLUDED.title, status = EXCLUDED.status, severity = EXCLUDED.severity,
        classification = EXCLUDED.classification, determination = EXCLUDED.determination,
        assigned_to = EXCLUDED.assigned_to, service_source = EXCLUDED.service_source,
        incident_id = EXCLUDED.incident_id, web_url = EXCLUDED.web_url,
        created_at = EXCLUDED.created_at, last_update_at = EXCLUDED.last_update_at,
        payload_hash = EXCLUDED.payload_hash, payload = EXCLUDED.payload, last_changed_at = now()
    WHERE o.payload_hash IS DISTINCT FROM EXCLUDED.payload_hash
      AND o.last_update_at <= EXCLUDED.last_update_at
    RETURNING o.kind, o.id, o.payload_hash, o.last_update_at, o.payload
), ver AS (
    INSERT INTO soc.security_object_version (kind, id, payload_hash, last_update_at, payload)
    SELECT kind, id, payload_hash, last_update_at, payload FROM up
    ON CONFLICT DO NOTHING
), pub AS (
    INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
    SELECT kind, kind, id, last_update_at, payload FROM up
    UNION ALL
    SELECT kind || '_version', kind, id || ':' || payload_hash, last_update_at, payload FROM up
)
SELECT count(*)::int AS changed FROM up`;

/**
 * Grava o estado atual e uma versão para cada alteração real (hash diferente).
 * Uma resposta mais antiga que o estado gravado não sobrescreve o estado.
 */
export async function upsertObjects(client: Client, kind: 'incident' | 'alert', rows: SecurityObjectRow[]): Promise<number> {
  if (rows.length === 0) return 0;
  const r = await client.query<{ changed: number }>(UPSERT_OBJECTS, [kind, JSON.stringify(rows)]);
  return r.rows[0]?.changed ?? 0;
}
