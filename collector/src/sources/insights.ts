import type { InsightsSourceConfig } from '../config.js';
import { setCheckpoint, withTransaction, type Client, type Pool, type RunCounters } from '../db.js';
import type { RemediationCatalog } from '../insights/catalog.js';
import { buildInsights, contentHash, type DeviceContext, type Finding, type Insight } from '../insights/engine.js';
import type { Logger } from '../logger.js';

const TABLES = {
  devicetvmsoftwarevulnerabilities: 'DeviceTvmSoftwareVulnerabilities',
  devicetvmsecureconfigurationassessment: 'DeviceTvmSecureConfigurationAssessment',
  devicetvmsoftwareinventory: 'DeviceTvmSoftwareInventory',
} as const;

function lowerText(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : null;
}

export function deviceContext(payload: Record<string, unknown>): DeviceContext | null {
  const id = typeof payload.DeviceId === 'string' && payload.DeviceId.trim() ? payload.DeviceId.trim() : null;
  if (!id) return null;
  const internet = payload.IsInternetFacing;
  return {
    deviceId: id,
    deviceName: lowerText(payload.DeviceName),
    osPlatform: lowerText(payload.OSPlatform),
    exposureLevel: lowerText(payload.ExposureLevel),
    assetValue: lowerText(payload.AssetValue),
    internetFacing: internet === true || internet === 'true' ? true : internet === false || internet === 'false' ? false : null,
    criticality: lowerText(payload.SOCCriticality),
  };
}

interface StoredInsight {
  insight_id: string;
  status: Insight['status'];
  first_seen: Date;
  content_hash: string;
  payload: Insight;
}

/**
 * Lê a postura atual numa visão consistente e grava o estado dos insights com a
 * publicação na mesma transação. Sem snapshot concluído de vulnerabilidades e de
 * configurações a execução falha: nunca encerra insights por falta de dados.
 */
export async function storeInsights(client: Client, src: InsightsSourceConfig, catalog: RemediationCatalog, generatedAt: Date):
  Promise<{ fetched: number; inserted: number; changed: number; insights: number }> {
  await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  await client.query("SELECT pg_advisory_xact_lock(hashtext('soc.remediation_insight'))");
  const own = await client.query<{ watermark: Date }>('SELECT watermark FROM soc.collector_checkpoint WHERE source=$1', [src.name]);
  if (own.rows[0] && own.rows[0].watermark > generatedAt) throw new Error(`${src.name}: execução anterior ao último cálculo; recusada`);
  const sourceNames = [src.vulnerabilitySource, src.configurationSource, ...(src.softwareInventorySource ? [src.softwareInventorySource] : [])];
  const checkpoints = await client.query<{ source: string; watermark: Date }>(
    'SELECT source, watermark FROM soc.collector_checkpoint WHERE source = ANY($1)', [sourceNames]);
  const watermark = (name: string | null): Date | null => checkpoints.rows.find((r) => r.source === name)?.watermark ?? null;
  for (const name of [src.vulnerabilitySource, src.configurationSource]) {
    if (!watermark(name)) throw new Error(`${src.name}: fonte ${name} sem snapshot concluído; insights não recalculados`);
  }
  const inventoryReady = !!src.softwareInventorySource && !!watermark(src.softwareInventorySource);

  const posture = await client.query<{ dataset: keyof typeof TABLES; doc_id: string; device_id: string; payload: Record<string, unknown> }>(
    'SELECT dataset, doc_id, device_id, payload FROM soc.posture_state WHERE active ORDER BY dataset, doc_id');
  const of = (dataset: keyof typeof TABLES): Finding[] => posture.rows.filter((r) => r.dataset === dataset)
    .map((r) => ({ docId: r.doc_id, deviceId: r.device_id, payload: r.payload }));
  const inventory = await client.query<{ payload: Record<string, unknown> }>(
    'SELECT payload FROM soc.device_inventory WHERE device_id IS NOT NULL');

  const insights = buildInsights({
    generatedAt,
    vulnerabilities: of('devicetvmsoftwarevulnerabilities'),
    configurations: of('devicetvmsecureconfigurationassessment'),
    softwareInventory: inventoryReady ? of('devicetvmsoftwareinventory') : null,
    devices: inventory.rows.map((r) => deviceContext(r.payload)).filter((d): d is DeviceContext => !!d),
    snapshots: [
      { table: TABLES.devicetvmsoftwarevulnerabilities, snapshotAt: watermark(src.vulnerabilitySource)?.toISOString() ?? null },
      { table: TABLES.devicetvmsecureconfigurationassessment, snapshotAt: watermark(src.configurationSource)?.toISOString() ?? null },
      ...(src.softwareInventorySource ? [{ table: TABLES.devicetvmsoftwareinventory, snapshotAt: watermark(src.softwareInventorySource)?.toISOString() ?? null }] : []),
    ],
    catalog,
  });

  const existing = await client.query<StoredInsight>(
    'SELECT insight_id, status, first_seen, content_hash, payload FROM soc.remediation_insight');
  const known = new Map(existing.rows.map((r) => [r.insight_id, r]));
  const at = generatedAt.toISOString();
  const rows: Array<{ id: string; status: string; first_seen: string; last_seen: string; hash: string; payload: Insight }> = [];
  let inserted = 0;
  let changed = 0;
  for (const insight of insights) {
    const previous = known.get(insight.insight_id);
    const hash = contentHash(insight);
    if (!previous) inserted++;
    else if (previous.content_hash !== hash || previous.status !== 'open') changed++;
    const payload: Insight = { ...insight, first_seen: previous ? previous.first_seen.toISOString() : at };
    rows.push({ id: insight.insight_id, status: 'open', first_seen: payload.first_seen, last_seen: at, hash, payload });
  }
  const current = new Set(insights.map((i) => i.insight_id));
  for (const previous of existing.rows) {
    if (current.has(previous.insight_id) || previous.status !== 'open') continue;
    changed++;
    // Conserva a última evidência conhecida; ausência não prova correção.
    const payload: Insight = { ...previous.payload, '@timestamp': at, analysis_id: insights[0]?.analysis_id ?? previous.payload.analysis_id,
      status: 'no_longer_reported', resolved_at: at };
    rows.push({ id: previous.insight_id, status: 'no_longer_reported', first_seen: previous.first_seen.toISOString(),
      last_seen: previous.payload.last_seen, hash: previous.content_hash, payload });
  }

  if (rows.length) {
    await client.query(`
      WITH rows AS (
        SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(id text, status text, first_seen timestamptz, last_seen timestamptz, hash text, payload jsonb)
      ), saved AS (
        INSERT INTO soc.remediation_insight AS i (insight_id, status, first_seen, last_seen, generated_at, content_hash, payload)
        SELECT id, status, first_seen, last_seen, $2::timestamptz, hash, payload FROM rows
        ON CONFLICT (insight_id) DO UPDATE SET status = EXCLUDED.status, last_seen = EXCLUDED.last_seen,
          generated_at = EXCLUDED.generated_at, content_hash = EXCLUDED.content_hash, payload = EXCLUDED.payload
        WHERE i.generated_at <= EXCLUDED.generated_at
        RETURNING insight_id, generated_at, payload
      )
      INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
      SELECT 'insight', 'remediation', insight_id, generated_at, payload FROM saved`,
    [JSON.stringify(rows), generatedAt]);
  }
  await setCheckpoint(client, src.name, generatedAt);
  return { fetched: posture.rows.length, inserted, changed, insights: insights.length };
}

export async function collectInsights(
  src: InsightsSourceConfig, deps: { pool: Pool; log: Logger; catalog: RemediationCatalog }, counters: RunCounters,
): Promise<void> {
  const generatedAt = new Date();
  counters.windowStart = generatedAt;
  counters.windowEnd = generatedAt;
  const result = await withTransaction(deps.pool, (client) => storeInsights(client, src, deps.catalog, generatedAt));
  counters.fetched = result.fetched;
  counters.inserted = result.inserted;
  counters.changed = result.changed;
  deps.log.info({ source: src.name, insights: result.insights }, 'insights de remediação recalculados');
}
