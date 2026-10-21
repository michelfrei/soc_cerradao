import type { ExpectedAssetConfig, InventorySourceConfig } from '../config.js';
import { setCheckpoint, withTransaction, type Pool, type RunCounters } from '../db.js';
import type { GraphClient } from '../graph/client.js';
import type { Logger } from '../logger.js';
import { isServerInScope } from '../scope.js';
import { parseTimestamp } from '../util.js';

export interface InventoryRecord {
  key: string;
  payload: Record<string, unknown>;
}

function nonempty(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function nameOf(row: Record<string, unknown>): string | undefined {
  return nonempty(row.DeviceName)?.toLowerCase();
}

/**
 * DeviceId identifica o observado. Um esperado sem observação recebe expected:<nome>.
 * Reconhecimento posterior conserva a chave existente, inclusive depois de um rename.
 * Nunca remove silenciosos. Homônimos com IDs diferentes não são mesclados.
 */
export function mergeInventory(
  existing: InventoryRecord[], observed: Record<string, unknown>[], assets: ExpectedAssetConfig[], snapshot: Date,
): InventoryRecord[] {
  const at = snapshot.toISOString();
  const records = new Map(existing.map((r) => [r.key, {
    key: r.key,
    payload: { ...r.payload, SOCExpected: false, SOCObserved: false, SOCOwner: null, SOCEnvironment: null,
      SOCCriticality: null, SOCSnapshotAt: at } as Record<string, unknown>,
  }]));
  const byId = (id: string): InventoryRecord | undefined => [...records.values()].find((r) => r.payload.DeviceId === id);
  const byName = (name: string): InventoryRecord[] => [...records.values()].filter((r) => nameOf(r.payload) === name);

  // Primeiro associa esperados aos registros existentes, antes de receber novas observações.
  for (const asset of assets) {
    const name = asset.name.toLowerCase();
    if (!isServerInScope(name)) throw new Error(`ativo esperado fora do escopo de servidores: ${asset.name}`);
    if (!asset.id && name) {
      const observedIds = new Set(observed.filter((r) => nameOf(r) === name).map((r) => nonempty(r.DeviceId)));
      if (observedIds.size > 1) throw new Error(`nome esperado ambíguo no snapshot; informe id: ${asset.name}`);
    }
    const sameName = name ? byName(name) : [];
    const candidates = asset.id ? sameName.filter((r) => !r.payload.DeviceId || r.payload.DeviceId === asset.id) : sameName;
    const idMatch = asset.id ? byId(asset.id) : undefined;
    const catalogMatches = [...records.values()].filter((r) =>
      nonempty(r.payload.SOCCatalogName)?.toLowerCase() === name &&
      (!asset.id || !r.payload.DeviceId || r.payload.DeviceId === asset.id));
    if (catalogMatches.length > 1) throw new Error(`vínculo de catálogo ambíguo; informe id: ${asset.name}`);
    const catalogMatch = catalogMatches[0];
    if (!idMatch && !catalogMatch && candidates.length > 1) throw new Error(`nome esperado ambíguo; informe id: ${asset.name}`);
    // Um placeholder já reconhecido pode ter sido renomeado no Defender.
    // A sua chave expected:<nome original> continua vinculando a expectativa.
    const originalPlaceholder = name ? records.get(`expected:${name}`) : undefined;
    const compatiblePlaceholder = originalPlaceholder && (!asset.id || !originalPlaceholder.payload.DeviceId ||
      originalPlaceholder.payload.DeviceId === asset.id) ? originalPlaceholder : undefined;
    let record = idMatch ?? catalogMatch ?? compatiblePlaceholder ?? candidates[0];
    if (!record) {
      const key = asset.id ?? `expected:${name!}`;
      record = { key, payload: { DeviceId: asset.id ?? null, DeviceName: asset.name ?? null, Timestamp: null,
        OSPlatform: null, DeviceType: null, MachineGroup: null, OnboardingStatus: null, SensorHealthState: null,
        SOCObserved: false, SOCSnapshotAt: at } };
      records.set(key, record);
    }
    record.payload.SOCExpected = true;
    record.payload.SOCCatalogName = asset.name;
    record.payload.SOCOwner = asset.owner ?? null;
    record.payload.SOCEnvironment = asset.environment ?? null;
    record.payload.SOCCriticality = asset.criticality ?? null;
  }

  const seen = new Set<string>();
  for (const row of observed) {
    const id = nonempty(row.DeviceId);
    const name = nonempty(row.DeviceName);
    if (!id || !name) throw new Error('DeviceInfo precisa de DeviceId e DeviceName');
    parseTimestamp(row.Timestamp);
    if (!isServerInScope(name)) continue;
    if (seen.has(id)) throw new Error(`DeviceInfo duplicado no snapshot: ${id}`);
    seen.add(id);
    const placeholders = byName(name.toLowerCase()).filter((r) => !r.payload.DeviceId);
    if (placeholders.length > 1) throw new Error(`esperado ambíguo para ${name}`);
    let record = byId(id) ?? placeholders[0];
    if (!record) {
      record = { key: id, payload: {} };
      records.set(id, record);
    }
    const previous = record.payload;
    // Preserva Timestamp original (até sete casas decimais), sem conversão para Date.
    record.payload = { DeviceId: id, DeviceName: name, Timestamp: row.Timestamp,
      OSPlatform: null, DeviceType: null, MachineGroup: null, OnboardingStatus: null, SensorHealthState: null,
      ...row, SOCExpected: previous.SOCExpected === true, SOCObserved: true,
      SOCCatalogName: previous.SOCCatalogName ?? null,
      SOCOwner: previous.SOCOwner ?? null, SOCEnvironment: previous.SOCEnvironment ?? null,
      SOCCriticality: previous.SOCCriticality ?? null, SOCSnapshotAt: at };
  }
  return [...records.values()];
}

export async function collectInventory(
  src: InventorySourceConfig,
  deps: { pool: Pool; graph: GraphClient; log: Logger; assets: ExpectedAssetConfig[] },
  counters: RunCounters,
): Promise<void> {
  const snapshot = new Date();
  counters.windowStart = new Date(snapshot.getTime() - 30 * 24 * 3600_000);
  counters.windowEnd = snapshot;
  const result = await deps.graph.request('POST', '/security/runHuntingQuery', counters, { Query: src.query }) as { results?: unknown };
  if (!Array.isArray(result.results)) throw new Error('DeviceInfo sem lista results');
  if (result.results.length >= src.maxRows) {
    throw new Error(`DeviceInfo atingiu limite de ${src.maxRows} linhas; snapshot recusado por completude desconhecida`);
  }
  const observed = result.results as Record<string, unknown>[];
  counters.fetched = observed.length;
  await withTransaction(deps.pool, async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(hashtext('soc.device_inventory'))");
    const before = await client.query<{ key: string; payload: Record<string, unknown> }>(
      'SELECT inventory_key AS key, payload FROM soc.device_inventory',
    );
    const records = mergeInventory(before.rows, observed, deps.assets, snapshot);
    if (records.length > 0) {
      const saved = await client.query(`
        WITH rows AS (
          SELECT * FROM jsonb_to_recordset($1::jsonb) AS r(key text, payload jsonb)
        ), saved AS (
          INSERT INTO soc.device_inventory AS i (inventory_key, device_id, device_name, last_seen_at, snapshot_at, payload)
          SELECT key, payload->>'DeviceId', payload->>'DeviceName', (payload->>'Timestamp')::timestamptz,
                 $2::timestamptz, payload FROM rows
          ON CONFLICT (inventory_key) DO UPDATE SET
            device_id = EXCLUDED.device_id, device_name = EXCLUDED.device_name,
            last_seen_at = EXCLUDED.last_seen_at, snapshot_at = EXCLUDED.snapshot_at, payload = EXCLUDED.payload
          WHERE i.snapshot_at <= EXCLUDED.snapshot_at
          RETURNING inventory_key, snapshot_at, payload
        )
        INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
        SELECT 'device', 'deviceinfo', inventory_key, snapshot_at, payload FROM saved`,
      [JSON.stringify(records), snapshot]);
      counters.changed = saved.rowCount ?? 0;
      counters.inserted = records.filter((r) => !before.rows.some((b) => b.key === r.key)).length;
    }
    await setCheckpoint(client, src.name, snapshot);
  });
}
