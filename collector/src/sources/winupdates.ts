import type { WinUpdatesSourceConfig } from '../config.js';
import { setCheckpoint, withTransaction, type Client, type Pool, type RunCounters } from '../db.js';
import type { Logger } from '../logger.js';
import { evaluateServer, isInScope, type CatalogEntry, type ServerInput, type VulnerabilityStats, type WinUpdateDoc } from '../winupdates/engine.js';

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/** WindowsServer2022 → windows_server_2022 (nome do SO no inventário TVM). */
function tvmOsName(osPlatform: string): string | null {
  const m = /^WindowsServer(\d{4})/i.exec(osPlatform);
  return m ? `windows_server_${m[1]}` : null;
}

export function buildServers(
  devices: Record<string, unknown>[],
  osRows: { device_id: string; payload: Record<string, unknown> }[],
  defenderKbs: Map<string, string[]>,
  prefix: string,
  vulnerabilities: Map<string, VulnerabilityStats> = new Map(),
  vulnerabilitySnapshotDone = false,
): ServerInput[] {
  const servers: ServerInput[] = [];
  for (const d of devices) {
    const id = text(d.DeviceId);
    const name = text(d.DeviceName);
    const platform = text(d.OSPlatform);
    if (!id || !name || !platform || d.SOCObserved !== true || !isInScope(name, platform, prefix)) continue;
    const rows = osRows.filter((r) => r.device_id === id);
    const expected = tvmOsName(platform);
    // Com mais de um SO no inventário, só a linha do SO reportado pelo DeviceInfo vale.
    const row = rows.find((r) => text(r.payload.SoftwareName)?.toLowerCase() === expected) ?? (rows.length === 1 ? rows[0] : undefined);
    servers.push({
      deviceId: id, deviceName: name, osPlatform: platform, lastSeen: text(d.Timestamp),
      osVersion: row ? text(row.payload.SoftwareVersion) : null,
      osSnapshotAt: row ? text(row.payload.SOCSnapshotAt) : null,
      defenderKbs: (defenderKbs.get(id) ?? []).map((k) => (/^\d+$/.test(k) ? `KB${k}` : k)),
      // Com snapshot concluído, servidor sem linhas tem zero vulnerabilidades reportadas; sem snapshot, desconhecido.
      vulnerabilities: vulnerabilities.get(id) ?? (vulnerabilitySnapshotDone ? { instances: 0, cves: 0, critical: 0, exploit: 0, exploitUnknown: 0 } : null),
    });
  }
  return servers;
}

export async function storeWinUpdates(client: Client, src: WinUpdatesSourceConfig, generatedAt: Date):
  Promise<{ fetched: number; changed: number; docs: WinUpdateDoc[] }> {
  await client.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
  const devices = await client.query<{ payload: Record<string, unknown> }>(
    'SELECT payload FROM soc.device_inventory WHERE device_id IS NOT NULL');
  const osRows = await client.query<{ device_id: string; payload: Record<string, unknown> }>(`
    SELECT device_id, payload FROM soc.posture_state
    WHERE dataset = 'devicetvmsoftwareinventory' AND active
      AND lower(payload->>'SoftwareVendor') = 'microsoft' AND lower(payload->>'SoftwareName') LIKE 'windows\\_server%'`);
  const kbs = await client.query<{ device_id: string; kbs: string[] }>(`
    SELECT device_id, array_agg(DISTINCT payload->>'RecommendedSecurityUpdateId') FILTER (WHERE payload->>'RecommendedSecurityUpdateId' <> '') AS kbs
    FROM soc.posture_state
    WHERE dataset = 'devicetvmsoftwarevulnerabilities' AND active AND lower(payload->>'SoftwareName') LIKE 'windows\\_server%'
    GROUP BY device_id`);
  // Exploit chega como 1/0 (ou true/false); outro valor é desconhecido, não "sem exploit".
  const vulns = await client.query<{ device_id: string; instances: number; cves: number; critical: number; exploit: number; unknown: number }>(`
    SELECT device_id, count(*)::int AS instances, count(DISTINCT payload->>'CveId')::int AS cves,
      count(DISTINCT payload->>'CveId') FILTER (WHERE lower(payload->>'VulnerabilitySeverityLevel') = 'critical')::int AS critical,
      count(DISTINCT payload->>'CveId') FILTER (WHERE payload->>'IsExploitAvailable' IN ('1', 'true'))::int AS exploit,
      count(DISTINCT payload->>'CveId') FILTER (WHERE coalesce(payload->>'IsExploitAvailable', '') NOT IN ('0', '1', 'true', 'false'))::int AS unknown
    FROM soc.posture_state WHERE dataset = 'devicetvmsoftwarevulnerabilities' AND active GROUP BY device_id`);
  const vulnSnapshot = await client.query('SELECT 1 FROM soc.collector_checkpoint WHERE source = $1', [src.vulnerabilitySource]);
  const catalog = await client.query<{ kb: string; build_major: number; ubr: number; fixed_build: string; release_date: Date; reboot_required: boolean | null; url: string | null }>(
    'SELECT kb, build_major, ubr, fixed_build, release_date, reboot_required, url FROM soc.windows_security_update');
  const checkpoint = await client.query<{ watermark: Date }>('SELECT watermark FROM soc.collector_checkpoint WHERE source = $1', [src.msrcSource]);

  const entries: CatalogEntry[] = catalog.rows.map((r) => ({ kb: r.kb, buildMajor: r.build_major, ubr: r.ubr, fixedBuild: r.fixed_build,
    releaseDate: r.release_date.toISOString(), rebootRequired: r.reboot_required, url: r.url }));
  const servers = buildServers(devices.rows.map((r) => r.payload), osRows.rows,
    new Map(kbs.rows.map((r) => [r.device_id, r.kbs ?? []])), src.namePrefix,
    new Map(vulns.rows.map((r) => [r.device_id, { instances: r.instances, cves: r.cves, critical: r.critical, exploit: r.exploit, exploitUnknown: r.unknown }])),
    (vulnSnapshot.rowCount ?? 0) > 0);
  const opts = { generatedAt, catalogUpdatedAt: checkpoint.rows[0]?.watermark.toISOString() ?? null,
    deviceStaleHours: src.deviceStaleHours, snapshotStaleHours: src.snapshotStaleHours, catalogStaleHours: src.catalogStaleHours };
  const docs = servers.map((s) => evaluateServer(s, entries, opts));

  if (docs.length) {
    // Estado atual (um documento por servidor) e foto diária para histórico, com IDs estáveis.
    const day = generatedAt.toISOString().slice(0, 10);
    const rows = docs.flatMap((d) => [
      { dataset: 'state', doc_id: d.host.id, payload: d },
      { dataset: 'history', doc_id: `${d.host.id}|${day}`, payload: d },
    ]);
    await client.query(`
      INSERT INTO soc.publication (entity, dataset, doc_id, occurred_at, payload)
      SELECT 'winupdate', dataset, doc_id, $2, payload FROM jsonb_to_recordset($1::jsonb) AS r(dataset text, doc_id text, payload jsonb)`,
    [JSON.stringify(rows), generatedAt]);
  }
  await setCheckpoint(client, src.name, generatedAt);
  return { fetched: servers.length, changed: docs.length, docs };
}

export async function collectWinUpdates(src: WinUpdatesSourceConfig, deps: { pool: Pool; log: Logger }, counters: RunCounters): Promise<void> {
  const at = new Date();
  counters.windowStart = at;
  counters.windowEnd = at;
  const result = await withTransaction(deps.pool, (client) => storeWinUpdates(client, src, at));
  counters.fetched = result.fetched;
  counters.changed = result.changed;
  const byStatus = result.docs.reduce<Record<string, number>>((acc, d) => ({ ...acc, [d.status]: (acc[d.status] ?? 0) + 1 }), {});
  deps.log.info({ source: src.name, servers: result.fetched, ...byStatus }, 'estado de atualização do Windows recalculado');
}
