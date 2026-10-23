/**
 * Estado de atualização do Windows Server por servidor, só com dados do Defender
 * (build do SO pelo inventário TVM) e do catálogo de segurança da Microsoft (MSRC).
 * Cada servidor é comparado com as atualizações da própria build (14393, 17763,
 * 20348…), nunca com um KB único. Atualizações cumulativas: a mais recente
 * substitui as anteriores. Previews opcionais não estão no catálogo de segurança.
 */

export const SCHEMA_VERSION = '1.0';

export interface CatalogEntry {
  kb: string;
  buildMajor: number;
  ubr: number;
  fixedBuild: string;
  releaseDate: string;
  rebootRequired: boolean | null;
  url: string | null;
}

export interface ServerInput {
  deviceId: string;
  deviceName: string;
  osPlatform: string;
  lastSeen: string | null;
  /** Versão do SO no inventário TVM (ex.: 10.0.20348.4405) e horário do snapshot. */
  osVersion: string | null;
  osSnapshotAt: string | null;
  /** KBs que o Defender recomenda para CVEs do próprio SO neste servidor (evidência). */
  defenderKbs: string[];
  /** Vulnerabilidades ativas no servidor (todo software); null = sem dados de vulnerabilidade. */
  vulnerabilities: VulnerabilityStats | null;
}

export interface VulnerabilityStats {
  instances: number;
  cves: number;
  critical: number;
  exploit: number;
  exploitUnknown: number;
}

export interface WinUpdateOptions {
  generatedAt: Date;
  catalogUpdatedAt: string | null;
  deviceStaleHours: number;
  snapshotStaleHours: number;
  catalogStaleHours: number;
}

export type Status = 'em_dia' | 'pendente' | 'nao_determinado' | 'coleta_desatualizada';

const STATUS_LABEL: Record<Status, string> = {
  em_dia: 'Em dia', pendente: 'Pendente', nao_determinado: 'Não determinado', coleta_desatualizada: 'Coleta desatualizada',
};

export interface WinUpdateDoc {
  '@timestamp': string;
  schema_version: string;
  host: { id: string; name: string };
  windows: { product: string; os_platform: string; version: string | null; build: string | null; build_major: number | null; ubr: number | null };
  update: {
    latest_kb: string | null;
    latest_release_date: string | null;
    latest_fixed_build: string | null;
    latest_url: string | null;
    installed_kb: string | null;
    installed_release_date: string | null;
    installed_match: 'exata' | 'equivalente' | 'acima_da_seguranca' | null;
    pending: boolean | null;
    pending_kb: string | null;
    pending_superseded_count: number | null;
    reboot_required: boolean | null;
    reboot_required_label: string;
    days_since_latest_release: number | null;
    oldest_pending_kb: string | null;
    oldest_pending_release_date: string | null;
    defender_recommended_kbs: string[];
  };
  vulnerabilities: {
    instance_count: number | null;
    cve_count: number | null;
    critical_cve_count: number | null;
    exploit_cve_count: number | null;
    exploit_unknown_count: number | null;
  };
  status: Status;
  status_label: string;
  status_reason: string;
  collection: { device_last_seen: string | null; build_snapshot_at: string | null; catalog_updated_at: string | null; collected_at: string };
}

const BUILD = /^10\.0\.(\d+)\.(\d+)$/;

function hoursBetween(later: Date, iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : (later.getTime() - t) / 3_600_000;
}

/** WindowsServer2022 → Windows Server 2022. */
export function productName(osPlatform: string): string {
  const m = /^WindowsServer(\d{4})(.*)$/i.exec(osPlatform);
  return m ? `Windows Server ${m[1]}${m[2] ? ` ${m[2]}` : ''}` : osPlatform;
}

export function isInScope(name: string, osPlatform: string, prefix: string): boolean {
  return name.toLowerCase().startsWith(prefix.toLowerCase()) && /^windowsserver/i.test(osPlatform);
}

export function evaluateServer(s: ServerInput, catalog: CatalogEntry[], opts: WinUpdateOptions): WinUpdateDoc {
  const now = opts.generatedAt;
  const m = s.osVersion ? BUILD.exec(s.osVersion) : null;
  const major = m ? Number(m[1]) : null;
  const ubr = m ? Number(m[2]) : null;
  const entries = major === null ? [] : catalog.filter((c) => c.buildMajor === major).sort((a, b) => a.ubr - b.ubr);
  const latest = entries.at(-1) ?? null;
  const exact = ubr === null ? undefined : entries.find((c) => c.ubr === ubr);
  const below = ubr === null ? [] : entries.filter((c) => c.ubr <= ubr);
  const installed = exact ?? below.at(-1) ?? null;
  const newer = ubr === null ? [] : entries.filter((c) => c.ubr > ubr);
  const pending = latest && ubr !== null ? ubr < latest.ubr : null;
  const installedMatch: WinUpdateDoc['update']['installed_match'] = !installed || ubr === null ? null
    : exact ? 'exata' : latest && ubr > latest.ubr ? 'acima_da_seguranca' : 'equivalente';

  const reasons: string[] = [];
  let status: Status;
  if (!m) {
    status = 'nao_determinado';
    reasons.push(s.osVersion ? `Build do Windows em formato não reconhecido (${s.osVersion}).` : 'Defender não informou a build do Windows.');
  } else if (!latest) {
    status = 'nao_determinado';
    reasons.push(`Catálogo de segurança da Microsoft sem atualizações para a build ${major}.`);
  } else if (pending) {
    status = 'pendente';
    reasons.push(`Build ${s.osVersion} anterior à ${latest.fixedBuild} da ${latest.kb}; ${newer.length} atualização(ões) de segurança lançada(s) desde a build instalada.`);
  } else {
    status = 'em_dia';
    reasons.push(installedMatch === 'acima_da_seguranca'
      ? `Build ${s.osVersion} acima da última de segurança (${latest.fixedBuild}); provável preview opcional ou atualização fora do ciclo.`
      : `Build ${s.osVersion} corresponde à atualização de segurança mais recente (${latest.kb}).`);
  }
  const stale: string[] = [];
  const seenAge = hoursBetween(now, s.lastSeen);
  if (seenAge === null || seenAge > opts.deviceStaleHours) stale.push(seenAge === null ? 'último contato do sensor desconhecido' : `sensor sem contato há ${Math.floor(seenAge)} h`);
  const buildAge = hoursBetween(now, s.osSnapshotAt);
  if (m && (buildAge === null || buildAge > opts.snapshotStaleHours)) stale.push(`build coletada há ${buildAge === null ? '?' : Math.floor(buildAge)} h`);
  const catalogAge = hoursBetween(now, opts.catalogUpdatedAt);
  if (catalogAge === null || catalogAge > opts.catalogStaleHours) stale.push(catalogAge === null ? 'catálogo Microsoft nunca atualizado' : `catálogo Microsoft atualizado há ${Math.floor(catalogAge)} h`);
  if (stale.length && status !== 'nao_determinado') {
    reasons.unshift(`Situação calculada com dados antigos (${stale.join('; ')}).`);
    status = 'coleta_desatualizada';
  } else if (stale.length) {
    reasons.push(`Dados antigos: ${stale.join('; ')}.`);
  }

  const reboot = pending && latest ? latest.rebootRequired : null;
  return {
    '@timestamp': now.toISOString(),
    schema_version: SCHEMA_VERSION,
    host: { id: s.deviceId, name: s.deviceName.toLowerCase() },
    windows: { product: productName(s.osPlatform), os_platform: s.osPlatform, version: s.osVersion, build: m ? `${major}.${ubr}` : null, build_major: major, ubr },
    update: {
      latest_kb: latest?.kb ?? null,
      latest_release_date: latest?.releaseDate ?? null,
      latest_fixed_build: latest?.fixedBuild ?? null,
      latest_url: latest?.url ?? null,
      installed_kb: installed?.kb ?? null,
      installed_release_date: installed?.releaseDate ?? null,
      installed_match: installedMatch,
      pending,
      pending_kb: pending ? latest!.kb : null,
      pending_superseded_count: pending ? newer.length - 1 : pending === false ? 0 : null,
      reboot_required: reboot,
      reboot_required_label: !pending ? (pending === false ? 'Sem atualização pendente' : 'Não determinado')
        : reboot === true ? 'Sim (segundo a Microsoft)' : reboot === false ? 'Não (segundo a Microsoft)' : 'Não informado pela Microsoft',
      days_since_latest_release: pending && latest ? Math.floor((now.getTime() - Date.parse(latest.releaseDate)) / 86_400_000) : null,
      // Primeira atualização de segurança da própria build ausente: desde quando o servidor está desatualizado.
      oldest_pending_kb: newer[0]?.kb ?? null,
      oldest_pending_release_date: newer[0]?.releaseDate ?? null,
      defender_recommended_kbs: [...new Set(s.defenderKbs)].sort(),
    },
    vulnerabilities: {
      instance_count: s.vulnerabilities?.instances ?? null,
      cve_count: s.vulnerabilities?.cves ?? null,
      critical_cve_count: s.vulnerabilities?.critical ?? null,
      exploit_cve_count: s.vulnerabilities?.exploit ?? null,
      exploit_unknown_count: s.vulnerabilities?.exploitUnknown ?? null,
    },
    status,
    status_label: STATUS_LABEL[status],
    status_reason: reasons.join(' '),
    collection: { device_last_seen: s.lastSeen, build_snapshot_at: s.osSnapshotAt, catalog_updated_at: opts.catalogUpdatedAt, collected_at: now.toISOString() },
  };
}
