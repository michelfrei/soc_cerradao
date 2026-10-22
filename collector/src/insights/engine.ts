import { canonicalJson, sha256 } from '../util.js';
import type { Category, ConfigurationEntryConfig, GpoSettingConfig, RemediationCatalog } from './catalog.js';

/**
 * Agrupa a postura TVM ativa pela ação capaz de tratá-la. Cada achado entra em
 * exatamente um bloco. Função pura: as mesmas entradas geram os mesmos insights.
 */

export const SCHEMA_VERSION = '1.0';
const SOURCE_NAME = 'microsoft-defender-vulnerability-management';

export interface Finding {
  docId: string;
  deviceId: string;
  payload: Record<string, unknown>;
}

export interface DeviceContext {
  deviceId: string;
  deviceName: string | null;
  osPlatform: string | null;
  exposureLevel: string | null;
  assetValue: string | null;
  internetFacing: boolean | null;
  criticality: string | null;
}

export interface SourceSnapshot {
  table: string;
  snapshotAt: string | null;
}

export interface InsightInputs {
  generatedAt: Date;
  vulnerabilities: Finding[];
  configurations: Finding[];
  /** null: fonte de inventário de software ainda sem snapshot concluído. */
  softwareInventory: Finding[] | null;
  devices: DeviceContext[];
  snapshots: SourceSnapshot[];
  catalog: RemediationCatalog;
}

export interface AffectedProduct {
  vendor: string | null;
  name: string;
  versions: string[];
}

export interface Insight {
  '@timestamp': string;
  schema_version: string;
  analysis_id: string;
  insight_id: string;
  grouping_key: string;
  source: {
    name: string;
    tables: string[];
    snapshot_at: Record<string, string | null>;
    finding_ids: string[];
    finding_count: number;
  };
  title: string;
  description: string;
  category: Category;
  remediation_type: 'definitive' | 'mitigation' | 'undetermined';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  priority_label: string;
  priority_score: number;
  risk_rationale: string[];
  cve_ids: string[];
  cve_count: number;
  recommendation_ids: string[];
  affected_products: AffectedProduct[];
  affected_device_count: number;
  affected_device_ids: string[];
  affected_devices: string[];
  internet_facing_device_count: number | null;
  high_value_device_count: number | null;
  exploit_available: boolean | null;
  max_severity: string | null;
  max_cvss: number | null;
  end_of_support: string[];
  remediation_steps: string[];
  gpo_name: string | null;
  gpo_settings: GpoSettingConfig[];
  scope_guidance: string | null;
  server_notes: string | null;
  dc_notes: string | null;
  compatibility_risks: string[];
  dependencies: string[];
  expected_outcome: {
    summary: string;
    finding_reduction: number | null;
    cve_reduction: number | null;
    device_reduction: number | null;
    basis: string;
  };
  effort: 'baixo' | 'medio' | 'alto' | 'desconhecido';
  operational_impact: string;
  owner: string;
  validation_steps: string[];
  rollback_steps: string[];
  references: string[];
  data_gaps: string[];
  suggested_catalog_key: string | null;
  status: 'open' | 'no_longer_reported';
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
}

const DEFAULT_OWNERS: Record<Category, string> = {
  gpo_configuration: 'Infraestrutura - AD/GPO',
  windows_update: 'Infraestrutura - atualizações Windows (WSUS)',
  application_update: 'Infraestrutura - aplicações e responsável pelo sistema',
  driver_firmware: 'Infraestrutura - hardware/virtualização',
  software_replacement: 'Responsável pelo sistema com Infraestrutura',
  script_manual: 'Infraestrutura - servidores',
  investigation: 'SOC / Segurança',
};

const CATEGORY_LABEL: Record<Category, string> = {
  gpo_configuration: 'Configuração por GPO',
  windows_update: 'Atualização do Windows',
  application_update: 'Atualização de aplicativo ou componente',
  driver_firmware: 'Atualização de driver ou firmware',
  software_replacement: 'Remoção ou substituição de software',
  script_manual: 'Script ou ação manual',
  investigation: 'Investigação adicional',
};

const SEVERITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };
const HIGH_VALUE = new Set(['high', 'alta', 'alto', 'critical', 'critica', 'crítica', 'critico', 'crítico']);
const PORTAL_IDS_GAP = 'IDs de recomendação do portal (va-_-/sca-_-) não são expostos pelo Advanced Hunting; recommendation_ids traz scid/KB.';

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function lower(value: unknown): string | null {
  return text(value)?.toLowerCase() ?? null;
}

function bool(value: unknown): boolean | null {
  if (value === true || value === 'true' || value === 1 || value === '1') return true;
  if (value === false || value === 'false' || value === 0 || value === '0') return false;
  return null;
}

function cvss(value: unknown): number | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Number(value) : NaN;
  return Number.isFinite(n) && n >= 0 && n <= 10 ? n : null;
}

function kb(value: unknown): string | null {
  const id = text(value);
  if (!id) return null;
  return /^\d+$/.test(id) ? `KB${id}` : id.toUpperCase();
}

const sorted = (values: Iterable<string>): string[] => [...new Set(values)].sort();

function softwareKey(vendor: string | null, name: string): string {
  return `${vendor ?? ''}|${name}`;
}

/** Sistema operacional Windows (windows_server_2022, windows_11…); windows_admin_center é aplicativo. */
function isWindowsOs(vendor: string | null, name: string): boolean {
  return vendor === 'microsoft' && /^windows_(server_\d{4}\w*|1[01]|7|8(_1)?)$/.test(name);
}

type EosStatus = 'eos_software' | 'eos_version' | 'upcoming_software' | 'upcoming_version';

function eosStatus(value: unknown): EosStatus | null {
  const s = lower(value);
  if (!s) return null;
  const upcoming = s.includes('upcoming');
  if (s.includes('software')) return upcoming ? 'upcoming_software' : 'eos_software';
  if (s.includes('version')) return upcoming ? 'upcoming_version' : 'eos_version';
  return null;
}

interface Block {
  category: Category;
  groupingKey: string;
  title: string;
  catalogEntry?: ConfigurationEntryConfig;
  ruleNote?: string;
  ruleOwner?: string;
  heuristic?: string;
  vulns: Finding[];
  configs: Finding[];
  eos: Finding[];
}

export function insightId(category: Category, groupingKey: string): string {
  return `ins-${sha256(canonicalJson([category, groupingKey])).slice(0, 32)}`;
}

export function analysisId(generatedAt: Date): string {
  return `soc-insights-${generatedAt.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z')}`;
}

function classifyBlocks(inputs: InsightInputs): Block[] {
  const blocks = new Map<string, Block>();
  const block = (category: Category, groupingKey: string, title: string, extra: Partial<Block> = {}): Block => {
    const id = `${category}|${groupingKey}`;
    let b = blocks.get(id);
    if (!b) {
      b = { category, groupingKey, title, vulns: [], configs: [], eos: [], ...extra };
      blocks.set(id, b);
    }
    return b;
  };

  // Fim de suporte por dispositivo+software+versão e por dispositivo+software.
  const eosByVersion = new Map<string, EosStatus>();
  const eosBySoftware = new Map<string, EosStatus>();
  for (const f of inputs.softwareInventory ?? []) {
    const status = eosStatus(f.payload.EndOfSupportStatus);
    const name = lower(f.payload.SoftwareName);
    if (!status || !name) continue;
    const sw = softwareKey(lower(f.payload.SoftwareVendor), name);
    eosByVersion.set(`${f.deviceId}|${sw}|${lower(f.payload.SoftwareVersion) ?? ''}`, status);
    if (status === 'eos_software' || status === 'upcoming_software') eosBySoftware.set(`${f.deviceId}|${sw}`, status);
  }

  const softwareBlock = (vendor: string | null, name: string, displayVendor: string, displayName: string,
    eos: EosStatus | null): Block => {
    const sw = softwareKey(vendor, name);
    const rule = inputs.catalog.software_rules.find((r) => r.vendor === (vendor ?? '') && new RegExp(r.name_pattern, 'i').test(name));
    if (rule) {
      return block(rule.category, sw, `${CATEGORY_LABEL[rule.category]}: ${displayVendor} ${displayName}`,
        { ruleNote: rule.note, ...(rule.owner ? { ruleOwner: rule.owner } : {}) });
    }
    if (eos === 'eos_software' || eos === 'upcoming_software') {
      return block('software_replacement', sw, `Substituir ou remover ${displayVendor} ${displayName} (fim de suporte)`);
    }
    if (isWindowsOs(vendor, name)) {
      return block('windows_update', name, `Aplicar a atualização cumulativa mais recente em ${displayName}`);
    }
    if (/firmware|bios|driver/.test(name)) {
      return block('driver_firmware', sw, `Atualizar driver/firmware ${displayVendor} ${displayName}`,
        { heuristic: 'Classificado como driver/firmware pelo nome do software; confirmar com o fabricante.' });
    }
    return block('application_update', sw, `Atualizar ${displayVendor} ${displayName}`);
  };

  for (const f of inputs.vulnerabilities) {
    const name = lower(f.payload.SoftwareName);
    if (!name) continue;
    const vendor = lower(f.payload.SoftwareVendor);
    const version = lower(f.payload.SoftwareVersion) ?? '';
    const sw = softwareKey(vendor, name);
    const eos = eosBySoftware.get(`${f.deviceId}|${sw}`) ?? eosByVersion.get(`${f.deviceId}|${sw}|${version}`) ?? null;
    // Windows: um bloco por SO. As atualizações de segurança são cumulativas: a mais
    // recente trata as CVEs dos KBs anteriores, que ficam como evidência.
    softwareBlock(vendor, name, text(f.payload.SoftwareVendor) ?? '', text(f.payload.SoftwareName)!, eos).vulns.push(f);
  }

  // Software sem suporte sem CVE ativo também exige decisão de substituição.
  for (const f of inputs.softwareInventory ?? []) {
    const status = eosStatus(f.payload.EndOfSupportStatus);
    const name = lower(f.payload.SoftwareName);
    if (!status || !name) continue;
    const vendor = lower(f.payload.SoftwareVendor);
    const b = status === 'eos_software' || status === 'upcoming_software'
      ? softwareBlock(vendor, name, text(f.payload.SoftwareVendor) ?? '', text(f.payload.SoftwareName)!, status)
      : [...blocks.values()].find((x) => x.groupingKey === softwareKey(vendor, name) && x.category !== 'investigation')
        ?? softwareBlock(vendor, name, text(f.payload.SoftwareVendor) ?? '', text(f.payload.SoftwareName)!, status);
    b.eos.push(f);
  }

  const byScid = new Map<string, ConfigurationEntryConfig>();
  for (const entry of inputs.catalog.configurations) for (const id of entry.configuration_ids) byScid.set(id, entry);
  for (const f of inputs.configurations) {
    if (bool(f.payload.IsApplicable) !== true || bool(f.payload.IsCompliant) !== false) continue;
    const scid = text(f.payload.ConfigurationId);
    if (!scid) continue;
    const entry = byScid.get(scid);
    if (entry) {
      block(entry.category, entry.key, entry.title, { catalogEntry: entry }).configs.push(f);
    } else {
      const name = text(f.payload.ConfigurationName) ?? scid;
      block('investigation', `configuration|${scid}`, `Avaliar tratamento: ${name}`).configs.push(f);
    }
  }
  return [...blocks.values()];
}

function suggestCatalog(catalog: RemediationCatalog, configs: Finding[]): ConfigurationEntryConfig | null {
  const names = configs.map((f) => `${lower(f.payload.ConfigurationName) ?? ''} ${lower(f.payload.RemediationOptions) ?? ''}`);
  for (const entry of catalog.configurations) {
    if (entry.name_hints.some((h) => names.some((n) => n.includes(h.toLowerCase())))) return entry;
  }
  return null;
}

function priority(score: number): Pick<Insight, 'priority' | 'priority_label'> {
  if (score >= 70) return { priority: 'P1', priority_label: 'crítica' };
  if (score >= 45) return { priority: 'P2', priority_label: 'alta' };
  if (score >= 25) return { priority: 'P3', priority_label: 'média' };
  return { priority: 'P4', priority_label: 'baixa' };
}

function references(category: Category, cves: string[], kbs: string[], entry?: ConfigurationEntryConfig): string[] {
  const refs: string[] = [...(entry?.references ?? [])];
  for (const id of kbs.filter((k) => /^KB\d+$/.test(k))) refs.push(`https://support.microsoft.com/help/${id.slice(2)}`);
  const msrc = category === 'windows_update';
  for (const cve of cves.slice(0, 10)) {
    refs.push(msrc ? `https://msrc.microsoft.com/update-guide/vulnerability/${cve}` : `https://nvd.nist.gov/vuln/detail/${cve}`);
  }
  if (category === 'software_replacement' || category === 'windows_update') {
    refs.push('https://learn.microsoft.com/defender-vulnerability-management/tvm-end-of-support-software');
  }
  refs.push('https://learn.microsoft.com/defender-vulnerability-management/tvm-security-recommendation');
  return sorted(refs);
}

function buildInsight(b: Block, inputs: InsightInputs, devices: Map<string, DeviceContext>, gapsBase: string[]): Insight {
  const at = inputs.generatedAt.toISOString();
  const findings = [...b.vulns, ...b.configs, ...b.eos];
  const deviceIds = sorted(findings.map((f) => f.deviceId));
  const contexts = deviceIds.map((id) => devices.get(id));
  const known = contexts.filter((c): c is DeviceContext => !!c);
  const names = sorted(deviceIds.map((id, i) => contexts[i]?.deviceName ?? lower(findings.find((f) => f.deviceId === id)?.payload.DeviceName) ?? id));
  const cves = sorted(b.vulns.map((f) => text(f.payload.CveId)?.toUpperCase()).filter((v): v is string => !!v));
  const kbs = sorted(b.vulns.map((f) => kb(f.payload.RecommendedSecurityUpdateId)).filter((v): v is string => !!v));
  const scids = sorted(b.configs.map((f) => text(f.payload.ConfigurationId)).filter((v): v is string => !!v));
  const gaps = [...gapsBase];

  // Produtos e versões afetados.
  const products = new Map<string, AffectedProduct>();
  for (const f of [...b.vulns, ...b.eos]) {
    const name = text(f.payload.SoftwareName);
    if (!name) continue;
    const vendor = text(f.payload.SoftwareVendor);
    const key = softwareKey(vendor?.toLowerCase() ?? null, name.toLowerCase());
    const p = products.get(key) ?? { vendor, name, versions: [] };
    const version = text(f.payload.SoftwareVersion);
    if (version && !p.versions.includes(version)) p.versions.push(version);
    products.set(key, p);
  }
  for (const p of products.values()) p.versions.sort();
  const eosLabels = sorted(b.eos.map((f) => `${text(f.payload.SoftwareName)} ${text(f.payload.SoftwareVersion) ?? ''}: ${text(f.payload.EndOfSupportStatus)}${text(f.payload.EndOfSupportDate) ? ` (${text(f.payload.EndOfSupportDate)})` : ''}`.trim()));

  // Evidências de risco; desconhecido nunca vira zero/falso.
  const exploitValues = b.vulns.map((f) => bool(f.payload.IsExploitAvailable));
  const exploit = exploitValues.includes(true) ? true : exploitValues.length && exploitValues.every((v) => v === false) ? false : null;
  const exploitCves = sorted(b.vulns.filter((f) => bool(f.payload.IsExploitAvailable) === true).map((f) => text(f.payload.CveId) ?? ''));
  const severities = b.vulns.map((f) => lower(f.payload.VulnerabilitySeverityLevel)).filter((s): s is string => !!s && s in SEVERITY_RANK);
  const maxSeverity = severities.sort((x, y) => SEVERITY_RANK[y]! - SEVERITY_RANK[x]!)[0] ?? null;
  const scores = b.vulns.map((f) => cvss(f.payload.CvssScore)).filter((v): v is number => v !== null);
  const maxCvss = scores.length ? Math.max(...scores) : null;
  const impacts = b.configs.map((f) => cvss(f.payload.ConfigurationImpact)).filter((v): v is number => v !== null);
  const maxImpact = impacts.length ? Math.max(...impacts) : null;
  const allKnown = known.length === deviceIds.length;
  const internet = known.filter((c) => c.internetFacing === true).length;
  const internetCount = internet > 0 || (allKnown && known.every((c) => c.internetFacing === false)) ? internet : null;
  const highValue = known.filter((c) => HIGH_VALUE.has(c.assetValue ?? '') || HIGH_VALUE.has(c.criticality ?? '') || c.exposureLevel === 'high').length;
  const valueKnown = known.filter((c) => c.assetValue || c.criticality || c.exposureLevel).length;
  const highValueCount = highValue > 0 || (allKnown && valueKnown === known.length && known.length > 0) ? highValue : null;

  let score = 0;
  const rationale: string[] = [];
  if (exploit === true) { score += 40; rationale.push(`Exploit público disponível segundo o Defender (${exploitCves.length} CVE): ${exploitCves.slice(0, 5).join(', ')}${exploitCves.length > 5 ? '…' : ''}. Não comprova exploração observada.`); }
  if (maxSeverity === 'critical') { score += 25; rationale.push('Severidade máxima reportada: crítica.'); }
  else if (maxSeverity === 'high') { score += 15; rationale.push('Severidade máxima reportada: alta.'); }
  else if (maxSeverity === 'medium') { score += 5; rationale.push('Severidade máxima reportada: média.'); }
  if (maxCvss !== null && maxCvss >= 9) { score += 5; rationale.push(`CVSS máximo ${maxCvss}.`); }
  if (maxImpact !== null) {
    if (maxImpact >= 7) score += 20; else if (maxImpact >= 4) score += 10;
    rationale.push(`Impacto da configuração reportado pelo Defender: ${maxImpact}.`);
  }
  if (internet > 0) { score += 20; rationale.push(`${internet} servidor(es) reportado(s) como expostos à Internet.`); }
  if (highValue > 0) { score += 15; rationale.push(`${highValue} servidor(es) de alto valor/exposição alta/criticidade alta.`); }
  if (deviceIds.length >= 10) { score += 10; rationale.push(`Abrangência: ${deviceIds.length} servidores.`); }
  else if (deviceIds.length >= 3) { score += 5; rationale.push(`Abrangência: ${deviceIds.length} servidores.`); }
  if (b.category === 'software_replacement' && b.eos.some((f) => eosStatus(f.payload.EndOfSupportStatus) === 'eos_software')) {
    score += 15; rationale.push('Software sem suporte do fabricante: não receberá novas correções.');
  }
  if (!rationale.length) rationale.push('Sem fatores de agravamento identificados nos dados disponíveis.');

  if (exploit === null && b.vulns.length) gaps.push('Informação de exploit ausente para ao menos uma CVE do bloco.');
  if (b.vulns.length && scores.length < b.vulns.length) gaps.push('CVSS ausente ou inválido em parte das instâncias (mantido no bruto, sem score inventado).');
  if (!allKnown) gaps.push(`${deviceIds.length - known.length} servidor(es) sem registro em DeviceInfo: exposição e valor desconhecidos.`);
  if (highValueCount === null) gaps.push('Valor/criticidade do ativo não informado para todos os servidores (assets.json ou AssetValue do Defender).');
  if (b.category === 'windows_update' && !kbs.length && b.vulns.length) gaps.push('Defender não informou a atualização recomendada (KB).');
  if (b.heuristic) gaps.push(b.heuristic);
  if (inputs.softwareInventory === null && b.vulns.length) gaps.push('Inventário de fim de suporte ainda não coletado: substituição não avaliada.');
  // A Microsoft documenta fim de suporte do TVM apenas para produtos Windows.
  if (b.vulns.length && [...products.values()].some((p) => p.vendor?.toLowerCase() !== 'microsoft')) {
    gaps.push('Fim de suporte de software não Microsoft não é informado pelo Defender; confirmar o ciclo de vida com o fabricante.');
  }

  const entry = b.catalogEntry;
  const suggestion = b.category === 'investigation' ? suggestCatalog(inputs.catalog, b.configs) : null;
  const definitive = b.category !== 'investigation' && (!entry || entry.remediation_type === 'definitive');
  const remediationType: Insight['remediation_type'] = b.category === 'investigation' ? 'undetermined' : entry?.remediation_type ?? 'definitive';
  const productList = [...products.values()].map((p) => `${p.vendor ? `${p.vendor} ` : ''}${p.name} (${p.versions.join(', ') || 'versão não informada'})`);
  const updateText = sorted(b.vulns.map((f) => text(f.payload.RecommendedSecurityUpdate)).filter((v): v is string => !!v));

  const steps: Record<Category, () => string[]> = {
    gpo_configuration: () => entry!.remediation_steps,
    script_manual: () => entry?.remediation_steps ?? [],
    windows_update: () => [
      'Aprovar no WSUS/ferramenta de distribuição a atualização cumulativa (LCU) mais recente deste SO: ela inclui as correções dos KBs anteriores.',
      ...(kbs.length ? [`KBs indicados pelo Defender para as CVEs do bloco (evidência; os anteriores são substituídos pela LCU mais recente): ${kbs.slice(0, 15).join(', ')}${kbs.length > 15 ? ` e mais ${kbs.length - 15}` : ''}.`] : []),
      ...(updateText.length ? [`Atualização indicada pelo Defender: ${updateText.slice(0, 5).join('; ')}.`] : []),
      ...(b.eos.length ? ['Versão sem suporte: planejar atualização para versão com suporte antes de aplicar correções.'] : []),
      'Aplicar primeiro em servidores piloto e respeitar a janela de reinicialização.',
      'Expandir aos demais servidores após 48 h sem incidentes no piloto.',
    ],
    application_update: () => [
      `Atualizar ${productList.join('; ')} para a versão corrigida mais recente suportada pelo fabricante.`,
      ...(updateText.length ? [`Orientação do Defender: ${updateText.slice(0, 5).join('; ')}.`] : []),
      ...(b.eos.length ? ['Há versão sem suporte: a atualização deve migrar para uma versão suportada.'] : []),
      ...(b.ruleNote ? [b.ruleNote] : []),
      'Distribuir pela ferramenta existente (WSUS para produtos Microsoft, pacote do fabricante ou atualização manual) começando por um piloto.',
    ],
    driver_firmware: () => [
      `Obter do fabricante a versão corrigida de ${productList.join('; ')} compatível com o hardware/hipervisor.`,
      ...(b.ruleNote ? [b.ruleNote] : []),
      'Aplicar em janela de manutenção com acesso de console fora de banda disponível.',
    ],
    software_replacement: () => [
      `Confirmar com o responsável a necessidade de ${productList.join('; ')}.`,
      'Remover se não for necessário; caso contrário, migrar para versão/produto com suporte do fabricante.',
      ...(eosLabels.length ? [`Fim de suporte reportado: ${eosLabels.slice(0, 5).join('; ')}.`] : []),
      ...(b.ruleNote ? [b.ruleNote] : []),
      'Até a substituição, avaliar mitigação (restrição de rede, desinstalação de componentes não usados).',
    ],
    investigation: () => [
      'Nenhuma ação validada no catálogo para esta configuração; avaliar a orientação do Defender abaixo.',
      ...sorted(b.configs.map((f) => text(f.payload.RemediationOptions)).filter((v): v is string => !!v)).slice(0, 3).map((r) => `Orientação do Defender (não validada): ${r}`),
      ...(suggestion ? [`Possível correspondência com a entrada "${suggestion.key}" do catálogo; confirmar e incluir ${scids.join(', ')} em configuration_ids.`] : []),
      'Após validar em documentação oficial, cadastrar a ação em remediation-catalog.json.',
    ],
  };

  const validation: Record<Category, () => string[]> = {
    gpo_configuration: () => entry!.validation_steps,
    script_manual: () => entry?.validation_steps ?? [],
    windows_update: () => [
      'No servidor: Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 (confirmar a LCU aprovada).',
      'Aguardar o Defender refletir a mudança (software: em geral 2 h) e o próximo snapshot TVM (a cada 6 h); confirmar em soc-posture que as instâncias passaram a no_longer_reported.',
      'Conferir neste insight a queda de affected_device_count; status no_longer_reported indica ausência do achado, não prova de correção.',
    ],
    application_update: () => [
      'Conferir a versão instalada no servidor (Programas e Recursos ou o próprio aplicativo).',
      'Aguardar o próximo snapshot TVM e confirmar no_longer_reported das instâncias em soc-posture.',
    ],
    driver_firmware: () => ['Conferir a versão do driver/firmware no servidor ou na console do fabricante.', 'Aguardar o próximo snapshot TVM e confirmar no_longer_reported.'],
    software_replacement: () => ['Confirmar a remoção/substituição no servidor.', 'Conferir que o software não consta mais em soc-posture após o próximo snapshot.'],
    investigation: () => ['Registrar a decisão (tratar, aceitar risco ou exceção) antes de fechar o bloco.'],
  };

  const rollback: Record<Category, () => string[]> = {
    gpo_configuration: () => entry!.rollback_steps,
    script_manual: () => entry?.rollback_steps ?? [],
    windows_update: () => [
      'Se houver regressão: wusa /uninstall /kb:<número da LCU aplicada> (ou Configurações > Atualizações > Desinstalar) e recusar a atualização no WSUS.',
      'Restaurar snapshot/backup da VM se a desinstalação não for suportada pela atualização.',
    ],
    application_update: () => ['Reinstalar a versão anterior a partir do pacote homologado e registrar o motivo.'],
    driver_firmware: () => ['Usar o procedimento de rollback do fabricante (driver anterior ou firmware de recuperação).'],
    software_replacement: () => ['Reinstalar o software a partir da mídia homologada, se a remoção afetar o negócio.'],
    investigation: () => ['Não se aplica até haver ação definida.'],
  };

  const cveCount = cves.length;
  const outcome: Insight['expected_outcome'] = definitive && b.category !== 'software_replacement'
    ? {
      summary: `Eliminar ${findings.length} achado(s) ativo(s) em ${deviceIds.length} servidor(es).`,
      finding_reduction: findings.length,
      cve_reduction: b.vulns.length ? cveCount : null,
      device_reduction: null,
      basis: 'Cada achado foi atribuído a um único bloco cuja ação, segundo o Defender, o trata. A redução de dispositivos não é estimada: o servidor pode ter achados em outros blocos.',
    }
    : {
      summary: b.category === 'investigation' ? 'Definir a ação após investigação.'
        : remediationType === 'mitigation' ? 'Reduzir o risco; a vulnerabilidade/configuração pode continuar reportada.'
          : 'Eliminar os achados do software removido/substituído.',
      finding_reduction: b.category === 'software_replacement' ? findings.length : null,
      cve_reduction: b.category === 'software_replacement' && b.vulns.length ? cveCount : null,
      device_reduction: null,
      basis: b.category === 'software_replacement'
        ? 'Remoção elimina os achados deste software; substituição por outro produto pode gerar achados novos.'
        : 'Dados insuficientes para estimar redução.',
    };

  const effort: Insight['effort'] = entry ? entry.effort
    : b.category === 'investigation' ? 'desconhecido'
      : b.category === 'software_replacement' || b.category === 'driver_firmware' ? 'alto'
        : deviceIds.length > 3 || b.category === 'windows_update' ? 'medio' : 'baixo';
  const impact: Record<Category, string> = {
    gpo_configuration: entry?.operational_impact ?? '',
    script_manual: entry?.operational_impact ?? '',
    windows_update: 'Exige reinicialização dos servidores; agendar janela e respeitar dependências de clusters/serviços.',
    application_update: 'Pode exigir parada do aplicativo; validar compatibilidade com o responsável pelo sistema.',
    driver_firmware: 'Exige janela de manutenção e, em geral, reinicialização; risco maior de indisponibilidade.',
    software_replacement: 'Pode afetar sistemas de negócio dependentes; exige planejamento com o responsável.',
    investigation: 'Desconhecido até a ação ser definida.',
  };

  const descriptionParts = [
    `${CATEGORY_LABEL[b.category]}. ${findings.length} achado(s) em ${deviceIds.length} servidor(es)`,
    cveCount ? `${cveCount} CVE(s) distinta(s)` : null,
    scids.length ? `configuração ${scids.join(', ')}` : null,
    productList.length ? `produtos: ${productList.slice(0, 5).join('; ')}` : null,
  ].filter(Boolean);

  const owner = b.ruleOwner ?? entry?.owner ?? inputs.catalog.owners[b.category] ?? DEFAULT_OWNERS[b.category];
  const tables = sorted([
    ...(b.vulns.length ? ['DeviceTvmSoftwareVulnerabilities'] : []),
    ...(b.configs.length ? ['DeviceTvmSecureConfigurationAssessment'] : []),
    ...(b.eos.length ? ['DeviceTvmSoftwareInventory'] : []),
  ]);
  const snapshotAt = Object.fromEntries(inputs.snapshots.filter((s) => tables.includes(s.table)).map((s) => [s.table, s.snapshotAt]));

  return {
    '@timestamp': at,
    schema_version: SCHEMA_VERSION,
    analysis_id: analysisId(inputs.generatedAt),
    insight_id: insightId(b.category, b.groupingKey),
    grouping_key: `${b.category}|${b.groupingKey}`,
    source: { name: SOURCE_NAME, tables, snapshot_at: snapshotAt, finding_ids: sorted(findings.map((f) => f.docId)), finding_count: findings.length },
    title: b.title,
    description: `${descriptionParts.join('; ')}.`,
    category: b.category,
    remediation_type: remediationType,
    ...priority(score),
    priority_score: score,
    risk_rationale: rationale,
    cve_ids: cves,
    cve_count: cveCount,
    recommendation_ids: sorted([...scids, ...kbs]),
    affected_products: [...products.values()].sort((x, y) => `${x.vendor}|${x.name}`.localeCompare(`${y.vendor}|${y.name}`)),
    affected_device_count: deviceIds.length,
    affected_device_ids: deviceIds,
    affected_devices: names,
    internet_facing_device_count: internetCount,
    high_value_device_count: highValueCount,
    exploit_available: b.vulns.length ? exploit : null,
    max_severity: maxSeverity,
    max_cvss: maxCvss,
    end_of_support: eosLabels,
    remediation_steps: steps[b.category](),
    gpo_name: entry?.gpo_name ?? null,
    gpo_settings: entry?.gpo_settings ?? [],
    scope_guidance: entry?.scope_guidance ?? null,
    server_notes: entry?.server_notes ?? null,
    dc_notes: entry?.dc_notes ?? null,
    compatibility_risks: entry?.compatibility_risks ?? [],
    dependencies: [
      ...(entry?.dependencies ?? []),
      ...(b.category === 'windows_update' ? ['Servidor de distribuição (WSUS) com a atualização aprovada.'] : []),
      ...(b.category === 'windows_update' && b.groupingKey === 'windows_server_2016'
        ? ['Windows Server 2016: instalar antes a Servicing Stack Update (SSU) mais recente indicada na página da LCU.'] : []),
    ],
    expected_outcome: outcome,
    effort,
    operational_impact: impact[b.category],
    owner,
    validation_steps: validation[b.category](),
    rollback_steps: rollback[b.category](),
    references: references(b.category, cves, kbs, entry ?? suggestion ?? undefined),
    data_gaps: sorted(gaps),
    suggested_catalog_key: suggestion?.key ?? null,
    status: 'open',
    first_seen: at,
    last_seen: at,
    resolved_at: null,
  };
}

export function buildInsights(inputs: InsightInputs): Insight[] {
  const devices = new Map(inputs.devices.map((d) => [d.deviceId, d]));
  const gapsBase = [PORTAL_IDS_GAP];
  const generated = inputs.generatedAt.getTime();
  for (const s of inputs.snapshots) {
    if (!s.snapshotAt) gapsBase.push(`${s.table}: sem snapshot concluído.`);
    else if (generated - Date.parse(s.snapshotAt) > 36 * 3600_000) gapsBase.push(`${s.table}: snapshot com mais de 36 h (${s.snapshotAt}).`);
  }
  return classifyBlocks(inputs)
    .filter((b) => b.vulns.length + b.configs.length + b.eos.length > 0)
    .map((b) => buildInsight(b, inputs, devices, gapsBase))
    .sort((x, y) => y.priority_score - x.priority_score || x.insight_id.localeCompare(y.insight_id));
}

/** Hash do conteúdo, sem campos que mudam a cada execução. */
export function contentHash(insight: Insight): string {
  const { '@timestamp': _t, analysis_id: _a, last_seen: _l, first_seen: _f, status: _s, resolved_at: _r, ...content } = insight;
  const { snapshot_at: _snap, ...source } = content.source;
  return sha256(canonicalJson({ ...content, source, data_gaps: content.data_gaps.filter((g) => !/snapshot/.test(g)) }));
}
