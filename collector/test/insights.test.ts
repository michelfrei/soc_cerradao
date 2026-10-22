import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseSources } from '../src/config.js';
import { EMPTY_CATALOG, parseCatalog, type RemediationCatalog } from '../src/insights/catalog.js';
import { buildInsights, contentHash, insightId, type Finding, type InsightInputs } from '../src/insights/engine.js';
import { deviceContext } from '../src/sources/insights.js';

const at = new Date('2026-10-22T12:00:00Z');
const snapshots = [
  { table: 'DeviceTvmSoftwareVulnerabilities', snapshotAt: '2026-10-22T10:00:00.000Z' },
  { table: 'DeviceTvmSecureConfigurationAssessment', snapshotAt: '2026-10-22T10:00:00.000Z' },
  { table: 'DeviceTvmSoftwareInventory', snapshotAt: '2026-10-22T10:00:00.000Z' },
];

let seq = 0;
const vuln = (deviceId: string, p: Record<string, unknown>): Finding => ({ docId: `v${++seq}`, deviceId,
  payload: { DeviceId: deviceId, DeviceName: `srv-${deviceId}`, VulnerabilitySeverityLevel: 'High', ...p } });
const config = (deviceId: string, p: Record<string, unknown>): Finding => ({ docId: `c${++seq}`, deviceId,
  payload: { DeviceId: deviceId, DeviceName: `srv-${deviceId}`, IsApplicable: true, IsCompliant: false, ...p } });
const eos = (deviceId: string, p: Record<string, unknown>): Finding => ({ docId: `e${++seq}`, deviceId,
  payload: { DeviceId: deviceId, DeviceName: `srv-${deviceId}`, ...p } });

const windows = (deviceId: string, cve: string, kbId: string | null, extra: Record<string, unknown> = {}) =>
  vuln(deviceId, { SoftwareVendor: 'microsoft', SoftwareName: 'windows_server_2019', SoftwareVersion: '10.0.17763.1',
    CveId: cve, RecommendedSecurityUpdateId: kbId, RecommendedSecurityUpdate: kbId ? `Outubro (KB${kbId})` : null, ...extra });
const chrome = (deviceId: string, cve: string, version = '120.0', extra: Record<string, unknown> = {}) =>
  vuln(deviceId, { SoftwareVendor: 'google', SoftwareName: 'chrome', SoftwareVersion: version, CveId: cve, ...extra });

const catalog: RemediationCatalog = parseCatalog({
  configurations: [{
    key: 'smb-signing', title: 'Exigir assinatura SMB', category: 'gpo_configuration', remediation_type: 'definitive',
    configuration_ids: ['scid-100'], name_hints: ['smb signing'], gpo_name: 'SOC - Servidores - SMB',
    gpo_settings: [{ scope: 'computer', path: 'Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Local Policies\\Security Options',
      policy: 'Microsoft network server: Digitally sign communications (always)', value: 'Enabled' }],
    remediation_steps: ['Criar GPO'], validation_steps: ['gpresult /h'], rollback_steps: ['Desvincular GPO'],
    references: ['https://learn.microsoft.com/example'], effort: 'baixo', operational_impact: 'Baixo',
  }, {
    key: 'llmnr', title: 'Desativar LLMNR', category: 'gpo_configuration', remediation_type: 'mitigation',
    configuration_ids: [], name_hints: ['multicast name resolution'], gpo_name: 'SOC - LLMNR',
    gpo_settings: [{ scope: 'computer', path: 'Computer Configuration\\Policies\\Administrative Templates\\Network\\DNS Client',
      policy: 'Turn off multicast name resolution', value: 'Enabled' }],
    remediation_steps: ['Criar GPO'], validation_steps: ['gpresult'], rollback_steps: ['Desvincular'],
    references: ['https://learn.microsoft.com/example2'], effort: 'baixo', operational_impact: 'Baixo',
  }],
});

function inputs(p: Partial<InsightInputs>): InsightInputs {
  return { generatedAt: at, vulnerabilities: [], configurations: [], softwareInventory: [], devices: [], snapshots, catalog, ...p };
}

describe('insights de remediação', () => {
  it('agrupa Windows por KB, sem somar servidores repetidos, e separa CVEs de instâncias', () => {
    const result = buildInsights(inputs({ vulnerabilities: [
      windows('d1', 'CVE-2026-0001', '5044281'), windows('d1', 'CVE-2026-0002', '5044281'),
      windows('d2', 'CVE-2026-0001', '5044281'), windows('d3', 'CVE-2026-0003', null),
    ] }));
    const kb = result.find((i) => i.recommendation_ids.includes('KB5044281'))!;
    expect(kb).toMatchObject({ category: 'windows_update', remediation_type: 'definitive', affected_device_count: 2,
      cve_count: 2, cve_ids: ['CVE-2026-0001', 'CVE-2026-0002'], affected_device_ids: ['d1', 'd2'] });
    expect(kb.source.finding_count).toBe(3);
    expect(kb.expected_outcome).toMatchObject({ finding_reduction: 3, cve_reduction: 2, device_reduction: null });
    expect(kb.references).toContain('https://support.microsoft.com/help/5044281');
    expect(kb.remediation_steps.join(' ')).toContain('KB5044281');
    const noKb = result.find((i) => i.grouping_key === 'windows_update|windows_server_2019|sem-kb')!;
    expect(noKb.data_gaps).toContain('Defender não informou a atualização recomendada (KB).');
    expect(result).toHaveLength(2);
  });

  it('agrupa aplicativo por fornecedor/produto juntando versões e prioriza exploit + Internet', () => {
    const result = buildInsights(inputs({
      vulnerabilities: [chrome('d1', 'CVE-1', '119.0', { IsExploitAvailable: true, VulnerabilitySeverityLevel: 'Critical', CvssScore: 9.8 }),
        chrome('d2', 'CVE-2', '120.0', { IsExploitAvailable: false })],
      devices: [deviceContext({ DeviceId: 'd1', DeviceName: 'SRV-d1', IsInternetFacing: true, AssetValue: 'High', ExposureLevel: 'High' })!,
        deviceContext({ DeviceId: 'd2', DeviceName: 'SRV-d2', IsInternetFacing: false, AssetValue: 'Low', ExposureLevel: 'Low' })!],
    }));
    expect(result).toHaveLength(1);
    const app = result[0]!;
    expect(app).toMatchObject({ category: 'application_update', exploit_available: true, max_severity: 'critical', max_cvss: 9.8,
      internet_facing_device_count: 1, high_value_device_count: 1, priority: 'P1' });
    expect(app.affected_products).toEqual([{ vendor: 'google', name: 'chrome', versions: ['119.0', '120.0'] }]);
    expect(app.risk_rationale.join(' ')).toMatch(/Não comprova exploração observada/);
  });

  it('desconhecido nunca vira zero ou falso', () => {
    const [app] = buildInsights(inputs({ vulnerabilities: [chrome('d9', 'CVE-9')] }));
    expect(app).toMatchObject({ exploit_available: null, internet_facing_device_count: null, high_value_device_count: null, max_cvss: null });
    expect(app!.data_gaps.join(' ')).toMatch(/sem registro em DeviceInfo/);
    expect(app!.data_gaps.join(' ')).toMatch(/exploit ausente/);
  });

  it('software sem suporte vai para substituição, inclusive sem CVE ativo', () => {
    const result = buildInsights(inputs({
      vulnerabilities: [vuln('d1', { SoftwareVendor: 'oracle', SoftwareName: 'jre', SoftwareVersion: '7.0', CveId: 'CVE-7' })],
      softwareInventory: [
        eos('d1', { SoftwareVendor: 'oracle', SoftwareName: 'jre', SoftwareVersion: '7.0', EndOfSupportStatus: 'EOS Software', EndOfSupportDate: '2022-07-19' }),
        eos('d2', { SoftwareVendor: 'adobe', SoftwareName: 'flash_player', SoftwareVersion: '32', EndOfSupportStatus: 'EOS Software' }),
      ],
    }));
    const jre = result.find((i) => i.grouping_key === 'software_replacement|oracle|jre')!;
    expect(jre).toMatchObject({ category: 'software_replacement', cve_ids: ['CVE-7'], affected_device_count: 1 });
    expect(jre.end_of_support[0]).toContain('EOS Software (2022-07-19)');
    expect(jre.risk_rationale.join(' ')).toMatch(/sem suporte/);
    expect(result.find((i) => i.grouping_key === 'software_replacement|adobe|flash_player')).toBeDefined();
    expect(result.filter((i) => i.category === 'application_update')).toHaveLength(0);
  });

  it('sem inventário de fim de suporte coletado, registra a lacuna e não classifica substituição', () => {
    const [app] = buildInsights(inputs({ softwareInventory: null, vulnerabilities: [chrome('d1', 'CVE-1')] }));
    expect(app!.category).toBe('application_update');
    expect(app!.data_gaps.join(' ')).toMatch(/fim de suporte ainda não coletado/);
  });

  it('configuração catalogada vira GPO; não catalogada vira investigação com sugestão não decisória', () => {
    const result = buildInsights(inputs({ configurations: [
      config('d1', { ConfigurationId: 'scid-100', ConfigurationName: 'Require SMB signing', ConfigurationImpact: 8 }),
      config('d2', { ConfigurationId: 'scid-100', ConfigurationName: 'Require SMB signing', ConfigurationImpact: 8 }),
      config('d1', { ConfigurationId: 'scid-200', ConfigurationName: 'Disable multicast name resolution', RemediationOptions: 'Set policy X' }),
      config('d1', { ConfigurationId: 'scid-300', IsCompliant: true }),
      config('d1', { ConfigurationId: 'scid-301', IsApplicable: false }),
      config('d1', { ConfigurationId: 'scid-302', IsCompliant: null }),
    ] }));
    expect(result).toHaveLength(2);
    const gpo = result.find((i) => i.category === 'gpo_configuration')!;
    expect(gpo).toMatchObject({ insight_id: insightId('gpo_configuration', 'smb-signing'), gpo_name: 'SOC - Servidores - SMB',
      recommendation_ids: ['scid-100'], affected_device_count: 2, cve_ids: [], exploit_available: null });
    expect(gpo.gpo_settings[0]!.policy).toContain('Digitally sign');
    const inv = result.find((i) => i.category === 'investigation')!;
    expect(inv).toMatchObject({ remediation_type: 'undetermined', suggested_catalog_key: 'llmnr', gpo_settings: [], effort: 'desconhecido' });
    expect(inv.remediation_steps.join(' ')).toContain('Orientação do Defender (não validada): Set policy X');
    expect(inv.expected_outcome.finding_reduction).toBeNull();
  });

  it('mitigação não promete eliminação de achados', () => {
    const mitigation = parseCatalog({ configurations: [{ ...catalog.configurations[1], configuration_ids: ['scid-200'] }] });
    const [i] = buildInsights(inputs({ catalog: mitigation, configurations: [config('d1', { ConfigurationId: 'scid-200' })] }));
    expect(i).toMatchObject({ remediation_type: 'mitigation', expected_outcome: { finding_reduction: null } });
  });

  it('regra de software força categoria e driver por nome é marcado como heurística', () => {
    const rules = parseCatalog({ software_rules: [{ vendor: 'Dell', name_pattern: '^idrac', category: 'driver_firmware', note: 'Atualizar pelo Lifecycle Controller.' }] });
    const result = buildInsights(inputs({ catalog: rules, vulnerabilities: [
      vuln('d1', { SoftwareVendor: 'dell', SoftwareName: 'idrac9', SoftwareVersion: '4', CveId: 'CVE-A' }),
      vuln('d1', { SoftwareVendor: 'intel', SoftwareName: 'ethernet_driver', SoftwareVersion: '1', CveId: 'CVE-B' }),
    ] }));
    const idrac = result.find((i) => i.grouping_key === 'driver_firmware|dell|idrac9')!;
    expect(idrac.remediation_steps).toContain('Atualizar pelo Lifecycle Controller.');
    expect(idrac.data_gaps.join(' ')).not.toMatch(/pelo nome/);
    expect(result.find((i) => i.grouping_key === 'driver_firmware|intel|ethernet_driver')!.data_gaps.join(' ')).toMatch(/pelo nome/);
  });

  it('insight_id e hash são estáveis entre execuções e independem de dispositivos', () => {
    const finding = chrome('d1', 'CVE-1');
    const a = buildInsights(inputs({ vulnerabilities: [finding] }))[0]!;
    const b = buildInsights(inputs({ generatedAt: new Date('2026-10-23T00:00:00Z'), vulnerabilities: [finding],
      snapshots: snapshots.map((s) => ({ ...s, snapshotAt: '2026-10-22T23:00:00.000Z' })) }))[0]!;
    const c = buildInsights(inputs({ vulnerabilities: [finding, chrome('d2', 'CVE-2')] }))[0]!;
    expect(a.insight_id).toBe(b.insight_id);
    expect(a.insight_id).toBe(c.insight_id);
    expect(a.insight_id).toMatch(/^ins-[0-9a-f]{32}$/);
    expect(contentHash(a)).toBe(contentHash(b));
    expect(contentHash(a)).not.toBe(contentHash(c));
    expect(a.analysis_id).toBe('soc-insights-20261022T120000Z');
  });

  it('snapshot antigo ou ausente vira lacuna explícita', () => {
    const [i] = buildInsights(inputs({ vulnerabilities: [chrome('d1', 'CVE-1')],
      snapshots: [{ table: 'DeviceTvmSoftwareVulnerabilities', snapshotAt: '2026-10-20T00:00:00.000Z' }, { table: 'DeviceTvmSoftwareInventory', snapshotAt: null }] }));
    expect(i!.data_gaps.join(' ')).toMatch(/mais de 36 h/);
    expect(i!.data_gaps.join(' ')).toMatch(/sem snapshot concluído/);
  });
});

describe('catálogo e configuração', () => {
  it('catálogo do repositório é válido', () => {
    const raw: unknown = JSON.parse(readFileSync(new URL('../config/remediation-catalog.json', import.meta.url), 'utf8'));
    expect(() => parseCatalog(raw)).not.toThrow();
  });

  it('recusa scid vinculado a duas entradas e GPO sem configurações', () => {
    const entry = catalog.configurations[0]!;
    expect(() => parseCatalog({ configurations: [entry, { ...entry, key: 'outra' }] })).toThrow(/scid-100/);
    expect(() => parseCatalog({ configurations: [{ ...entry, gpo_settings: [] }] })).toThrow(/gpo_settings/);
    expect(parseCatalog({})).toEqual(EMPTY_CATALOG);
  });

  it('fonte insights exige snapshots declarados das tabelas certas', () => {
    const snap = (name: string, table: string) => ({ name, type: 'snapshot', table, queryFile: 'q.kql' });
    const base = [snap('v', 'DeviceTvmSoftwareVulnerabilities'), snap('c', 'DeviceTvmSecureConfigurationAssessment')];
    const insights = { name: 'insights.remediation', type: 'insights', vulnerabilitySource: 'v', configurationSource: 'c', softwareInventorySource: null };
    const query = (table: string) => () => table;
    const read = (f: string) => (f === 'q.kql' ? 'DeviceTvmSoftwareVulnerabilities' : '');
    expect(() => parseSources({ sources: [base[0], { ...insights }] }, read)).toThrow(/c não é snapshot/);
    expect(() => parseSources({ sources: [base[0], { ...insights, configurationSource: 'v' }] }, query('x'))).toThrow(/DeviceTvmSecureConfigurationAssessment/);
  });
});
