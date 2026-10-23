import { describe, expect, it } from 'vitest';
import { parseSources } from '../src/config.js';
import { addPage, type SecurityUpdate } from '../src/sources/msrc.js';
import { buildServers } from '../src/sources/winupdates.js';
import { evaluateServer, isInScope, productName, type CatalogEntry, type ServerInput } from '../src/winupdates/engine.js';

const kbArticle = (kb: string, build: string, extra: Record<string, unknown> = {}) => ({ articleName: kb, articleUrl: `https://support.microsoft.com/help/${kb}`,
  downloadName: 'Security Update', supercedence: '5000000', rebootRequired: 'Yes', fixedBuildNumber: build, ...extra });

describe('catálogo MSRC', () => {
  it('só Security Update com build 10.0.x.y; data é a primeira publicação; Server Core une ao produto', () => {
    const catalog = new Map<string, SecurityUpdate>();
    addPage(catalog, [
      { product: 'Windows Server 2022', releaseDate: '2026-10-13T07:00:00-07:00', kbArticles: [kbArticle('5126655', '10.0.20348.5761')] },
      { product: 'Windows Server 2022 (Server Core installation)', releaseDate: '2026-09-08T07:00:00-07:00', kbArticles: [kbArticle('5126655', '10.0.20348.5761')] },
      { product: 'Windows Server 2022', releaseDate: '2026-10-13T07:00:00-07:00', kbArticles: [
        kbArticle('5126700', '10.0.20348.9999', { downloadName: 'Security Hotpatch Update' }),
        kbArticle('5126701', '', { downloadName: 'Security Update' }),
        kbArticle('5126702', '10.0.20348.5800', { downloadName: 'Monthly Rollup' }),
      ] },
      { product: 'Windows Server 2016', releaseDate: '2026-10-13T07:00:00-07:00', kbArticles: [kbArticle('5126868', '10.0.14393.9612', { rebootRequired: 'No' })] },
    ]);
    expect([...catalog.values()]).toEqual([
      { kb: 'KB5126655', product: 'Windows Server 2022', fixedBuild: '10.0.20348.5761', buildMajor: 20348, ubr: 5761,
        releaseDate: '2026-09-08T14:00:00.000Z', supersedes: 'KB5000000', rebootRequired: true, url: 'https://support.microsoft.com/help/5126655' },
      expect.objectContaining({ kb: 'KB5126868', buildMajor: 14393, rebootRequired: false }),
    ]);
  });

  it('mesmo KB com builds diferentes é recusado', () => {
    const catalog = new Map<string, SecurityUpdate>();
    expect(() => addPage(catalog, [
      { product: 'Windows Server 2022', releaseDate: '2026-10-13T07:00:00Z', kbArticles: [kbArticle('1', '10.0.20348.1')] },
      { product: 'Windows Server 2022', releaseDate: '2026-10-13T07:00:00Z', kbArticles: [kbArticle('1', '10.0.20348.2')] },
    ])).toThrow(/builds diferentes/);
  });
});

const now = new Date('2026-10-23T12:00:00Z');
const opts = { generatedAt: now, catalogUpdatedAt: '2026-10-23T06:00:00.000Z', deviceStaleHours: 24, snapshotStaleHours: 36, catalogStaleHours: 48 };
const entry = (kb: string, major: number, ubr: number, date: string, reboot: boolean | null = true): CatalogEntry =>
  ({ kb, buildMajor: major, ubr, fixedBuild: `10.0.${major}.${ubr}`, releaseDate: date, rebootRequired: reboot, url: null });
const catalog = [
  entry('KB5099540', 20348, 5386, '2026-08-12T14:00:00.000Z'), entry('KB5122882', 20348, 5622, '2026-09-08T14:00:00.000Z'),
  entry('KB5126655', 20348, 5761, '2026-10-13T14:00:00.000Z'),
  entry('KB5123099', 14393, 9512, '2026-09-08T14:00:00.000Z'), entry('KB5126868', 14393, 9612, '2026-10-13T14:00:00.000Z', null),
];
const server = (osVersion: string | null, extra: Partial<ServerInput> = {}): ServerInput => ({ deviceId: 'd1', deviceName: 'SRV03.usinacerradao.com.br',
  osPlatform: 'WindowsServer2022', lastSeen: '2026-10-23T11:00:00Z', osVersion, osSnapshotAt: '2026-10-23T10:00:00.000Z', defenderKbs: ['KB5126655'], ...extra });

describe('estado de atualização por servidor', () => {
  it('compara com a atualização da própria build e trata a pendente como cumulativa', () => {
    const d = evaluateServer(server('10.0.20348.5386'), catalog, opts);
    expect(d).toMatchObject({ status: 'pendente', status_label: 'Pendente', host: { name: 'srv03.usinacerradao.com.br' },
      windows: { product: 'Windows Server 2022', build: '20348.5386', build_major: 20348, ubr: 5386 },
      update: { latest_kb: 'KB5126655', latest_release_date: '2026-10-13T14:00:00.000Z', installed_kb: 'KB5099540', installed_match: 'exata',
        pending: true, pending_kb: 'KB5126655', pending_superseded_count: 1, reboot_required: true,
        reboot_required_label: 'Sim (segundo a Microsoft)', days_since_latest_release: 9 } });
    expect(d.status_reason).toMatch(/2 atualização\(ões\) de segurança/);
  });

  it('Windows Server 2016 não é comparado com KB do 2022', () => {
    const d = evaluateServer(server('10.0.14393.9612', { osPlatform: 'WindowsServer2016' }), catalog, opts);
    expect(d).toMatchObject({ status: 'em_dia', update: { latest_kb: 'KB5126868', pending: false, pending_kb: null,
      pending_superseded_count: 0, reboot_required: null, reboot_required_label: 'Sem atualização pendente', days_since_latest_release: null } });
  });

  it('build entre duas atualizações é equivalente à anterior; acima da última é em dia (preview não conta)', () => {
    expect(evaluateServer(server('10.0.20348.5700'), catalog, opts).update).toMatchObject({ installed_kb: 'KB5122882', installed_match: 'equivalente', pending: true });
    const preview = evaluateServer(server('10.0.20348.5800'), catalog, opts);
    expect(preview).toMatchObject({ status: 'em_dia', update: { installed_kb: 'KB5126655', installed_match: 'acima_da_seguranca', pending: false } });
    expect(preview.status_reason).toMatch(/preview/);
  });

  it('build anterior a todo o catálogo: pendente, sem KB instalado conhecido', () => {
    expect(evaluateServer(server('10.0.20348.169'), catalog, opts)).toMatchObject({ status: 'pendente',
      update: { installed_kb: null, installed_match: null, pending_superseded_count: 2 } });
  });

  it('sem build ou sem catálogo da build: não determinado, nunca em dia', () => {
    expect(evaluateServer(server(null), catalog, opts)).toMatchObject({ status: 'nao_determinado', update: { pending: null, latest_kb: null } });
    const d = evaluateServer(server('10.0.17763.9376', { osPlatform: 'WindowsServer2019' }), catalog, opts);
    expect(d).toMatchObject({ status: 'nao_determinado', update: { pending: null, reboot_required_label: 'Não determinado' } });
    expect(d.status_reason).toMatch(/build 17763/);
  });

  it('reinicialização desconhecida pela Microsoft não vira não', () => {
    const d = evaluateServer(server('10.0.14393.9512', { osPlatform: 'WindowsServer2016' }), catalog, opts);
    expect(d.update).toMatchObject({ pending_kb: 'KB5126868', reboot_required: null, reboot_required_label: 'Não informado pela Microsoft' });
  });

  it('dados antigos viram coleta desatualizada com o motivo', () => {
    const d = evaluateServer(server('10.0.20348.5761', { lastSeen: '2026-10-20T00:00:00Z' }), catalog,
      { ...opts, catalogUpdatedAt: '2026-10-19T00:00:00.000Z' });
    expect(d.status).toBe('coleta_desatualizada');
    expect(d.status_reason).toMatch(/sensor sem contato há 84 h.*catálogo Microsoft atualizado há 108 h/);
    expect(evaluateServer(server('10.0.20348.5761'), catalog, { ...opts, catalogUpdatedAt: null }).status).toBe('coleta_desatualizada');
  });

  it('escopo: nome começa com SRV (sem diferenciar caixa) e Windows Server', () => {
    expect(isInScope('SRV03.dominio', 'WindowsServer2022', 'srv')).toBe(true);
    expect(isInScope('srv44.dominio', 'Windows11', 'srv')).toBe(false);
    expect(isInScope('fisico-srv01', 'WindowsServer2022', 'srv')).toBe(false);
    expect(productName('WindowsServer2016')).toBe('Windows Server 2016');
  });

  it('usa a linha do SO correspondente ao DeviceInfo e ignora fora do escopo', () => {
    const devices = [
      { DeviceId: 'd1', DeviceName: 'SRV03', OSPlatform: 'WindowsServer2022', Timestamp: '2026-10-23T11:00:00Z', SOCObserved: true },
      { DeviceId: 'd2', DeviceName: 'srv44', OSPlatform: 'Windows11', SOCObserved: true },
      { DeviceId: 'd3', DeviceName: 'srv99', OSPlatform: 'WindowsServer2016', SOCObserved: false },
    ];
    const rows = [
      { device_id: 'd1', payload: { SoftwareName: 'windows_server_2019', SoftwareVersion: '10.0.17763.1', SOCSnapshotAt: 'x' } },
      { device_id: 'd1', payload: { SoftwareName: 'windows_server_2022', SoftwareVersion: '10.0.20348.5761', SOCSnapshotAt: '2026-10-23T10:00:00.000Z' } },
    ];
    expect(buildServers(devices, rows, new Map([['d1', ['5126655']]]), 'srv')).toEqual([{ deviceId: 'd1', deviceName: 'SRV03',
      osPlatform: 'WindowsServer2022', lastSeen: '2026-10-23T11:00:00Z', osVersion: '10.0.20348.5761', osSnapshotAt: '2026-10-23T10:00:00.000Z', defenderKbs: ['KB5126655'] }]);
  });

  it('winupdates exige fonte msrc declarada', () => {
    expect(() => parseSources({ sources: [{ name: 'w', type: 'winupdates', msrcSource: 'nao-existe' }] }, () => '')).toThrow(/msrc/);
    expect(parseSources({ sources: [{ name: 'm', type: 'msrc', products: ['Windows Server 2022'] },
      { name: 'w', type: 'winupdates', msrcSource: 'm' }] }, () => '')).toHaveLength(2);
  });
});
