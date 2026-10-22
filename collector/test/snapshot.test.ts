import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseSources, type SnapshotSourceConfig } from '../src/config.js';
import type { Pool, RunCounters } from '../src/db.js';
import type { GraphClient } from '../src/graph/client.js';
import { completeHuntingResults } from '../src/graph/hunting-results.js';
import type { Logger } from '../src/logger.js';
import { eventKey } from '../src/sources/hunting.js';
import { collectSnapshot, postureKey, snapshotRows } from '../src/sources/snapshot.js';

const at = new Date('2026-10-21T15:00:00Z');
const vulnerability = { DeviceId: 'd1', DeviceName: 'SRV-APP', CveId: 'CVE-2026-0001',
  SoftwareVendor: 'Vendor', SoftwareName: 'App', SoftwareVersion: '1.0', CvssScore: '9.8', IsExploitAvailable: true };
const assessment = { DeviceId: 'd1', DeviceName: 'fisico-db', ConfigurationId: 'scid-1',
  Context: { z: [1, 2], a: { second: true, first: false } }, Timestamp: '2026-10-21T14:30:00.1234567Z',
  IsApplicable: true, IsCompliant: false, ConfigurationName: 'Antivirus setting' };

function source(table: SnapshotSourceConfig['table'] = 'DeviceTvmSoftwareVulnerabilities'): SnapshotSourceConfig {
  return parseSources({ sources: [{ name: `snapshot.${table.toLowerCase()}`, type: 'snapshot', table,
    queryFile: 'test.kql', maxRows: 100 }] }, () => table)[0] as SnapshotSourceConfig;
}

describe('fontes novas e contrato KQL', () => {
  const sources = parseSources(JSON.parse(readFileSync(new URL('../config/sources.json', import.meta.url), 'utf8')),
    (f) => readFileSync(new URL(`../queries/${f}`, import.meta.url), 'utf8'));

  it.each(['deviceprocessevents', 'devicenetworkevents'])('%s usa janelas conservadoras e reconciliação existente', (table) => {
    expect(sources.find((s) => s.name === `hunting.${table}`)).toMatchObject({ enabled: true,
      intervalSeconds: 300, initialLookbackHours: 1, ingestionLagMinutes: 5, overlapMinutes: 15,
      maxWindowMinutes: 15, maxRows: 10000, minWindowMinutes: 1, maxWindowsPerRun: 24 });
    expect(sources.find((s) => s.name === `reconcile.${table}`)).toMatchObject({ enabled: true,
      intervalSeconds: 3600, ingestionLagMinutes: 1440, overlapMinutes: 0, initialLookbackHours: 26 });
  });

  it.each(['devicetvmsoftwarevulnerabilities', 'devicetvmsecureconfigurationassessment'])('%s é snapshot habilitado e sem corte silencioso', (dataset) => {
    const s = sources.find((s) => s.name === `snapshot.${dataset}`) as SnapshotSourceConfig;
    expect(s).toMatchObject({ type: 'snapshot', enabled: true, intervalSeconds: 21600, maxRows: 10000 });
    expect(s.query).toContain('| take 10001');
    expect(s.query).toContain('(DeviceName contains "srv" or DeviceName contains "fisico")');
    expect(s.query).toContain('and DeviceName !contains "note" and DeviceName !contains "micro"');
  });

  it('proíbe dois snapshots da mesma tabela e rejeita tabela errada na consulta', () => {
    const src = { name: 'a', type: 'snapshot', table: 'DeviceTvmSoftwareVulnerabilities', queryFile: 'x.kql' };
    expect(() => parseSources({ sources: [src, { ...src, name: 'b' }] }, () => src.table)).toThrow(/snapshot duplicado/);
    expect(() => parseSources({ sources: [src] }, () => 'DeviceEvents')).toThrow(/declara a tabela/);
  });

  it('processo criado conserva identidade diferente da do iniciador; rede não inventa bytes/direção', () => {
    const process = readFileSync(new URL('../queries/deviceprocessevents.kql', import.meta.url), 'utf8');
    expect(process).toContain('ProcessId, ProcessCommandLine, ProcessCreationTime');
    expect(process).toContain('InitiatingProcessId, InitiatingProcessFileName');
    expect(process).toContain('ProcessUniqueId = column_ifexists');
    const row = { DeviceId: 'd1', ReportId: 10, Timestamp: at.toISOString(), ActionType: 'ProcessCreated',
      ProcessId: 123, InitiatingProcessId: 456 };
    expect(eventKey('DeviceProcessEvents', row)).toBe(eventKey('DeviceProcessEvents', { ...row }));
    expect(eventKey('DeviceProcessEvents', row)).not.toBe(eventKey('DeviceProcessEvents', { ...row, ReportId: 11 }));
    expect(eventKey('DeviceProcessEvents', row)).not.toBe(eventKey('DeviceNetworkEvents', row));
    const network = readFileSync(new URL('../queries/devicenetworkevents.kql', import.meta.url), 'utf8').replace(/\/\/[^\n]*/g, '');
    expect(network).toContain('LocalIP, LocalPort, LocalIPType, RemoteIP, RemotePort, RemoteIPType, RemoteUrl, Protocol');
    expect(network).not.toMatch(/Bytes|Direction/);
  });

  it('inventário expõe risco/valor/internet opcionais sem inferir ausência como false', () => {
    const query = readFileSync(new URL('../queries/deviceinfo.kql', import.meta.url), 'utf8');
    expect(query).toContain('ExposureLevel = column_ifexists("ExposureLevel", "")');
    expect(query).toContain('AssetValue = column_ifexists("AssetValue", "")');
    expect(query).toContain('IsInternetFacing = column_ifexists("IsInternetFacing", bool(null))');
  });
});

describe('identidade e completude de postura', () => {
  it('CVE/software/vendor/version/device/dataset distinguem identidades e metadados não', () => {
    const key = postureKey('DeviceTvmSoftwareVulnerabilities', vulnerability);
    expect(key).toMatch(/^[a-f0-9]{64}$/);
    expect(key).toBe(postureKey('DeviceTvmSoftwareVulnerabilities', { ...vulnerability, CvssScore: '7.5' }));
    for (const field of ['DeviceId', 'CveId', 'SoftwareVendor', 'SoftwareName', 'SoftwareVersion']) {
      expect(key).not.toBe(postureKey('DeviceTvmSoftwareVulnerabilities', { ...vulnerability, [field]: 'different' }));
    }
    expect(() => postureKey('DeviceTvmSoftwareVulnerabilities', { ...vulnerability, SoftwareVersion: '' })).not.toThrow();
    expect(() => postureKey('DeviceTvmSoftwareVulnerabilities', { ...vulnerability, SoftwareVersion: undefined })).toThrow();
  });

  it('ConfigurationId+Context são canônicos para objetos e strings JSON, sem perder precisão original', () => {
    const table = 'DeviceTvmSecureConfigurationAssessment';
    const reordered = { ...assessment, Context: { a: { first: false, second: true }, z: [1, 2] } };
    expect(postureKey(table, assessment)).toBe(postureKey(table, reordered));
    expect(postureKey(table, assessment)).toBe(postureKey(table, { ...assessment, Context: JSON.stringify(reordered.Context) }));
    expect(postureKey(table, assessment)).not.toBe(postureKey(table, { ...assessment, Context: { z: [2, 1] } }));
    const rows = snapshotRows(source(table), [assessment, reordered], at);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.payload).toMatchObject({ Timestamp: assessment.Timestamp, SOCActive: true,
      SOCSnapshotAt: at.toISOString(), SOCState: 'observed', IsCompliant: false });
  });

  it('exclusões prevalecem e não há catálogo para restringir servidores', () => {
    const rows = snapshotRows(source(), [vulnerability, { ...vulnerability, DeviceId: 'd2', DeviceName: 'FISICO-NEW' },
      { ...vulnerability, DeviceName: 'srv-note' }, { ...vulnerability, DeviceName: 'fisico-MICRO' }], at);
    expect(rows).toHaveLength(2);
    expect(snapshotRows(source(), [], at)).toEqual([]);
  });

  it('>=limite é recusado antes de filtro local ou deduplicação', () => {
    const src = source();
    const rows = Array.from({ length: src.maxRows }, () => ({ ...vulnerability, DeviceName: 'srv-note' }));
    expect(() => snapshotRows(src, rows, at)).toThrow(/snapshot incompleto/);
    expect(() => snapshotRows(src, [...rows, vulnerability], at)).toThrow(/snapshot incompleto/);
    expect(() => snapshotRows(src, [{ DeviceName: 'srv01' }], at)).toThrow(/DeviceId/);
  });

  it.each([
    { error: { code: 'PartialError' } }, { errors: ['failure'] }, { stats: { isPartial: true } },
    { statistics: { result: { truncated: true } } }, { stats: { partial_query_failures: 1 } },
    { '@odata.nextLink': 'https://graph.microsoft.com/next' }, { stats: { isComplete: false } },
  ])('recusa envelope HTTP200 com erro/sinal parcial %j', (metadata) => {
    expect(() => completeHuntingResults({ results: [vulnerability], ...metadata }, 100, 'snapshot')).toThrow(/recusado/);
  });

  it('metadados sem falhas e snapshot vazio podem completar; envelope ausente não', () => {
    expect(completeHuntingResults({ schema: [], results: [], stats: { isPartial: false, errors: [], partial_query_failures: 0 } }, 100, 's')).toEqual([]);
    expect(() => completeHuntingResults({ stats: {} }, 100, 's')).toThrow(/results/);
  });

  it('erro da API e limite não iniciam transação nem acessam banco', async () => {
    const deps = { pool: {} as Pool, log: {} as Logger,
      graph: { request: async () => { throw new Error('Graph 403 tabela/licença indisponível'); } } as unknown as GraphClient };
    const counters = (): RunCounters => ({ fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 });
    await expect(collectSnapshot(source(), deps, counters())).rejects.toThrow(/403/);
    deps.graph = { request: async () => ({ results: Array.from({ length: 100 }, () => vulnerability) }) } as unknown as GraphClient;
    await expect(collectSnapshot(source(), deps, counters())).rejects.toThrow(/snapshot incompleto/);
    deps.graph = { request: async () => ({ results: [], stats: { isPartial: true } }) } as unknown as GraphClient;
    await expect(collectSnapshot(source(), deps, counters())).rejects.toThrow(/recusado/);
  });
});
