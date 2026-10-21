import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseAssets, parseSources, type InventorySourceConfig } from '../src/config.js';
import type { GraphClient } from '../src/graph/client.js';
import type { Pool, RunCounters } from '../src/db.js';
import type { Logger } from '../src/logger.js';
import { isServerInScope } from '../src/scope.js';
import { collectInventory, mergeInventory } from '../src/sources/inventory.js';

const snapshot = new Date('2026-10-21T15:00:00Z');
const row = { DeviceId: 'device-1', DeviceName: 'SRV01', Timestamp: '2026-10-21T14:30:00.1234567Z',
  OSPlatform: 'WindowsServer2022', DeviceType: 'Server', MachineGroup: 'Servers',
  OnboardingStatus: 'Onboarded', SensorHealthState: 'Active' };

describe('escopo de servidores', () => {
  it.each([
    ['SRV-APP', true], ['HOST-FISICO', true], ['notebook', false], ['micro01', false],
    ['srv-note', false], ['fisico-micro', false], ['sRv-NoTe', false], ['FISICO-MICRO', false], ['dc01', false],
  ])('%s: %s', (name, expected) => expect(isServerInScope(name)).toBe(expected));

  it.each(['devicelogonevents.kql', 'asr.kql', 'deviceinfo.kql'])('KQL %s aplica inclusão e exclusões', (file) => {
    const text = readFileSync(new URL(`../queries/${file}`, import.meta.url), 'utf8');
    expect(text).toContain('(DeviceName contains "srv" or DeviceName contains "fisico")');
    expect(text).toContain('and DeviceName !contains "note" and DeviceName !contains "micro"');
  });
});

describe('inventário persistente', () => {
  it('promove esperado por nome sem trocar chave, preserva precisão e evita duplicação', () => {
    const assets = parseAssets({ assets: [{ name: 'srv01', owner: 'Infra', environment: 'prod', criticality: 'high' }] });
    const expected = mergeInventory([], [], assets, snapshot);
    expect(expected).toHaveLength(1);
    expect(expected[0]!.key).toBe('expected:srv01');
    expect(expected[0]!.payload).toMatchObject({ SOCExpected: true, SOCObserved: false, Timestamp: null });
    const recognized = mergeInventory(expected, [row], assets, snapshot);
    expect(recognized).toHaveLength(1);
    expect(recognized[0]).toMatchObject({ key: 'expected:srv01', payload: {
      DeviceId: 'device-1', SOCExpected: true, SOCObserved: true, SOCOwner: 'Infra', Timestamp: row.Timestamp,
    } });
    const renamed = mergeInventory(recognized, [{ ...row, DeviceName: 'srv02' }], [{ id: 'device-1', name: 'srv02' }], snapshot);
    expect(renamed).toHaveLength(1);
    expect(renamed[0]!.key).toBe('expected:srv01');
    const stillExpected = mergeInventory(renamed, [{ ...row, DeviceName: 'srv02' }], assets, snapshot);
    expect(stillExpected).toHaveLength(1);
    expect(stillExpected[0]!.payload.SOCExpected).toBe(true);
  });

  it('mantém silencioso e não inventa observação nem cobertura sem lista esperada', () => {
    const known = mergeInventory([], [row], [], snapshot);
    expect(known[0]!.payload).toMatchObject({ SOCExpected: false, SOCObserved: true });
    const silent = mergeInventory(known, [], [], new Date('2026-10-22T15:00:00Z'));
    expect(silent).toHaveLength(1);
    expect(silent[0]!.payload).toMatchObject({ SOCExpected: false, SOCObserved: false, Timestamp: row.Timestamp });
    expect(mergeInventory([], [], [], snapshot)).toEqual([]);
  });

  it('não duplica observado ao adicionar posteriormente uma expectativa', () => {
    const known = mergeInventory([], [row], [], snapshot);
    const expected = mergeInventory(known, [row], [{ name: 'srv01', owner: 'SOC' }], snapshot);
    expect(expected).toHaveLength(1);
    expect(expected[0]).toMatchObject({ key: 'device-1', payload: { SOCExpected: true, SOCOwner: 'SOC' } });
    const renamed = mergeInventory(expected, [{ ...row, DeviceName: 'srv02' }], [{ name: 'srv01', owner: 'SOC' }], snapshot);
    const nextCycle = mergeInventory(renamed, [{ ...row, DeviceName: 'srv02' }], [{ name: 'srv01', owner: 'SOC' }], snapshot);
    expect(nextCycle).toHaveLength(1);
    expect(nextCycle[0]).toMatchObject({ key: 'device-1', payload: {
      DeviceName: 'srv02', SOCExpected: true, SOCCatalogName: 'srv01',
    } });
  });

  it('nomes iguais com IDs diferentes não mesclam ativos e exigem id na expectativa', () => {
    const known = mergeInventory([], [row, { ...row, DeviceId: 'device-2' }], [], snapshot);
    expect(known).toHaveLength(2);
    expect(() => mergeInventory(known, [], [{ name: 'srv01' }], snapshot)).toThrow(/ambíguo/);
    expect(() => mergeInventory([], [row, { ...row, DeviceId: 'device-2' }], [{ name: 'srv01' }], snapshot)).toThrow(/ambíguo/);
    const expected = mergeInventory(known, [], [{ id: 'device-1', name: 'srv01' }], snapshot);
    expect(expected.filter((r) => r.payload.SOCExpected)).toHaveLength(1);
  });

  it('exclusão prevalece também em observações recebidas e ativos inválidos são explícitos', () => {
    expect(mergeInventory([], [{ ...row, DeviceName: 'srv-note' }], [], snapshot)).toEqual([]);
    expect(() => mergeInventory([], [], [{ name: 'fisico-micro' }], snapshot)).toThrow(/fora do escopo/);
    expect(() => parseAssets({ assets: [{}] })).toThrow();
    expect(() => parseAssets({ assets: [{ id: 'device-1' }] })).toThrow();
    expect(() => parseAssets({ assets: [{ name: 'srv01' }, { name: 'SRV01' }] })).toThrow(/duplicado/);
  });

  it('snapshot no limite é recusado antes de qualquer escrita no banco', async () => {
    const src = parseSources({ sources: [{ name: 'inventory.deviceinfo', type: 'inventory', maxRows: 100 }] },
      () => 'DeviceInfo | summarize arg_max(Timestamp, *) by DeviceId')[0] as InventorySourceConfig;
    const counters: RunCounters = { fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 };
    const graph = { request: async () => ({ results: Array.from({ length: 100 }, () => row) }) } as unknown as GraphClient;
    await expect(collectInventory(src, { pool: {} as Pool, graph, log: {} as Logger, assets: [] }, counters))
      .rejects.toThrow(/snapshot recusado/);
    expect(counters.changed).toBe(0);
  });
});
