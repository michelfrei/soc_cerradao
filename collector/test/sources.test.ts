import { describe, expect, it } from 'vitest';
import { parseSources } from '../src/config.js';
import { eventKey, nextWindow, renderQuery, toEventRow } from '../src/sources/hunting.js';
import { latestById, toObjectRow } from '../src/sources/objects.js';

const settings = { initialLookbackHours: 24, ingestionLagMinutes: 5, maxWindowMinutes: 60, overlapMinutes: 15 };

describe('nextWindow', () => {
  const now = new Date('2026-10-20T12:00:00Z');

  it('começa pelo lookback inicial quando não há checkpoint', () => {
    const w = nextWindow(null, now, settings)!;
    expect(w.start.toISOString()).toBe('2026-10-19T12:00:00.000Z');
    expect(w.end.toISOString()).toBe('2026-10-19T13:00:00.000Z');
    expect(w.queryStart.toISOString()).toBe('2026-10-19T11:45:00.000Z');
  });

  it('respeita o atraso de ingestão', () => {
    const w = nextWindow(new Date('2026-10-20T11:30:00Z'), now, settings)!;
    expect(w.end.toISOString()).toBe('2026-10-20T11:55:00.000Z');
  });

  it('não gera janela quando já alcançou o presente', () => {
    expect(nextWindow(new Date('2026-10-20T11:54:30Z'), now, settings)).toBeNull();
  });
});

describe('renderQuery', () => {
  it('substitui início e fim em UTC', () => {
    const q = renderQuery('T | where Timestamp >= datetime({{start}}) and Timestamp < datetime({{end}})',
      new Date('2026-10-20T10:00:00Z'), new Date('2026-10-20T11:00:00Z'));
    expect(q).toBe('T | where Timestamp >= datetime(2026-10-20T10:00:00.000Z) and Timestamp < datetime(2026-10-20T11:00:00.000Z)');
  });
});

describe('eventos de hunting', () => {
  const row = {
    Timestamp: '2026-10-20T10:15:30.1234567Z',
    DeviceId: 'abc',
    DeviceName: 'srv01',
    ReportId: 42,
    ActionType: 'LogonSuccess',
    AccountName: 'admin',
  };

  it('gera a mesma chave para a mesma linha', () => {
    expect(eventKey('DeviceLogonEvents', row)).toBe(eventKey('DeviceLogonEvents', { ...row }));
  });

  it('diferencia linhas com ação diferente', () => {
    expect(eventKey('DeviceLogonEvents', row)).not.toBe(eventKey('DeviceLogonEvents', { ...row, ActionType: 'LogonFailed' }));
  });

  it('usa o conteúdo quando faltam campos de identificação', () => {
    const k = eventKey('DeviceEvents', { Timestamp: row.Timestamp, Foo: 1 });
    expect(k).toMatch(/^[0-9a-f]{64}$/);
  });

  it('converte para a linha do banco', () => {
    const r = toEventRow('DeviceLogonEvents', row);
    expect(r).toMatchObject({ ts: row.Timestamp, device_id: 'abc', device_name: 'srv01', action_type: 'LogonSuccess' });
  });

  it('rejeita linha sem Timestamp', () => {
    expect(() => toEventRow('DeviceLogonEvents', { DeviceId: 'abc' })).toThrow();
  });
});

describe('incidentes e alertas', () => {
  const incident = {
    id: '123',
    displayName: 'Atividade suspeita',
    status: 'active',
    severity: 'high',
    createdDateTime: '2026-10-20T09:00:00Z',
    lastUpdateDateTime: '2026-10-20T10:00:00.1234567Z',
    incidentWebUrl: 'https://security.microsoft.com/incidents/123',
    comments: [],
  };

  it('mapeia o incidente e preserva o payload', () => {
    const r = toObjectRow('incidents', incident);
    expect(r).toMatchObject({ id: '123', title: 'Atividade suspeita', incident_id: '123', last_update_at: '2026-10-20T10:00:00.123Z' });
    expect(r.payload).toBe(incident);
  });

  it('mapeia o alerta', () => {
    const r = toObjectRow('alerts', { id: 'da1', title: 'X', incidentId: '123', serviceSource: 'microsoftDefenderForEndpoint', lastUpdateDateTime: '2026-10-20T10:00:00Z' });
    expect(r).toMatchObject({ id: 'da1', incident_id: '123', service_source: 'microsoftDefenderForEndpoint' });
  });

  it('rejeita objeto sem lastUpdateDateTime', () => {
    expect(() => toObjectRow('alerts', { id: 'x' })).toThrow();
  });

  it('mantém só a versão mais recente de cada id na página', () => {
    const a = toObjectRow('incidents', incident);
    const b = toObjectRow('incidents', { ...incident, status: 'resolved', lastUpdateDateTime: '2026-10-20T11:00:00Z' });
    const out = latestById([b, a]);
    expect(out).toHaveLength(1);
    expect(out[0]!.status).toBe('resolved');
  });
});

describe('parseSources', () => {
  const query = 'DeviceEvents | where Timestamp >= datetime({{start}}) and Timestamp < datetime({{end}})';

  it('carrega o arquivo de fontes do repositório', async () => {
    const { readFileSync } = await import('node:fs');
    const raw: unknown = JSON.parse(readFileSync(new URL('../config/sources.json', import.meta.url), 'utf8'));
    const sources = parseSources(raw, (f) => readFileSync(new URL(`../queries/${f}`, import.meta.url), 'utf8'));
    expect(sources.map((s) => s.name)).toEqual([
      'hunting.deviceprocessevents', 'hunting.devicenetworkevents',
      'reconcile.deviceprocessevents', 'reconcile.devicenetworkevents',
      'snapshot.devicetvmsoftwarevulnerabilities', 'snapshot.devicetvmsecureconfigurationassessment',
      'snapshot.devicetvmsoftwareinventory', 'msrc.windows-server', 'windows.updates', 'insights.remediation',
      'inventory.deviceinfo', 'incidents', 'alerts', 'hunting.devicelogonevents', 'hunting.asr', 'reconcile.devicelogonevents', 'reconcile.asr',
      'fwflows.fortigate',
    ]);
    // Agregados da firewall só ligam depois do usuário de leitura no Elasticsearch.
    expect(sources.find((s) => s.name === 'fwflows.fortigate')?.enabled).toBe(false);
  });

  it('exige os marcadores de período na consulta', () => {
    const raw = { sources: [{ name: 'h', type: 'hunting', table: 'DeviceEvents', queryFile: 'x.kql' }] };
    expect(() => parseSources(raw, () => 'DeviceEvents | take 10')).toThrow(/\{\{start\}\}/);
    expect(parseSources(raw, () => query)).toHaveLength(1);
  });

  it('rejeita consulta que lê tabela diferente da declarada', () => {
    const raw = { sources: [{ name: 'h', type: 'hunting', table: 'DeviceLogonEvents', queryFile: 'x.kql' }] };
    const asr = '// comentário\nDeviceEvents\n| where Timestamp >= datetime({{start}}) and Timestamp < datetime({{end}})';
    expect(() => parseSources(raw, () => asr)).toThrow(/DeviceEvents/);
    expect(parseSources(raw, () => asr.replace('DeviceEvents', 'DeviceLogonEvents'))).toHaveLength(1);
  });

  it('rejeita lookback acima da retenção do Advanced Hunting', () => {
    const raw = { sources: [{ name: 'h', type: 'hunting', table: 'DeviceEvents', queryFile: 'x.kql', initialLookbackHours: 1000 }] };
    expect(() => parseSources(raw, () => query)).toThrow();
  });

  it('rejeita nomes duplicados', () => {
    const raw = { sources: [{ name: 'a', type: 'alerts' }, { name: 'a', type: 'incidents' }] };
    expect(() => parseSources(raw, () => query)).toThrow(/duplicada/);
  });
});
