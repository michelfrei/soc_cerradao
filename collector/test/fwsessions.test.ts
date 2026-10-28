import { describe, expect, it } from 'vitest';
import { parseSources } from '../src/config.js';
import type { Client } from '../src/db.js';
import { fetchSessions, sessionQuery, storeSessions, toSession, type SessionBucket } from '../src/sources/fwsessions.js';

const now = new Date('2026-10-27T15:00:00Z');
const opts = { adminStaleHours: 24, vpnStaleHours: 72 };
const ms = (iso: string) => Date.parse(iso);

function bucket(id: string, latest: Record<string, unknown>, openedAt?: string, opening?: Record<string, unknown>): SessionBucket {
  return {
    key: { id },
    latest: { hits: { hits: [{ _source: latest }] } },
    first: { value: ms(openedAt ?? String(latest['@timestamp'])) },
    opened: openedAt ? { doc_count: 1, at: { value: ms(openedAt) }, event: { hits: { hits: [{ _source: opening ?? latest }] } } } : { doc_count: 0 },
  };
}

const vpnOpen = { '@timestamp': '2026-10-27T13:00:00.000Z', soc: { fw: { session: { state: 'open' }, access: { kind: 'vpn', channel: 'ssl', user: 'maria' } } },
  source: { ip: '198.51.100.7' }, fortinet: { firewall: { tunnelip: '10.212.134.200' } } };

describe('estado da sessão', () => {
  it('túnel aberto: duração até agora, usuário e IP do túnel', () => {
    expect(toSession(bucket('vpn|FG1|77', vpnOpen, '2026-10-27T13:00:00.000Z'), now, opts)).toMatchObject({
      session_id: 'vpn|FG1|77', kind: 'vpn', channel: 'ssl', state: 'open', state_label: 'Aberta', user: 'maria',
      source: { ip: '198.51.100.7' }, tunnel_ip: '10.212.134.200', started_at: '2026-10-27T13:00:00.000Z', duration_seconds: 7200 });
  });

  it('sem evento de abertura, o início vem da duração do tunnel-stats', () => {
    const stats = { '@timestamp': '2026-10-27T14:01:59.000Z', event: { duration: 21_028 * 1e9 },
      soc: { fw: { session: { state: 'alive' }, access: { kind: 'vpn', channel: 'ssl', user: 'ana' } } } };
    const d = toSession(bucket('vpn|FG1|5', stats), now, opts)!;
    expect(d).toMatchObject({ state: 'open', started_at: '2026-10-27T08:11:31.000Z' });
    expect(d.duration_seconds).toBe(Math.round((now.getTime() - Date.parse('2026-10-27T08:11:31.000Z')) / 1000));
  });

  it('IPsec entre sites: IP remoto no campo de usuário não vira usuário', () => {
    const ipsec = { '@timestamp': '2026-10-27T14:00:00.000Z', soc: { fw: { session: { state: 'alive' }, access: { kind: 'vpn', channel: 'ipsec', user: '35.208.203.103' } } },
      fortinet: { firewall: { vpntunnel: 'VPN_CROMAI_PRI' } } };
    const d = toSession(bucket('vpn|FG1|9', ipsec), now, opts)!;
    expect(d.user).toBeUndefined();
    expect(d).toMatchObject({ channel: 'ipsec', vpn_tunnel: 'VPN_CROMAI_PRI' });
  });

  it('SD-WAN: último health-check define ativo/caído e guarda a última queda', () => {
    const up = { '@timestamp': '2026-10-27T14:30:00.000Z', soc: { fw: { session: { state: 'up' }, sdwan: { interface: 'VLAN-1001', healthcheck: 'PING' } } } };
    const b = { ...bucket('sdwan|FG1|VLAN-1001|PING', up), downs: { doc_count: 1, at: { value: ms('2026-10-27T14:10:00.000Z') } } };
    expect(toSession(b, now, opts)).toMatchObject({ kind: 'sdwan', state: 'up', state_label: 'Ativo', interface: 'VLAN-1001', healthcheck: 'PING',
      last_down: '2026-10-27T14:10:00.000Z', duration_seconds: 1800 });
    const down = { ...up, '@timestamp': '2026-10-20T14:30:00.000Z', soc: { fw: { session: { state: 'down' }, sdwan: up.soc.fw.sdwan } } };
    // Sem prazo de validade: caído há dias continua caído.
    expect(toSession(bucket('sdwan|FG1|VLAN-1001|PING', down), now, opts)?.state).toBe('down');
  });

  it('fechamento usa o último evento; dados da abertura preenchem o que falta', () => {
    const down = { '@timestamp': '2026-10-27T14:00:00.000Z', soc: { fw: { session: { state: 'close' }, access: { kind: 'vpn' } } },
      source: { bytes: 10 }, destination: { bytes: 20 } };
    const d = toSession(bucket('vpn|FG1|77', down, '2026-10-27T13:00:00.000Z', vpnOpen), now, opts)!;
    expect(d).toMatchObject({ state: 'closed', ended_at: '2026-10-27T14:00:00.000Z', duration_seconds: 3600, user: 'maria',
      tunnel_ip: '10.212.134.200', bytes_sent: 10, bytes_received: 20 });
  });

  it('sem fechamento além do limite vira stale (admin 24 h, VPN 72 h)', () => {
    const admin = { '@timestamp': '2026-10-26T10:00:00.000Z', soc: { fw: { session: { state: 'open' }, access: { kind: 'admin', user: 'admin' } } } };
    expect(toSession(bucket('admin|FG1|1', admin, '2026-10-26T10:00:00.000Z'), now, opts)?.state).toBe('stale');
    const vpn = { ...vpnOpen, '@timestamp': '2026-10-26T10:00:00.000Z' };
    expect(toSession(bucket('vpn|FG1|2', vpn, '2026-10-26T10:00:00.000Z'), now, opts)?.state).toBe('open');
  });

  it('consulta filtra a janela e só eventos com chave de sessão', () => {
    const q = JSON.stringify(sessionQuery(new Date('2026-10-20T15:00:00Z'), now));
    expect(q).toContain('"gte":"2026-10-20T15:00:00.000Z"');
    expect(q).toContain('{"exists":{"field":"soc.fw.session.id"}}');
  });
});

describe('gravação', () => {
  function fakeClient(rows: Record<string, unknown>[]) {
    const calls: { sql: string; params: unknown[] }[] = [];
    const client = {
      query: async (sql: string, params: unknown[] = []) => {
        calls.push({ sql, params });
        return { rows: sql.startsWith('SELECT session_id') ? rows : [], rowCount: 0 };
      },
    } as unknown as Client;
    return { client, calls };
  }
  const src = parseSources({ sources: [{ name: 'fw.sessions', type: 'fwsessions' }] }, () => '')[0] as Parameters<typeof storeSessions>[1];

  it('sessão aberta que saiu da janela vira unknown; sem mudança não republica', async () => {
    const current = toSession(bucket('vpn|FG1|77', vpnOpen, '2026-10-27T13:00:00.000Z'), now, opts)!;
    const { hashPayload } = await import('../src/util.js');
    const { client, calls } = fakeClient([
      { session_id: 'vpn|FG1|77', content_hash: hashPayload(current), state: 'open', payload: current },
      { session_id: 'vpn|FG1|9', content_hash: 'x', state: 'open', payload: { session_id: 'vpn|FG1|9', kind: 'vpn', state: 'open', last_seen: '2026-10-19T00:00:00.000Z' } },
    ]);
    const r = await storeSessions(client, src, [current], now);
    expect(r).toEqual({ published: 1, expired: 1 });
    const published = JSON.parse(String(calls.find((c) => c.sql.includes('soc.publication'))!.params[0])) as { payload: Record<string, unknown> }[];
    expect(published.map((p) => [p.payload.session_id, p.payload.state])).toEqual([['vpn|FG1|9', 'unknown']]);
  });

  it('composite paginado; truncado no limite', async () => {
    const page = (n: number, after?: Record<string, unknown>) => ({ aggregations: { sessions: {
      buckets: Array.from({ length: n }, (_, i) => bucket(`s${i}`, vpnOpen)), ...(after ? { after_key: after } : {}) } } });
    let call = 0;
    const es = { search: async () => (++call === 1 ? page(2, { id: 's1' }) : page(1)) };
    expect((await fetchSessions(es, 'fw-logs-fortigate', now, now, 100)).buckets).toHaveLength(3);
    call = 0;
    expect((await fetchSessions(es, 'fw-logs-fortigate', now, now, 2)).truncated).toBe(true);
  });
});
