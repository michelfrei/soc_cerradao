import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connect } from 'node:tls';
import { createFramer, createRelay, loadConfig, toLine } from '../relay.mjs';

const frame = (chunks, opts) => {
  const out = [];
  const feed = createFramer((m) => out.push(m.toString()), opts);
  for (const c of chunks) feed(Buffer.from(c));
  return out;
};

test('contagem de octetos, inclusive com mensagem partida entre leituras', () => {
  const a = '<189>date=2026-10-27 type="traffic"';
  const b = '<189>date=2026-10-27 action="deny"';
  const stream = `${a.length} ${a}${b.length} ${b}`;
  assert.deepEqual(frame([stream]), [a, b]);
  assert.deepEqual(frame([stream.slice(0, 3), stream.slice(3, 40), stream.slice(40)]), [a, b]);
});

test('delimitado por LF/NUL e misturado com contagem', () => {
  assert.deepEqual(frame(['<189>um\n<189>dois\0', '11 <189>tres x\n']), ['<189>um', '<189>dois', '<189>tres x']);
  // Mensagem que começa com dígito sem contagem (formato sem PRI) não é confundida.
  assert.deepEqual(frame(['2026-10-27 linha\n']), ['2026-10-27 linha']);
});

test('mensagem acima do limite é descartada sem travar o fluxo', () => {
  const sizes = [];
  const big = 'x'.repeat(50);
  assert.deepEqual(frame([`50 ${big}5 <1>ok`], { maxBytes: 20, onOversize: (n) => sizes.push(n) }), ['<1>ok']);
  assert.deepEqual(frame([`${big}`, `${big}\n<1>ok\n`], { maxBytes: 20, onOversize: (n) => sizes.push(n) }), ['<1>ok']);
  assert.equal(sizes.length, 2);
});

test('linha entregue ao Logstash sem quebras internas', () => {
  assert.equal(toLine(Buffer.from(' a\r\nb\n ')), 'a b\n');
});

test('configuração exige IPs válidos na lista de origem', () => {
  assert.throws(() => loadConfig({ FW_SYSLOG_ALLOWED: '172.16.0.10,abc' }), /IP inválido/);
  assert.deepEqual(loadConfig({ FW_SYSLOG_ALLOWED: ' 127.0.0.1 ' }).allowed, ['127.0.0.1']);
});

const dir = mkdtempSync(join(tmpdir(), 'relay-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'k.pem', '-out', 'c.pem', '-days', '1', '-subj', '/CN=syslog',
  '-addext', 'subjectAltName=IP:127.0.0.1'], { cwd: dir, stdio: 'pipe' });
const tls = { cert: readFileSync(join(dir, 'c.pem')), key: readFileSync(join(dir, 'k.pem')) };

async function withRelay(allowed, fn) {
  const received = [];
  const sink = createServer((s) => s.on('data', (d) => received.push(d.toString())));
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const logs = [];
  const relay = createRelay({ allowed, downstreamHost: '127.0.0.1', downstreamPort: sink.address().port, maxBytes: 65536, maxConnections: 2 },
    { tls, log: (o) => logs.push(o) });
  await new Promise((r) => relay.listen(0, '127.0.0.1', r));
  try { return await fn(relay.address().port, received, logs, relay); } finally { relay.close(); sink.close(); }
}

const send = (port, payload) => new Promise((resolve, reject) => {
  const s = connect({ host: '127.0.0.1', port, ca: tls.cert, servername: 'syslog' }, () => { s.end(payload); });
  s.on('close', resolve);
  s.on('error', reject);
});

test('TLS de ponta a ponta: origem permitida chega ao Logstash uma por linha', () => withRelay(['127.0.0.1'], async (port, received, _logs, relay) => {
  await send(port, '9 <189>a=1\n<189>b=2\n');
  for (let i = 0; i < 50 && received.join('').split('\n').length < 3; i++) await new Promise((r) => setTimeout(r, 20));
  assert.equal(received.join(''), '<189>a=1\n<189>b=2\n');
  assert.equal(relay.stats.messages, 2);
}));

test('origem fora da lista é recusada antes do TLS', () => withRelay(['10.9.9.9'], async (port, received, logs) => {
  await assert.rejects(send(port, '<1>x\n'));
  assert.equal(received.length, 0);
  assert.ok(logs.some((l) => l.reason === 'origem não permitida'));
}));
