import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isSecretAttribute, redact, resolveCommand } from '../lib/commands.mjs';
import { createGateway, sshArgs } from '../server.mjs';
import { callGateway, handle, toolList } from '../mcp.mjs';

test('lista fechada: só ferramentas conhecidas e id inteiro', () => {
  assert.equal(resolveCommand('status'), 'get system status');
  assert.equal(resolveCommand('policy', { id: 12 }), 'show firewall policy 12');
  assert.throws(() => resolveCommand('execute reboot'), /não permitida/);
  assert.throws(() => resolveCommand('policy', { id: '12; execute reboot' }), /inteiro/);
  assert.throws(() => resolveCommand('policy', { id: 1.5 }), /inteiro/);
  assert.throws(() => resolveCommand('status', { extra: 1 }), /parâmetro não permitido/);
  assert.throws(() => resolveCommand('__proto__'), /não permitida/);
});

test('segredos do FortiOS são removidos sem esconder atributos comuns', () => {
  const out = redact([
    'config system interface', '    edit "wan1"', '        set password ENC AbCdEf==', '        set keylife 86400',
    '        set psksecret ENC Zz9==', '        set auth-key "abc"', '        set comments "token de teste ENC xyz"',
    '-----BEGIN RSA PRIVATE KEY-----', 'MIIE', '-----END RSA PRIVATE KEY-----', '        set ip 10.0.0.1 255.255.255.0',
  ].join('\n'));
  assert.match(out, /set password <removido>/);
  assert.match(out, /set psksecret <removido>/);
  assert.match(out, /set auth-key <removido>/);
  assert.match(out, /set keylife 86400/);
  assert.match(out, /ENC <removido>/);
  assert.doesNotMatch(out, /AbCdEf|Zz9|MIIE|xyz/);
  assert.match(out, /set ip 10\.0\.0\.1/);
  assert.equal(isSecretAttribute('keepalive'), false);
});

test('ssh com identidade fixada, sem senha nem config do usuário', () => {
  const args = sshArgs({ sshPrefixArgs: [], sshKeyFile: 'k', fortigatePort: 40022, knownHostsFile: 'kh', fortigateUser: 'claude', fortigateHost: '172.16.0.1' }, 'get system status');
  for (const o of ['BatchMode=yes', 'StrictHostKeyChecking=yes', 'UserKnownHostsFile=kh', 'PasswordAuthentication=no', 'IdentitiesOnly=yes']) assert.ok(args.includes(o), o);
  assert.deepEqual(args.slice(0, 2), ['-F', 'none']);
  assert.equal(args.at(-1), 'get system status');
});

test('ferramentas MCP somente leitura e erro sem detalhes internos', async () => {
  assert.deepEqual(toolList().map((t) => t.name).sort(), ['fortigate_interfaces_config', 'fortigate_interfaces_status', 'fortigate_policies',
    'fortigate_policy', 'fortigate_routes', 'fortigate_status']);
  const init = await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }, () => ({}));
  assert.equal(init.result.serverInfo.name, 'fortigate-readonly');
  assert.equal(await handle({ jsonrpc: '2.0', method: 'notifications/initialized' }, () => ({})), null);
  const bad = await handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'fortigate_execute' } }, () => ({}));
  assert.equal(bad.result.isError, true);
});

// --- fluxo completo local: CA própria, mTLS, ssh falso -----------------------------------

const dir = mkdtempSync(join(tmpdir(), 'fgtgw-'));
const ossl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
function issue(name, cn, caName, ext) {
  writeFileSync(join(dir, `${name}.ext`), ext);
  ossl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${cn}`);
  ossl('x509', '-req', '-in', `${name}.csr`, '-CA', `${caName}.crt`, '-CAkey', `${caName}.key`, '-CAcreateserial', '-days', '2', '-out', `${name}.crt`, '-extfile', `${name}.ext`);
}
for (const ca of ['ca', 'other']) ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${ca}.key`, '-out', `${ca}.crt`, '-days', '2', '-subj', `/CN=${ca}`);
issue('server', 'fgt-gateway', 'ca', 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n');
issue('client', 'fgt-client-teste', 'ca', 'extendedKeyUsage=clientAuth\n');
issue('intruso', 'fgt-client-teste', 'other', 'extendedKeyUsage=clientAuth\n');

const fakeSsh = fileURLToPath(new URL('./fake-ssh.mjs', import.meta.url));
const cfg = { listenHost: '127.0.0.1', listenPort: 0, caFile: join(dir, 'ca.crt'), serverCertFile: join(dir, 'server.crt'), serverKeyFile: join(dir, 'server.key'),
  allowedClients: ['fgt-client-teste'], sshPath: process.execPath, sshPrefixArgs: [fakeSsh], sshKeyFile: 'C:/ProgramData/fgt-gateway/keys/fortigate_ed25519',
  knownHostsFile: 'kh', fortigateHost: '172.16.0.1', fortigatePort: 40022, fortigateUser: 'claude', auditDir: dir, timeoutMs: 10_000, maxOutputBytes: 1_000_000 };

async function withGateway(fn) {
  const server = createGateway(cfg);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  try { return await fn(server.address().port); } finally { server.close(); }
}
const client = (port, name = 'client') => ({ url: new URL(`https://127.0.0.1:${port}`), ca: readFileSync(join(dir, 'ca.crt')),
  cert: readFileSync(join(dir, `${name}.crt`)), key: readFileSync(join(dir, `${name}.key`)), timeoutMs: 10_000 });

test('mTLS: consulta permitida passa, saída sem segredos, auditoria sem conteúdo nem chave', () => withGateway(async (port) => {
  const r = await callGateway(client(port), 'policy', { id: 7 });
  assert.equal(r.status, 200);
  assert.equal(r.body.command, 'show firewall policy 7');
  assert.match(r.body.output, /ARGS .*show firewall policy 7/);
  assert.match(r.body.output, /set psksecret <removido>/);
  assert.doesNotMatch(r.body.output, /SegredoFalso/);
  const mcp = await handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'fortigate_status', arguments: {} } }, () => client(port));
  assert.match(mcp.result.content[0].text, /^# get system status/);
  const log = readdirSync(dir).filter((f) => f.startsWith('audit-')).map((f) => readFileSync(join(dir, f), 'utf8')).join('');
  assert.match(log, /"result":"ok","tool":"policy"/);
  assert.doesNotMatch(log, /SegredoFalso|psksecret|fortigate_ed25519|BEGIN/);
}));

test('mTLS: sem certificado ou de outra CA é recusado; comando fora da lista também', () => withGateway(async (port) => {
  const noCert = { ...client(port), cert: undefined, key: undefined };
  await assert.rejects(callGateway(noCert, 'status', {}));
  await assert.rejects(callGateway(client(port, 'intruso'), 'status', {}));
  const refused = await callGateway(client(port), 'diagnose', {});
  assert.equal(refused.status, 400);
  assert.match(refused.body.error, /não permitida/);
}));
