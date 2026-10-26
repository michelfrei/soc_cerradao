// fgt-gateway: recebe consultas por HTTPS com autenticação mútua (mTLS) e as executa
// no FortiGate por SSH, somente da lista em lib/commands.mjs. Uso:
//   node server.mjs C:\ProgramData\fgt-gateway\conf\gateway.json
// A chave SSH e o known_hosts ficam no servidor; nunca trafegam nem aparecem no log.
import { spawn } from 'node:child_process';
import { appendFileSync, readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import { join } from 'node:path';
import { redact, resolveCommand } from './lib/commands.mjs';

export function loadConfig(path) {
  const c = JSON.parse(readFileSync(path, 'utf8'));
  for (const k of ['listenHost', 'listenPort', 'caFile', 'serverCertFile', 'serverKeyFile', 'allowedClients', 'sshPath',
    'sshKeyFile', 'knownHostsFile', 'fortigateHost', 'fortigatePort', 'fortigateUser', 'auditDir']) {
    if (c[k] === undefined || c[k] === '') throw new Error(`configuração sem ${k}`);
  }
  if (!Array.isArray(c.allowedClients) || c.allowedClients.length === 0) throw new Error('allowedClients vazio');
  return { timeoutMs: 60_000, maxOutputBytes: 4 * 1024 * 1024, sshPrefixArgs: [], ...c };
}

/** Argumentos fixos do ssh: sem config do usuário, sem senha, identidade do FortiGate conferida. */
export function sshArgs(cfg, command) {
  return [...cfg.sshPrefixArgs,
    '-F', 'none', '-i', cfg.sshKeyFile, '-p', String(cfg.fortigatePort),
    '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'PasswordAuthentication=no',
    '-o', 'KbdInteractiveAuthentication=no', '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${cfg.knownHostsFile}`, '-o', `GlobalKnownHostsFile=${cfg.knownHostsFile}`,
    '-o', 'ConnectTimeout=15', '-o', 'LogLevel=ERROR',
    '-l', cfg.fortigateUser, cfg.fortigateHost, command];
}

export function runSsh(cfg, command) {
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(cfg.sshPath, sshArgs(cfg, command), { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true, shell: false });
    const out = [];
    let bytes = 0;
    let truncated = false;
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      if (bytes + chunk.length > cfg.maxOutputBytes) { truncated = true; child.kill(); return; }
      bytes += chunk.length;
      out.push(chunk);
    });
    child.stderr.on('data', (chunk) => { if (stderr.length < 2000) stderr += chunk.toString('utf8'); });
    const timer = setTimeout(() => { truncated = true; child.kill(); }, cfg.timeoutMs);
    child.on('error', (err) => { clearTimeout(timer); resolve({ exitCode: -1, output: '', stderr: err.message, ms: Date.now() - started, bytes, truncated }); });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ exitCode: code ?? -1, output: Buffer.concat(out).toString('utf8'), stderr, ms: Date.now() - started, bytes, truncated });
    });
  });
}

/** Uma consulta por vez: o FortiGate não precisa de sessões paralelas para leitura. */
let queue = Promise.resolve();
const serial = (fn) => { const p = queue.then(fn, fn); queue = p.catch(() => undefined); return p; };

function audit(cfg, entry) {
  const month = new Date().toISOString().slice(0, 7);
  try { appendFileSync(join(cfg.auditDir, `audit-${month}.jsonl`), `${JSON.stringify(entry)}\n`); } catch { /* auditoria não derruba o serviço */ }
}

function send(res, status, body) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(text);
}

/** Mensagem de erro do ssh sem caminhos locais (nome da chave/known_hosts). */
function sshError(stderr) {
  const s = stderr.toLowerCase();
  if (s.includes('host key verification failed') || s.includes('remote host identification has changed')) return 'identidade SSH do FortiGate não confere com o known_hosts';
  if (s.includes('permission denied')) return 'FortiGate recusou a chave do serviço';
  if (s.includes('timed out') || s.includes('connection refused') || s.includes('no route')) return 'FortiGate inacessível pela rede';
  return 'falha no SSH';
}

export function createGateway(cfg, run = runSsh) {
  const tls = {
    cert: readFileSync(cfg.serverCertFile), key: readFileSync(cfg.serverKeyFile),
    ca: readFileSync(cfg.caFile), requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.2',
  };
  return createServer(tls, (req, res) => {
    const peer = req.socket.getPeerCertificate();
    const client = peer?.subject?.CN ?? '';
    const base = { ts: new Date().toISOString(), remote: req.socket.remoteAddress, client, fingerprint256: peer?.fingerprint256 };
    if (!req.socket.authorized || !cfg.allowedClients.includes(client)) {
      audit(cfg, { ...base, result: 'rejected', reason: 'certificado de cliente não autorizado' });
      return send(res, 403, { error: 'cliente não autorizado' });
    }
    if (req.method === 'GET' && req.url === '/v1/health') return send(res, 200, { status: 'ok' });
    if (req.method !== 'POST' || req.url !== '/v1/query') return send(res, 404, { error: 'rota inexistente' });
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { body += chunk; if (body.length > 1024) req.destroy(); });
    req.on('end', async () => {
      let tool;
      let command;
      try {
        const parsed = JSON.parse(body);
        tool = parsed.tool;
        command = resolveCommand(tool, parsed.args ?? {});
      } catch (err) {
        audit(cfg, { ...base, result: 'refused', reason: err instanceof SyntaxError ? 'JSON inválido' : err.message });
        return send(res, 400, { error: err instanceof SyntaxError ? 'JSON inválido' : err.message });
      }
      const r = await serial(() => run(cfg, command));
      const ok = r.exitCode === 0 && !r.truncated;
      audit(cfg, { ...base, result: ok ? 'ok' : 'error', tool, command, exitCode: r.exitCode, ms: r.ms, bytes: r.bytes, truncated: r.truncated });
      if (!ok && !r.output) return send(res, 502, { error: r.truncated ? 'tempo ou tamanho limite excedido' : sshError(r.stderr), tool, command });
      send(res, 200, { tool, command, exitCode: r.exitCode, truncated: r.truncated, durationMs: r.ms, output: redact(r.output) });
    });
  });
}

if (process.argv[1]?.endsWith('server.mjs')) {
  const cfg = loadConfig(process.argv[2] ?? 'gateway.json');
  createGateway(cfg).listen(cfg.listenPort, cfg.listenHost, () => {
    console.log(`fgt-gateway ouvindo em https://${cfg.listenHost}:${cfg.listenPort}`);
  });
}
