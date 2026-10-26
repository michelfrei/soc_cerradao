// Conector MCP (stdio) do notebook: expõe as consultas permitidas do FortiGate como
// ferramentas e as encaminha ao fgt-gateway por HTTPS com certificado de cliente.
// Não lê chave SSH nem acessa o servidor por compartilhamento de rede.
// Configuração: %USERPROFILE%\.fgt-gateway\client.json (ou FGT_GATEWAY_CONFIG).
import { readFileSync } from 'node:fs';
import { request } from 'node:https';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join } from 'node:path';
import { createInterface } from 'node:readline';
import { TOOLS } from './lib/commands.mjs';

const VERSION = '1.0.0';

export function loadClientConfig(path = process.env.FGT_GATEWAY_CONFIG ?? join(homedir(), '.fgt-gateway', 'client.json')) {
  const c = JSON.parse(readFileSync(path, 'utf8'));
  const rel = (p) => (isAbsolute(p) ? p : join(dirname(path), p));
  const url = new URL(c.url);
  if (url.protocol !== 'https:') throw new Error('url do gateway precisa ser https');
  return { url, ca: readFileSync(rel(c.caFile)), pfx: readFileSync(rel(c.pfxFile)), passphrase: readFileSync(rel(c.passFile), 'utf8').trim(),
    timeoutMs: c.timeoutMs ?? 90_000 };
}

export function callGateway(cfg, tool, args) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ tool, args });
    const req = request({
      host: cfg.url.hostname, port: cfg.url.port || 443, path: '/v1/query', method: 'POST',
      ca: cfg.ca, pfx: cfg.pfx, passphrase: cfg.passphrase, minVersion: 'TLSv1.2', rejectUnauthorized: true,
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: cfg.timeoutMs,
    }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(text) }); } catch { reject(new Error(`resposta inválida do gateway (HTTP ${res.statusCode})`)); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('tempo limite do gateway')));
    req.on('error', reject);
    req.end(body);
  });
}

export function toolList() {
  return Object.entries(TOOLS).map(([name, t]) => ({
    name: `fortigate_${name}`,
    description: `${t.description} Somente leitura.`,
    inputSchema: { type: 'object', properties: t.params ?? {}, required: Object.keys(t.params ?? {}), additionalProperties: false },
  }));
}

export async function handle(msg, getConfig, call = callGateway) {
  const reply = (result) => ({ jsonrpc: '2.0', id: msg.id, result });
  switch (msg.method) {
    case 'initialize':
      return reply({ protocolVersion: msg.params?.protocolVersion ?? '2025-06-18', capabilities: { tools: {} },
        serverInfo: { name: 'fortigate-readonly', version: VERSION } });
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: toolList() });
    case 'tools/call': {
      const name = String(msg.params?.name ?? '');
      const tool = name.replace(/^fortigate_/, '');
      if (!Object.hasOwn(TOOLS, tool)) return reply({ isError: true, content: [{ type: 'text', text: 'ferramenta inexistente' }] });
      try {
        const r = await call(getConfig(), tool, msg.params?.arguments ?? {});
        if (r.status !== 200) return reply({ isError: true, content: [{ type: 'text', text: `gateway: ${r.body?.error ?? `HTTP ${r.status}`}` }] });
        const head = `# ${r.body.command} (${r.body.durationMs} ms${r.body.truncated ? ', truncado' : ''})\n`;
        return reply({ content: [{ type: 'text', text: head + r.body.output }] });
      } catch (err) {
        return reply({ isError: true, content: [{ type: 'text', text: `gateway indisponível: ${err.message}` }] });
      }
    }
    default:
      if (msg.id === undefined) return null; // notificações (ex.: notifications/initialized)
      return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: 'método não suportado' } };
  }
}

if (process.argv[1]?.endsWith('mcp.mjs')) {
  let cfg;
  const getConfig = () => (cfg ??= loadClientConfig());
  const rl = createInterface({ input: process.stdin });
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    const out = await handle(msg, getConfig);
    if (out) process.stdout.write(`${JSON.stringify(out)}\n`);
  });
}
