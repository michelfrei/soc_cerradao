// syslog-relay: recebe syslog por TCP + TLS do FortiAnalyzer e entrega ao Logstash
// uma mensagem por linha. Aceita os dois enquadramentos do RFC 6587 na mesma conexão:
// contagem de octetos ("123 <189>...") e delimitado por LF/NUL ("<189>...\n").
// Sem dependências. Configuração por ambiente (ver loadConfig).
import { readFileSync } from 'node:fs';
import { connect } from 'node:net';
import { isIP } from 'node:net';
import { createServer } from 'node:tls';

const LF = 0x0a;
const NUL = 0x00;
const SPACE = 0x20;

/**
 * Divide um fluxo TCP em mensagens syslog. onMessage recebe cada mensagem (Buffer,
 * sem o enquadramento); onOversize recebe o tamanho de mensagens descartadas.
 */
export function createFramer(onMessage, { maxBytes = 65536, onOversize = () => {} } = {}) {
  let buf = Buffer.alloc(0);
  let skip = 0; // bytes restantes de uma mensagem com contagem acima do limite
  let discarding = false; // mensagem delimitada acima do limite: descarta até o LF
  return (chunk) => {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    for (;;) {
      if (skip > 0) {
        const n = Math.min(skip, buf.length);
        skip -= n;
        buf = buf.subarray(n);
        if (skip > 0) return;
      }
      if (discarding) {
        const end = buf.findIndex((b) => b === LF || b === NUL);
        if (end < 0) { buf = Buffer.alloc(0); return; }
        discarding = false;
        buf = buf.subarray(end + 1);
      }
      // Separadores soltos entre mensagens.
      let start = 0;
      while (start < buf.length && (buf[start] === LF || buf[start] === NUL || buf[start] === 0x0d || buf[start] === SPACE)) start++;
      buf = buf.subarray(start);
      if (!buf.length) return;

      if (buf[0] >= 0x30 && buf[0] <= 0x39) {
        // Contagem de octetos: dígitos, espaço, mensagem.
        let i = 0;
        while (i < buf.length && i < 10 && buf[i] >= 0x30 && buf[i] <= 0x39) i++;
        if (i === buf.length) return; // espera o restante da contagem
        if (buf[i] === SPACE) {
          const len = Number(buf.subarray(0, i).toString('ascii'));
          const body = i + 1;
          if (len > maxBytes) {
            onOversize(len);
            skip = len;
            buf = buf.subarray(body);
            continue;
          }
          if (buf.length < body + len) return;
          onMessage(buf.subarray(body, body + len));
          buf = buf.subarray(body + len);
          continue;
        }
        // Dígitos sem espaço: não é contagem; trata como mensagem delimitada.
      }
      const end = buf.findIndex((b) => b === LF || b === NUL);
      if (end < 0) {
        if (buf.length > maxBytes) { onOversize(buf.length); discarding = true; buf = Buffer.alloc(0); }
        return;
      }
      onMessage(buf.subarray(0, end));
      buf = buf.subarray(end + 1);
    }
  };
}

/** Uma linha para o Logstash: sem CR/LF internos e sem espaços nas pontas. */
export function toLine(message) {
  return `${message.toString('utf8').replace(/[\r\n\0]+/g, ' ').trim()}\n`;
}

export function loadConfig(env = process.env) {
  const allowed = (env.FW_SYSLOG_ALLOWED ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const ip of allowed) if (!isIP(ip)) throw new Error(`FW_SYSLOG_ALLOWED: IP inválido: ${ip}`);
  return {
    port: Number(env.RELAY_PORT ?? 6514),
    certFile: env.RELAY_CERT_FILE ?? '/certs/syslog/syslog.crt',
    keyFile: env.RELAY_KEY_FILE ?? '/certs/syslog/syslog.key',
    allowed,
    downstreamHost: env.RELAY_DOWNSTREAM_HOST ?? 'logstash',
    downstreamPort: Number(env.RELAY_DOWNSTREAM_PORT ?? 5514),
    maxBytes: Number(env.RELAY_MAX_MESSAGE_BYTES ?? 65536),
    maxConnections: Number(env.RELAY_MAX_CONNECTIONS ?? 8),
  };
}

const plainIp = (addr) => (addr ?? '').replace(/^::ffff:/, '');

/**
 * Servidor TLS. Cada conexão do FortiAnalyzer tem sua própria conexão com o Logstash:
 * se o Logstash não aceita mais dados (fila cheia ou fora), a leitura pausa e o TCP
 * segura o emissor, que mantém os logs na própria fila de envio confiável.
 */
export function createRelay(cfg, { log = (o) => console.log(JSON.stringify(o)), tls = {} } = {}) {
  const stats = { connections: 0, rejected: 0, messages: 0, oversize: 0, bytes: 0 };
  const allowed = new Set(cfg.allowed);
  const server = createServer({
    cert: tls.cert ?? readFileSync(cfg.certFile), key: tls.key ?? readFileSync(cfg.keyFile),
    minVersion: 'TLSv1.2', requestCert: false,
  });
  // Recusa antes do handshake: origem fora da lista nem negocia TLS.
  server.on('connection', (raw) => {
    const ip = plainIp(raw.remoteAddress);
    if (!allowed.has(ip) || server.connectionsActive >= cfg.maxConnections) {
      stats.rejected++;
      log({ level: 'warn', msg: 'conexão recusada', remote: ip, reason: allowed.has(ip) ? 'limite de conexões' : 'origem não permitida' });
      raw.destroy();
      return;
    }
  });
  server.connectionsActive = 0;
  server.on('secureConnection', (up) => {
    const remote = plainIp(up.remoteAddress);
    server.connectionsActive++;
    stats.connections++;
    log({ level: 'info', msg: 'emissor conectado', remote });
    up.pause();
    const down = connect({ host: cfg.downstreamHost, port: cfg.downstreamPort });
    down.setNoDelay(true);
    down.on('connect', () => up.resume());
    const framer = createFramer((m) => {
      stats.messages++;
      stats.bytes += m.length;
      if (!down.write(toLine(m))) up.pause();
    }, { maxBytes: cfg.maxBytes, onOversize: (n) => { stats.oversize++; log({ level: 'warn', msg: 'mensagem acima do limite descartada', bytes: n }); } });
    down.on('drain', () => up.resume());
    up.on('data', framer);
    const close = (who, err) => {
      if (err) log({ level: 'warn', msg: `${who} encerrou com erro`, remote, err: err.message });
      up.destroy();
      down.end();
    };
    up.on('error', (e) => close('emissor', e));
    up.on('close', () => { server.connectionsActive--; log({ level: 'info', msg: 'emissor desconectado', remote }); down.end(); });
    down.on('error', (e) => close('logstash', e));
    down.on('close', () => up.destroy());
  });
  server.on('tlsClientError', (err, socket) => log({ level: 'warn', msg: 'falha no TLS', remote: plainIp(socket?.remoteAddress), err: err.message }));
  server.stats = stats;
  return server;
}

if (process.argv[1]?.endsWith('relay.mjs')) {
  const cfg = loadConfig();
  const log = (o) => console.log(JSON.stringify({ ts: new Date().toISOString(), ...o }));
  if (!cfg.allowed.length) log({ level: 'warn', msg: 'FW_SYSLOG_ALLOWED vazio: todas as conexões serão recusadas' });
  const relay = createRelay(cfg, { log });
  relay.listen(cfg.port, '0.0.0.0', () => log({ level: 'info', msg: 'syslog-relay ouvindo', port: cfg.port, allowed: cfg.allowed }));
  setInterval(() => log({ level: 'info', msg: 'estatísticas', active: relay.connectionsActive, ...relay.stats }), 60_000).unref();
  const stop = () => relay.close(() => process.exit(0));
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
