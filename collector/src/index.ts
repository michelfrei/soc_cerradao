import { createServer } from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';
import { loadConfig, type SourceConfig } from './config.js';
import { createPool, finishRun, startRun, type Pool, type RunCounters } from './db.js';
import { GraphAuth } from './graph/auth.js';
import { GraphClient } from './graph/client.js';
import { createLogger, type Logger } from './logger.js';
import { collectHunting } from './sources/hunting.js';
import { collectObjects } from './sources/objects.js';
import { errorMessage } from './util.js';

interface SourceState {
  lastStatus?: 'success' | 'failed';
  lastFinishedAt?: string;
  lastError?: string;
  consecutiveFailures: number;
}

/** Falhas seguidas a partir das quais o /health responde 503 (fonte travada). */
const FAILURES_UNHEALTHY = 3;

async function runOnce(src: SourceConfig, deps: { pool: Pool; graph: GraphClient; log: Logger }): Promise<void> {
  const counters: RunCounters = { fetched: 0, inserted: 0, changed: 0, apiCalls: 0, throttled: 0 };
  const runId = await startRun(deps.pool, src.name);
  const started = Date.now();
  try {
    if (src.type === 'hunting') await collectHunting(src, deps, counters);
    else await collectObjects(src, deps, counters);
    await finishRun(deps.pool, runId, counters);
    deps.log.info({ source: src.name, ms: Date.now() - started, ...counters }, 'coleta concluída');
  } catch (err) {
    await finishRun(deps.pool, runId, counters, errorMessage(err)).catch((e: unknown) =>
      deps.log.error({ source: src.name, err: errorMessage(e) }, 'falha ao registrar execução'),
    );
    throw err;
  }
}

async function loop(src: SourceConfig, deps: { pool: Pool; graph: GraphClient; log: Logger }, state: SourceState, signal: AbortSignal): Promise<void> {
  // Espalha o início das fontes para não disparar tudo junto.
  await sleep(Math.floor(Math.random() * 10_000), undefined, { signal }).catch(() => undefined);
  while (!signal.aborted) {
    try {
      await runOnce(src, deps);
      state.lastStatus = 'success';
      state.consecutiveFailures = 0;
      delete state.lastError;
    } catch (err) {
      if (signal.aborted) break;
      state.lastStatus = 'failed';
      state.consecutiveFailures++;
      state.lastError = errorMessage(err);
      deps.log.error({ source: src.name, err: errorMessage(err) }, 'coleta falhou');
    }
    state.lastFinishedAt = new Date().toISOString();
    const jitter = 0.9 + Math.random() * 0.2;
    await sleep(src.intervalSeconds * 1000 * jitter, undefined, { signal }).catch(() => undefined);
  }
}

async function main(): Promise<void> {
  const config = loadConfig();
  const log = createLogger(config.logLevel);
  const controller = new AbortController();
  const { signal } = controller;

  const pool = createPool(config.pg);
  pool.on('error', (err) => log.error({ err: err.message }, 'erro em conexão ociosa do PostgreSQL'));
  await pool.query('SELECT 1');

  const graph = new GraphClient(new GraphAuth(config.graph), {
    baseUrl: config.graph.baseUrl,
    requestTimeoutMs: config.graph.requestTimeoutMs,
    maxRetries: config.graph.maxRetries,
    maxConcurrency: config.graph.maxConcurrency,
    log,
    signal,
  });

  const enabled = config.sources.filter((s) => s.enabled);
  if (enabled.length === 0) log.warn('nenhuma fonte habilitada em sources.json');
  const states = new Map<string, SourceState>(enabled.map((s) => [s.name, { consecutiveFailures: 0 }]));

  const server = createServer((req, res) => {
    if (req.url !== '/health') {
      res.writeHead(404).end();
      return;
    }
    pool
      .query('SELECT 1')
      .then(() => {
        // Fonte falhando seguidamente não avança o checkpoint; sinaliza para o
        // monitoramento antes que os dados saiam da retenção do Defender.
        const stuck = [...states].filter(([, s]) => s.consecutiveFailures >= FAILURES_UNHEALTHY).map(([n]) => n);
        res.writeHead(stuck.length ? 503 : 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: stuck.length ? 'source_failing' : 'ok', stuck, sources: Object.fromEntries(states) }));
      })
      .catch((err: unknown) => {
        res.writeHead(503, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ status: 'database_unavailable', error: errorMessage(err) }));
      });
  });
  server.listen(config.healthPort, '0.0.0.0');

  const shutdown = (sig: string): void => {
    if (signal.aborted) return;
    log.info({ signal: sig }, 'encerrando');
    controller.abort();
    server.close();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  log.info({ sources: enabled.map((s) => s.name) }, 'coletor iniciado');
  const deps = { pool, graph, log };
  await Promise.all(enabled.map((s) => loop(s, deps, states.get(s.name)!, signal)));
  await pool.end();
  log.info('coletor encerrado');
}

main().catch((err: unknown) => {
  // Logger pode não existir se a configuração falhou.
  console.error(JSON.stringify({ level: 'fatal', msg: 'falha ao iniciar o coletor', err: errorMessage(err) }));
  process.exit(1);
});
