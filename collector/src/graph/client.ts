import { setTimeout as sleep } from 'node:timers/promises';
import type { Logger } from '../logger.js';
import { Semaphore } from '../util.js';
import type { TokenProvider } from './auth.js';

export interface RequestStats {
  apiCalls: number;
  throttled: number;
}

export class GraphError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string | undefined,
    readonly requestId: string | undefined,
  ) {
    super(message);
    this.name = 'GraphError';
  }
}

const RETRYABLE = new Set([408, 429, 500, 502, 503, 504]);

/** Interpreta Retry-After em segundos ou data HTTP. Retorna milissegundos. */
export function parseRetryAfter(header: string | null, now = Date.now()): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(header);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - now);
}

/** Espera exponencial com jitter completo, limitada a capMs. */
export function backoffMs(attempt: number, baseMs = 2_000, capMs = 60_000, random = Math.random): number {
  const ceiling = Math.min(capMs, baseMs * 2 ** attempt);
  return Math.floor(random() * ceiling);
}

export interface GraphClientOptions {
  baseUrl: string;
  requestTimeoutMs: number;
  maxRetries: number;
  maxConcurrency: number;
  log: Logger;
  signal: AbortSignal;
}

export class GraphClient {
  private readonly limiter: Semaphore;

  constructor(
    private readonly auth: TokenProvider,
    private readonly opts: GraphClientOptions,
  ) {
    this.limiter = new Semaphore(opts.maxConcurrency);
  }

  async request(method: 'GET' | 'POST', pathOrUrl: string, stats: RequestStats, body?: unknown): Promise<unknown> {
    const url = pathOrUrl.startsWith('https://') ? pathOrUrl : `${this.opts.baseUrl}${pathOrUrl}`;
    if (!url.startsWith('https://graph.microsoft.com/')) {
      throw new Error(`URL fora do Microsoft Graph recusada: ${url}`);
    }
    let refreshedToken = false;
    let forceRefresh = false;

    for (let attempt = 0; ; attempt++) {
      this.opts.signal.throwIfAborted();
      const token = await this.auth.getToken(forceRefresh);
      forceRefresh = false;

      let response: Response;
      try {
        response = await this.limiter.run(() => {
          stats.apiCalls++;
          return fetch(url, {
            method,
            headers: {
              authorization: `Bearer ${token}`,
              accept: 'application/json',
              ...(body === undefined ? {} : { 'content-type': 'application/json' }),
            },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
            signal: AbortSignal.any([this.opts.signal, AbortSignal.timeout(this.opts.requestTimeoutMs)]),
          });
        });
      } catch (err) {
        if (this.opts.signal.aborted) throw err;
        if (attempt >= this.opts.maxRetries) throw err;
        const wait = backoffMs(attempt);
        this.opts.log.warn({ url: redactUrl(url), attempt, wait, err: (err as Error).message }, 'falha de rede no Graph; nova tentativa');
        await sleep(wait, undefined, { signal: this.opts.signal });
        continue;
      }

      if (response.ok) return response.json();

      const text = await response.text();
      const parsed = safeJson(text) as { error?: { code?: string; message?: string } } | undefined;
      const requestId = response.headers.get('request-id') ?? response.headers.get('client-request-id') ?? undefined;
      const error = new GraphError(
        `Graph ${method} ${redactUrl(url)} -> ${response.status}: ${parsed?.error?.message ?? text.slice(0, 500)}`,
        response.status,
        parsed?.error?.code,
        requestId,
      );

      if (response.status === 401 && !refreshedToken) {
        refreshedToken = true;
        forceRefresh = true;
        this.opts.log.warn({ requestId }, 'token recusado pelo Graph; renovando');
        continue;
      }
      if (!RETRYABLE.has(response.status) || attempt >= this.opts.maxRetries) throw error;

      if (response.status === 429) stats.throttled++;
      const wait = parseRetryAfter(response.headers.get('retry-after')) ?? backoffMs(attempt);
      this.opts.log.warn(
        { status: response.status, attempt, wait, requestId, url: redactUrl(url) },
        'Graph pediu nova tentativa',
      );
      await sleep(wait, undefined, { signal: this.opts.signal });
    }
  }

  /** Percorre @odata.nextLink, devolvendo uma página por vez. */
  async *paginate(path: string, stats: RequestStats): AsyncGenerator<unknown[]> {
    let next: string | undefined = path;
    while (next) {
      const page = (await this.request('GET', next, stats)) as { value?: unknown; '@odata.nextLink'?: unknown };
      if (!Array.isArray(page.value)) throw new Error('resposta do Graph sem a lista "value"');
      yield page.value;
      next = typeof page['@odata.nextLink'] === 'string' ? page['@odata.nextLink'] : undefined;
    }
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

function redactUrl(url: string): string {
  return url.replace(/\$skiptoken=[^&]+/i, '$skiptoken=…');
}
