import { setTimeout as sleep } from 'node:timers/promises';
import type { MsrcSourceConfig } from '../config.js';
import { setCheckpoint, withTransaction, type Client, type Pool, type RunCounters } from '../db.js';
import type { Logger } from '../logger.js';
import { errorMessage } from '../util.js';

/**
 * Catálogo de atualizações de segurança do Windows Server a partir do Security
 * Update Guide (MSRC). Só "Security Update": previews opcionais e hotpatch não
 * entram. A data de lançamento é a menor releaseDate em que o KB aparece.
 */

export interface SecurityUpdate {
  kb: string;
  product: string;
  fixedBuild: string;
  buildMajor: number;
  ubr: number;
  releaseDate: string;
  supersedes: string | null;
  rebootRequired: boolean | null;
  url: string | null;
}

interface KbArticle {
  articleName?: unknown;
  articleUrl?: unknown;
  downloadName?: unknown;
  supercedence?: unknown;
  rebootRequired?: unknown;
  fixedBuildNumber?: unknown;
}

const BUILD = /^10\.0\.(\d+)\.(\d+)$/;

function str(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function reboot(value: unknown): boolean | null {
  const v = str(value)?.toLowerCase();
  return v === 'yes' ? true : v === 'no' ? false : null;
}

/** Acumula uma página no catálogo. Registros sem build 10.0.x.y ou de outro tipo são ignorados. */
export function addPage(catalog: Map<string, SecurityUpdate>, records: unknown[]): void {
  for (const record of records) {
    if (!record || typeof record !== 'object') throw new Error('MSRC: registro inválido');
    const r = record as { product?: unknown; releaseDate?: unknown; kbArticles?: unknown };
    const product = str(r.product);
    const released = str(r.releaseDate);
    if (!product || !released || !Array.isArray(r.kbArticles)) continue;
    const date = new Date(released);
    if (Number.isNaN(date.getTime())) throw new Error(`MSRC: releaseDate inválida: ${released}`);
    for (const a of r.kbArticles as KbArticle[]) {
      if (str(a.downloadName) !== 'Security Update') continue;
      const kbNumber = str(a.articleName);
      const build = str(a.fixedBuildNumber);
      const m = build ? BUILD.exec(build) : null;
      if (!kbNumber || !/^\d+$/.test(kbNumber) || !m) continue;
      const key = `${kbNumber}|${m[1]}`;
      const previous = catalog.get(key);
      const iso = date.toISOString();
      if (previous) {
        if (iso < previous.releaseDate) previous.releaseDate = iso;
        if (previous.fixedBuild !== build) throw new Error(`MSRC: KB${kbNumber} com builds diferentes (${previous.fixedBuild}, ${build})`);
        continue;
      }
      const supersedes = str(a.supercedence);
      catalog.set(key, {
        kb: `KB${kbNumber}`, product: product.replace(/ \(Server Core installation\)$/, ''), fixedBuild: build!,
        buildMajor: Number(m[1]), ubr: Number(m[2]), releaseDate: iso,
        supersedes: supersedes && /^\d+$/.test(supersedes) ? `KB${supersedes}` : supersedes,
        rebootRequired: reboot(a.rebootRequired), url: str(a.articleUrl),
      });
    }
  }
}

async function getJson(url: string, timeoutMs: number, log: Logger, counters: RunCounters): Promise<{ value?: unknown; '@odata.nextLink'?: unknown }> {
  for (let attempt = 0; ; attempt++) {
    counters.apiCalls++;
    try {
      const res = await fetch(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(timeoutMs) });
      if (res.ok) return await res.json() as { value?: unknown; '@odata.nextLink'?: unknown };
      if (![429, 500, 502, 503, 504].includes(res.status) || attempt >= 3) throw new Error(`MSRC HTTP ${res.status}`);
      if (res.status === 429) counters.throttled++;
    } catch (err) {
      if (attempt >= 3) throw err;
      log.warn({ url, attempt, err: errorMessage(err) }, 'MSRC: nova tentativa');
    }
    await sleep(2_000 * 2 ** attempt);
  }
}

/** Lê todas as páginas de um produto; qualquer falha recusa a atualização do catálogo. */
export async function fetchProduct(src: MsrcSourceConfig, product: string, catalog: Map<string, SecurityUpdate>,
  log: Logger, counters: RunCounters): Promise<number> {
  const params = new URLSearchParams({ $filter: `product eq '${product.replace(/'/g, "''")}'`, $top: String(src.pageSize) });
  let url: string | null = `${src.baseUrl}?${params.toString()}`;
  let records = 0;
  for (let page = 0; url; page++) {
    if (page >= src.maxPages) throw new Error(`MSRC: ${product} excedeu ${src.maxPages} páginas; catálogo não atualizado`);
    const body = await getJson(url, src.requestTimeoutMs, log, counters);
    if (!Array.isArray(body.value)) throw new Error(`MSRC: resposta sem value para ${product}`);
    addPage(catalog, body.value);
    records += body.value.length;
    url = typeof body['@odata.nextLink'] === 'string' ? body['@odata.nextLink'] : null;
  }
  if (records === 0) throw new Error(`MSRC: nenhum registro para ${product}; confira o nome do produto`);
  return records;
}

export async function storeCatalog(client: Client, src: MsrcSourceConfig, updates: SecurityUpdate[], at: Date): Promise<{ inserted: number; changed: number }> {
  const before = await client.query<{ n: number }>('SELECT count(*)::int AS n FROM soc.windows_security_update');
  const saved = await client.query(`
    INSERT INTO soc.windows_security_update AS u
      (kb, build_major, product, fixed_build, ubr, release_date, supersedes, reboot_required, url, updated_at)
    SELECT kb, "buildMajor", product, "fixedBuild", ubr, "releaseDate", supersedes, "rebootRequired", url, $2
    FROM jsonb_to_recordset($1::jsonb) AS r(kb text, "buildMajor" int, product text, "fixedBuild" text, ubr int,
      "releaseDate" timestamptz, supersedes text, "rebootRequired" boolean, url text)
    ON CONFLICT (kb, build_major) DO UPDATE SET product = EXCLUDED.product, fixed_build = EXCLUDED.fixed_build,
      ubr = EXCLUDED.ubr, release_date = least(u.release_date, EXCLUDED.release_date), supersedes = EXCLUDED.supersedes,
      reboot_required = EXCLUDED.reboot_required, url = EXCLUDED.url, updated_at = EXCLUDED.updated_at`,
  [JSON.stringify(updates), at]);
  await setCheckpoint(client, src.name, at);
  const after = await client.query<{ n: number }>('SELECT count(*)::int AS n FROM soc.windows_security_update');
  return { inserted: after.rows[0]!.n - before.rows[0]!.n, changed: saved.rowCount ?? 0 };
}

export async function collectMsrc(src: MsrcSourceConfig, deps: { pool: Pool; log: Logger }, counters: RunCounters): Promise<void> {
  const at = new Date();
  counters.windowStart = at;
  counters.windowEnd = at;
  const catalog = new Map<string, SecurityUpdate>();
  for (const product of src.products) counters.fetched += await fetchProduct(src, product, catalog, deps.log, counters);
  const result = await withTransaction(deps.pool, (client) => storeCatalog(client, src, [...catalog.values()], at));
  counters.inserted = result.inserted;
  counters.changed = result.changed;
}
