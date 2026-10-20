import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';

const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const EnvSchema = z.object({
  GRAPH_TENANT_ID: z.string().regex(GUID, 'GRAPH_TENANT_ID deve ser um GUID'),
  GRAPH_CLIENT_ID: z.string().regex(GUID, 'GRAPH_CLIENT_ID deve ser um GUID'),
  GRAPH_CLIENT_SECRET_FILE: z.string().optional(),
  GRAPH_CERT_KEY_FILE: z.string().optional(),
  GRAPH_CERT_THUMBPRINT_SHA256: z.string().optional(),
  GRAPH_BASE_URL: z.string().url().default('https://graph.microsoft.com/v1.0'),
  GRAPH_AUTHORITY_HOST: z.string().url().default('https://login.microsoftonline.com'),
  GRAPH_MAX_CONCURRENCY: z.coerce.number().int().min(1).max(10).default(2),
  GRAPH_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(5_000).default(120_000),
  GRAPH_MAX_RETRIES: z.coerce.number().int().min(0).max(10).default(6),

  PGHOST: z.string().min(1),
  PGPORT: z.coerce.number().int().default(5432),
  PGDATABASE: z.string().default('soc'),
  PGUSER: z.string().default('soc_collector'),
  PGPASSWORD_FILE: z.string().min(1),
  PGSSLMODE: z.enum(['disable', 'require', 'verify-full']).default('require'),
  PGSSLROOTCERT_FILE: z.string().optional(),
  PG_POOL_MAX: z.coerce.number().int().min(1).max(20).default(4),

  SOURCES_FILE: z.string().default('/app/config/sources.json'),
  QUERIES_DIR: z.string().default('/app/queries'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  HEALTH_PORT: z.coerce.number().int().default(8080),
});

const BaseSource = z.object({
  name: z.string().regex(/^[a-z0-9_.-]+$/),
  enabled: z.boolean().default(true),
  intervalSeconds: z.number().int().min(60).default(300),
  overlapMinutes: z.number().int().min(0).max(1440).default(30),
  initialLookbackHours: z.number().int().min(1).default(24),
});

const ObjectSource = BaseSource.extend({
  type: z.enum(['incidents', 'alerts']),
  pageSize: z.number().int().min(1).max(2000).optional(),
});

const HuntingSource = BaseSource.extend({
  type: z.literal('hunting'),
  table: z.string().regex(/^[A-Za-z]+$/),
  queryFile: z.string().regex(/^[a-z0-9_.-]+\.kql$/),
  // Advanced Hunting retém 30 dias.
  initialLookbackHours: z.number().int().min(1).max(720).default(24),
  ingestionLagMinutes: z.number().int().min(0).default(5),
  maxWindowMinutes: z.number().int().min(1).default(60),
  minWindowMinutes: z.number().int().min(1).default(1),
  maxRows: z.number().int().min(100).max(100_000).default(30_000),
  maxWindowsPerRun: z.number().int().min(1).default(24),
});

const SourcesFile = z.object({
  sources: z.array(z.discriminatedUnion('type', [ObjectSource, HuntingSource])),
});

export type ObjectSourceConfig = z.infer<typeof ObjectSource>;
export type HuntingSourceConfig = z.infer<typeof HuntingSource> & { query: string };
export type SourceConfig = ObjectSourceConfig | HuntingSourceConfig;

export type GraphCredential =
  | { kind: 'secret'; clientSecret: string }
  | { kind: 'certificate'; privateKey: string; thumbprintSha256: string };

export interface Config {
  graph: {
    tenantId: string;
    clientId: string;
    credential: GraphCredential;
    baseUrl: string;
    authorityHost: string;
    maxConcurrency: number;
    requestTimeoutMs: number;
    maxRetries: number;
  };
  pg: {
    host: string;
    port: number;
    database: string;
    user: string;
    password: string;
    sslmode: 'disable' | 'require' | 'verify-full';
    sslRootCert?: string;
    poolMax: number;
  };
  sources: SourceConfig[];
  logLevel: string;
  healthPort: number;
}

function readSecretFile(path: string, label: string): string {
  let value: string;
  try {
    value = readFileSync(path, 'utf8').trim();
  } catch (err) {
    throw new Error(`não foi possível ler ${label} em ${path}: ${(err as Error).message}`);
  }
  if (!value) throw new Error(`${label} em ${path} está vazio`);
  return value;
}

function graphCredential(env: z.infer<typeof EnvSchema>): GraphCredential {
  if (env.GRAPH_CERT_KEY_FILE) {
    if (!env.GRAPH_CERT_THUMBPRINT_SHA256) {
      throw new Error('GRAPH_CERT_THUMBPRINT_SHA256 é obrigatório com GRAPH_CERT_KEY_FILE');
    }
    return {
      kind: 'certificate',
      privateKey: readSecretFile(env.GRAPH_CERT_KEY_FILE, 'chave privada do certificado'),
      thumbprintSha256: env.GRAPH_CERT_THUMBPRINT_SHA256.replace(/[^0-9a-f]/gi, ''),
    };
  }
  if (env.GRAPH_CLIENT_SECRET_FILE) {
    return { kind: 'secret', clientSecret: readSecretFile(env.GRAPH_CLIENT_SECRET_FILE, 'client secret') };
  }
  throw new Error('defina GRAPH_CLIENT_SECRET_FILE ou GRAPH_CERT_KEY_FILE');
}

export function parseSources(raw: unknown, readQuery: (file: string) => string): SourceConfig[] {
  const parsed = SourcesFile.parse(raw);
  const names = new Set<string>();
  return parsed.sources.map((s) => {
    if (names.has(s.name)) throw new Error(`fonte duplicada: ${s.name}`);
    names.add(s.name);
    if (s.type !== 'hunting') return s;
    if (s.minWindowMinutes > s.maxWindowMinutes) {
      throw new Error(`${s.name}: minWindowMinutes maior que maxWindowMinutes`);
    }
    const query = readQuery(s.queryFile);
    if (!query.includes('{{start}}') || !query.includes('{{end}}')) {
      throw new Error(`${s.queryFile}: a consulta precisa conter {{start}} e {{end}}`);
    }
    return { ...s, query };
  });
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const e = EnvSchema.parse(env);
  const sourcesRaw: unknown = JSON.parse(readFileSync(e.SOURCES_FILE, 'utf8'));
  const sources = parseSources(sourcesRaw, (file) => readFileSync(join(e.QUERIES_DIR, file), 'utf8'));

  return {
    graph: {
      tenantId: e.GRAPH_TENANT_ID,
      clientId: e.GRAPH_CLIENT_ID,
      credential: graphCredential(e),
      baseUrl: e.GRAPH_BASE_URL.replace(/\/+$/, ''),
      authorityHost: e.GRAPH_AUTHORITY_HOST.replace(/\/+$/, ''),
      maxConcurrency: e.GRAPH_MAX_CONCURRENCY,
      requestTimeoutMs: e.GRAPH_REQUEST_TIMEOUT_MS,
      maxRetries: e.GRAPH_MAX_RETRIES,
    },
    pg: {
      host: e.PGHOST,
      port: e.PGPORT,
      database: e.PGDATABASE,
      user: e.PGUSER,
      password: readSecretFile(e.PGPASSWORD_FILE, 'senha do PostgreSQL'),
      sslmode: e.PGSSLMODE,
      ...(e.PGSSLROOTCERT_FILE ? { sslRootCert: readFileSync(e.PGSSLROOTCERT_FILE, 'utf8') } : {}),
      poolMax: e.PG_POOL_MAX,
    },
    sources,
    logLevel: e.LOG_LEVEL,
    healthPort: e.HEALTH_PORT,
  };
}
