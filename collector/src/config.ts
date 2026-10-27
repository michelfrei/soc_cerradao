import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { z } from 'zod';
import type { ElasticConfig } from './elastic/client.js';
import { EMPTY_CATALOG, parseCatalog, type RemediationCatalog } from './insights/catalog.js';

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

  // Leitura dos logs da firewall (fonte fwflows). Opcional enquanto a fonte estiver desligada.
  ES_URL: z.string().url().optional(),
  ES_USER: z.string().default('soc_collector_es'),
  ES_PASSWORD_FILE: z.string().optional(),
  ES_CA_FILE: z.string().optional(),
  ES_REQUEST_TIMEOUT_MS: z.coerce.number().int().min(5_000).default(60_000),

  SOURCES_FILE: z.string().default('/app/config/sources.json'),
  QUERIES_DIR: z.string().default('/app/queries'),
  ASSETS_FILE: z.string().optional(),
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

const InventorySource = BaseSource.extend({
  type: z.literal('inventory'),
  table: z.literal('DeviceInfo').default('DeviceInfo'),
  queryFile: z.string().regex(/^[a-z0-9_.-]+\.kql$/).default('deviceinfo.kql'),
  maxRows: z.number().int().min(100).max(10_000).default(10_000),
});

const SnapshotSource = BaseSource.extend({
  type: z.literal('snapshot'),
  table: z.enum(['DeviceTvmSoftwareVulnerabilities', 'DeviceTvmSecureConfigurationAssessment', 'DeviceTvmSoftwareInventory']),
  queryFile: z.string().regex(/^[a-z0-9_.-]+\.kql$/),
  intervalSeconds: z.number().int().min(60).default(21600),
  maxRows: z.number().int().min(100).max(10_000).default(10_000),
  // Consultas por hash(DeviceId): cada parte respeita maxRows; o snapshot só vale com todas.
  partitions: z.number().int().min(1).max(64).default(1),
  // Expressão KQL do hash; deve incluir DeviceId e só colunas da identidade da linha.
  partitionBy: z.string().regex(/^[A-Za-z0-9_(), '|]+$/).refine((e) => e.includes('DeviceId'), 'partitionBy precisa incluir DeviceId').default('DeviceId'),
});

const InsightsSource = BaseSource.extend({
  type: z.literal('insights'),
  intervalSeconds: z.number().int().min(60).default(21600),
  vulnerabilitySource: z.string().default('snapshot.devicetvmsoftwarevulnerabilities'),
  configurationSource: z.string().default('snapshot.devicetvmsecureconfigurationassessment'),
  // null: sem avaliação de fim de suporte.
  softwareInventorySource: z.string().nullable().default('snapshot.devicetvmsoftwareinventory'),
});

// Catálogo de segurança do Windows Server (Security Update Guide, MSRC). Sem credencial.
const MsrcSource = BaseSource.extend({
  type: z.literal('msrc'),
  intervalSeconds: z.number().int().min(3600).default(43200),
  baseUrl: z.string().url().default('https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct'),
  products: z.array(z.string().regex(/^Windows Server [0-9A-Za-z ,.()-]+$/)).min(1),
  pageSize: z.number().int().min(50).max(1000).default(500),
  maxPages: z.number().int().min(1).max(500).default(100),
  requestTimeoutMs: z.number().int().min(5_000).default(120_000),
});

// Estado de atualização do Windows por servidor (Defender + catálogo MSRC).
const WinUpdatesSource = BaseSource.extend({
  type: z.literal('winupdates'),
  intervalSeconds: z.number().int().min(300).default(3600),
  namePrefix: z.string().min(1).default('srv'),
  msrcSource: z.string().default('msrc.windows-server'),
  vulnerabilitySource: z.string().default('snapshot.devicetvmsoftwarevulnerabilities'),
  deviceStaleHours: z.number().int().min(1).default(24),
  snapshotStaleHours: z.number().int().min(1).default(36),
  catalogStaleHours: z.number().int().min(1).default(48),
});

// Agregados por hora do tráfego da firewall, lidos do Elasticsearch (fw-logs-fortigate).
const Cidr = z.string().regex(/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/, 'CIDR IPv4 inválido');
const FwFlowsSource = BaseSource.extend({
  type: z.literal('fwflows'),
  intervalSeconds: z.number().int().min(300).default(3600),
  index: z.string().regex(/^[a-z0-9_.*-]+$/).default('fw-logs-fortigate'),
  // Logs chegam do FortiAnalyzer com atraso de segundos a minutos.
  lagMinutes: z.number().int().min(0).max(240).default(15),
  initialLookbackHours: z.number().int().min(1).max(720).default(24),
  recomputeHours: z.number().int().min(0).max(24).default(1),
  maxHoursPerRun: z.number().int().min(1).max(168).default(24),
  serverCidrs: z.array(Cidr).min(1).default(['172.16.159.0/24']),
  maxBucketsPerHour: z.number().int().min(100).max(200_000).default(50_000),
  retentionDays: z.number().int().min(1).max(400).default(30),
});

const ExpectedAsset = z.object({
  name: z.string().trim().min(1),
  id: z.string().trim().min(1).optional(),
  owner: z.string().trim().min(1).optional(),
  environment: z.string().trim().min(1).optional(),
  criticality: z.string().trim().min(1).optional(),
});

export type ExpectedAssetConfig = z.infer<typeof ExpectedAsset>;

export function parseAssets(raw: unknown): ExpectedAssetConfig[] {
  const assets = z.object({ assets: z.array(ExpectedAsset) }).parse(raw).assets;
  const ids = new Set<string>();
  const names = new Set<string>();
  for (const a of assets) {
    if (a.id && ids.has(a.id)) throw new Error(`DeviceId esperado duplicado: ${a.id}`);
    const name = a.name?.toLowerCase();
    if (name && names.has(name)) throw new Error(`nome esperado duplicado: ${a.name}`);
    if (a.id) ids.add(a.id);
    if (name) names.add(name);
  }
  return assets;
}

const SourcesFile = z.object({
  sources: z.array(z.discriminatedUnion('type', [ObjectSource, HuntingSource, InventorySource, SnapshotSource, InsightsSource, MsrcSource, WinUpdatesSource, FwFlowsSource])),
});

export type ObjectSourceConfig = z.infer<typeof ObjectSource>;
export type HuntingSourceConfig = z.infer<typeof HuntingSource> & { query: string };
export type InventorySourceConfig = z.infer<typeof InventorySource> & { query: string };
export type SnapshotSourceConfig = z.infer<typeof SnapshotSource> & { query: string };
export type InsightsSourceConfig = z.infer<typeof InsightsSource>;
export type MsrcSourceConfig = z.infer<typeof MsrcSource>;
export type WinUpdatesSourceConfig = z.infer<typeof WinUpdatesSource>;
export type FwFlowsSourceConfig = z.infer<typeof FwFlowsSource>;
export type SourceConfig = ObjectSourceConfig | HuntingSourceConfig | InventorySourceConfig | SnapshotSourceConfig | InsightsSourceConfig
  | MsrcSourceConfig | WinUpdatesSourceConfig | FwFlowsSourceConfig;

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
  elastic: ElasticConfig | null;
  sources: SourceConfig[];
  assets: ExpectedAssetConfig[];
  catalog: RemediationCatalog;
  logLevel: string;
  healthPort: number;
}

function readSecretFile(path: string, label: string): string {
  let value: string;
  try {
    value = readFileSync(path, 'utf8').trim();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    const hint =
      code === 'EISDIR'
        ? ' (o Docker cria um diretório quando o arquivo de origem não existe: apague o diretório em docker/secrets, crie o arquivo e recrie o container)'
        : '';
    throw new Error(`não foi possível ler ${label} em ${path}: ${(err as Error).message}${hint}`);
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
  const snapshotTables = new Set<string>();
  // Insights dependem de snapshots declarados da tabela correspondente.
  const snapshotOf = new Map(parsed.sources.filter((s) => s.type === 'snapshot').map((s) => [s.name, s.table]));
  for (const s of parsed.sources) {
    if (s.type !== 'insights') continue;
    const refs: Array<[string | null, string]> = [[s.vulnerabilitySource, 'DeviceTvmSoftwareVulnerabilities'],
      [s.configurationSource, 'DeviceTvmSecureConfigurationAssessment'], [s.softwareInventorySource, 'DeviceTvmSoftwareInventory']];
    for (const [ref, table] of refs) {
      if (ref !== null && snapshotOf.get(ref) !== table) throw new Error(`${s.name}: ${ref} não é snapshot declarado de ${table}`);
    }
  }
  for (const s of parsed.sources) {
    if (s.type === 'winupdates' && !parsed.sources.some((o) => o.type === 'msrc' && o.name === s.msrcSource)) {
      throw new Error(`${s.name}: ${s.msrcSource} não é fonte msrc declarada`);
    }
  }
  return parsed.sources.map((s) => {
    if (names.has(s.name)) throw new Error(`fonte duplicada: ${s.name}`);
    names.add(s.name);
    if (s.type === 'snapshot') {
      if (snapshotTables.has(s.table)) throw new Error(`snapshot duplicado para tabela: ${s.table}`);
      snapshotTables.add(s.table);
    }
    if (s.type !== 'hunting' && s.type !== 'inventory' && s.type !== 'snapshot') return s;
    if (s.type === 'hunting' && s.minWindowMinutes > s.maxWindowMinutes) {
      throw new Error(`${s.name}: minWindowMinutes maior que maxWindowMinutes`);
    }
    const query = readQuery(s.queryFile);
    if (s.type === 'snapshot' && s.partitions > 1 && !query.includes('{{partition}}')) {
      throw new Error(`${s.queryFile}: partitions > 1 exige o marcador {{partition}} na consulta`);
    }
    if (s.type === 'hunting' && (!query.includes('{{start}}') || !query.includes('{{end}}'))) {
      throw new Error(`${s.queryFile}: a consulta precisa conter {{start}} e {{end}}`);
    }
    // A primeira instrução precisa ler a tabela declarada; evita gravar eventos
    // de uma tabela com o nome de outra (ex.: ASR dentro de DeviceLogonEvents).
    const firstTable = /^\s*([A-Za-z]+)/.exec(query.replace(/\/\/[^\n]*/g, ''))?.[1];
    if (firstTable !== s.table) {
      throw new Error(`${s.queryFile}: a consulta lê "${firstTable ?? '?'}", mas a fonte ${s.name} declara a tabela "${s.table}"`);
    }
    return { ...s, query };
  });
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const e = EnvSchema.parse(env);
  const sourcesRaw: unknown = JSON.parse(readFileSync(e.SOURCES_FILE, 'utf8'));
  const sources = parseSources(sourcesRaw, (file) => readFileSync(join(e.QUERIES_DIR, file), 'utf8'));
  const assetsFile = e.ASSETS_FILE ?? join(dirname(e.SOURCES_FILE), 'assets.json');
  let assets: ExpectedAssetConfig[] = [];
  try {
    assets = parseAssets(JSON.parse(readFileSync(assetsFile, 'utf8')));
  } catch (err) {
    // Optional only when absent. A malformed/inaccessible existing file fails startup.
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  let catalog = EMPTY_CATALOG;
  try {
    catalog = parseCatalog(JSON.parse(readFileSync(join(dirname(e.SOURCES_FILE), 'remediation-catalog.json'), 'utf8')));
  } catch (err) {
    // Ausente: insights sem catálogo (configurações vão para investigação). Inválido: falha.
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  // Só exige o acesso ao Elasticsearch quando uma fonte fwflows está ligada.
  let elastic: ElasticConfig | null = null;
  if (e.ES_URL && e.ES_PASSWORD_FILE) {
    elastic = { url: e.ES_URL, user: e.ES_USER, password: readSecretFile(e.ES_PASSWORD_FILE, 'senha do Elasticsearch'),
      ...(e.ES_CA_FILE ? { ca: readFileSync(e.ES_CA_FILE, 'utf8') } : {}), requestTimeoutMs: e.ES_REQUEST_TIMEOUT_MS };
  } else if (sources.some((s) => s.type === 'fwflows' && s.enabled)) {
    throw new Error('fonte fwflows ligada sem ES_URL e ES_PASSWORD_FILE');
  }

  return {
    elastic,
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
    assets,
    catalog,
    logLevel: e.LOG_LEVEL,
    healthPort: e.HEALTH_PORT,
  };
}
