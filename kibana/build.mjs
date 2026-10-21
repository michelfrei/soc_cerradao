// Gera os objetos do Kibana (data views e dashboards Lens) e o pacote de regras
// de detecção em NDJSON, prontos para importação pelo kibana/setup.sh.
//
// Uso: node kibana/build.mjs          (gera kibana/dist/*.ndjson)
//      node kibana/build.mjs --check  (falha se dist/ estiver desatualizado)
//
// Os objetos usam o formato salvo da 8.9; o Kibana migra na importação.
import { readFileSync, readdirSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const DIST = join(ROOT, 'dist');
const CHECK = process.argv.includes('--check');

// Data views ---------------------------------------------------------------------

const DATA_VIEWS = [
  { id: 'soc-events', title: 'soc-events-*', name: 'SOC - Eventos' },
  { id: 'soc-incidents', title: 'soc-incidents', name: 'SOC - Incidentes Defender - estado conhecido', timeless: true },
  { id: 'soc-alerts', title: 'soc-alerts', name: 'SOC - Alertas Defender - estado conhecido', timeless: true },
  { id: 'soc-alerts-timeline', title: 'soc-alerts', name: 'SOC - Alertas Defender - última atualização' },
  { id: 'soc-history', title: 'soc-*-history-*', name: 'SOC - Histórico' },
  { id: 'soc-devices', title: 'soc-devices', name: 'SOC - Inventário conhecido', timeless: true },
  { id: 'soc-metrics', title: 'soc-metrics-*', name: 'SOC - Coleta e capacidade' },
  { id: 'soc-elastic-alerts', title: '.alerts-security.alerts-soc', name: 'SOC - Alertas de detecção Elastic' },
];

const dataViewObjects = DATA_VIEWS.map((d) => ({
  type: 'index-pattern',
  id: d.id,
  attributes: { title: d.title, name: d.name, ...(!d.timeless ? { timeFieldName: '@timestamp' } : {}) },
  references: [],
  coreMigrationVersion: '8.8.0',
  typeMigrationVersion: '8.0.0',
}));

// Colunas Lens ---------------------------------------------------------------------

// Lens conserva o tipo do campo em termos, inclusive boolean e ip (Kibana 9.5).
const TERM_TYPES = {
  'soc.asset.expected': 'boolean', 'soc.asset.observed': 'boolean',
  'source.ip': 'ip', 'destination.ip': 'ip',
};

const col = {
  date: (label = '@timestamp') => ({
    label, dataType: 'date', operationType: 'date_histogram', sourceField: '@timestamp',
    isBucketed: true, scale: 'interval', params: { interval: 'auto', includeEmptyRows: true, dropPartials: false },
  }),
  count: (label = 'Eventos') => ({
    label, customLabel: true, dataType: 'number', operationType: 'count', sourceField: '___records___',
    isBucketed: false, scale: 'ratio', params: { emptyAsNull: false },
  }),
  unique: (field, label) => ({
    label, customLabel: true, dataType: 'number', operationType: 'unique_count', sourceField: field,
    isBucketed: false, scale: 'ratio', params: { emptyAsNull: false },
  }),
  last: (field, label) => ({
    label, customLabel: true, dataType: 'number', operationType: 'last_value', sourceField: field,
    isBucketed: false, scale: 'ratio', params: { sortField: '@timestamp', showArrayValues: false },
    filter: { query: `${field} : *`, language: 'kuery' },
  }),
  terms: (field, label, size, orderBy, missingBucket = false) => ({
    label, customLabel: true, dataType: TERM_TYPES[field] || 'string', operationType: 'terms', sourceField: field,
    isBucketed: true, scale: 'ordinal',
    params: {
      size, orderBy: { type: 'column', columnId: orderBy }, orderDirection: 'desc',
      otherBucket: false, missingBucket, parentFormat: { id: 'terms' },
    },
  }),
};

// Visualizações ---------------------------------------------------------------------

const LAYER = 'layer1';

/**
 * Cria um objeto Lens.
 * columns: [[id, coluna], ...] na ordem desejada (agrupamentos antes das métricas).
 */
function lens(id, title, dataView, query, visualizationType, columns, visualization) {
  return {
    type: 'lens',
    id,
    attributes: {
      title,
      description: '',
      visualizationType,
      state: {
        datasourceStates: {
          formBased: {
            layers: {
              [LAYER]: {
                columnOrder: columns.map(([cid]) => cid),
                columns: Object.fromEntries(columns),
                incompleteColumns: {},
              },
            },
          },
        },
        visualization,
        query: { query, language: 'kuery' },
        filters: [],
        internalReferences: [],
        adHocDataViews: {},
      },
    },
    references: [{ type: 'index-pattern', id: dataView, name: `indexpattern-datasource-layer-${LAYER}` }],
    coreMigrationVersion: '8.8.0',
    typeMigrationVersion: '8.9.0',
  };
}

const metric = (id, title, dataView, query, c = col.count(title)) =>
  lens(id, title, dataView, query, 'lnsMetric', [['m', c]], { layerId: LAYER, layerType: 'data', metricAccessor: 'm' });

const donut = (id, title, dataView, query, field, label, size = 8) =>
  lens(id, title, dataView, query, 'lnsPie',
    [['g', col.terms(field, label, size, 'm')], ['m', col.count()]],
    {
      shape: 'donut',
      layers: [{
        layerId: LAYER, layerType: 'data', primaryGroups: ['g'], metrics: ['m'],
        numberDisplay: 'percent', categoryDisplay: 'default', legendDisplay: 'default', nestedLegend: false,
      }],
    });

function xy(seriesType, layer) {
  return {
    legend: { isVisible: true, position: 'right' },
    valueLabels: 'hide',
    fittingFunction: 'None',
    preferredSeriesType: seriesType,
    axisTitlesVisibilitySettings: { x: false, yLeft: false, yRight: true },
    gridlinesVisibilitySettings: { x: true, yLeft: true, yRight: true },
    tickLabelsVisibilitySettings: { x: true, yLeft: true, yRight: true },
    layers: [{ layerId: LAYER, layerType: 'data', seriesType, showGridlines: false, position: 'top', ...layer }],
  };
}

/** Barras empilhadas no tempo, divididas por um campo. */
const timeline = (id, title, dataView, query, splitField, splitLabel, size = 8) =>
  lens(id, title, dataView, query, 'lnsXY',
    [['s', col.terms(splitField, splitLabel, size, 'm')], ['x', col.date()], ['m', col.count()]],
    xy('bar_stacked', { xAccessor: 'x', accessors: ['m'], splitAccessor: 's' }));

/** Snapshots de capacidade: último valor em cada bucket, sem acumular amostras. */
function capacityTrend(id, title, query, fields) {
  const columns = [['x', col.date()], ...fields.map(([field, label], i) => [`m${i}`, col.last(field, label)])];
  return lens(id, title, 'soc-metrics', query, 'lnsXY', columns,
    xy('line', { xAccessor: 'x', accessors: fields.map((_, i) => `m${i}`) }));
}

/** Ranking horizontal de um campo, opcionalmente dividido por outro. */
function ranking(id, title, dataView, query, field, label, size = 10, split) {
  const columns = [['y', col.terms(field, label, size, 'm')]];
  if (split) columns.push(['s', col.terms(split.field, split.label, 5, 'm')]);
  columns.push(['m', col.count()]);
  return lens(id, title, dataView, query, 'lnsXY', columns,
    xy('bar_horizontal_stacked', { xAccessor: 'y', accessors: ['m'], ...(split ? { splitAccessor: 's' } : {}) }));
}

/** Tabela: agrupamentos [campo, rótulo, tamanho] e métricas extras. */
function table(id, title, dataView, query, groups, extraMetrics = [], orderBy = 'm') {
  const metrics = [['m', col.count()], ...extraMetrics];
  const columns = [
    // Em tabelas, linhas sem o campo (ex.: incidente sem responsável) também aparecem.
    ...groups.map(([field, label, size], i) => [`g${i}`, col.terms(field, label, size, orderBy, true)]),
    ...metrics,
  ];
  return lens(id, title, dataView, query, 'lnsDatatable', columns, {
    layerId: LAYER, layerType: 'data', columns: columns.map(([columnId]) => ({ columnId })),
  });
}

// Dashboards ---------------------------------------------------------------------

/** Painel de texto (Markdown) embutido no dashboard. */
const markdown = (text) => ({
  kind: 'markdown',
  embeddableConfig: {
    hidePanelTitles: true,
    enhancements: {},
    savedVis: {
      title: '', description: '', type: 'markdown', uiState: {},
      params: { fontSize: 12, openLinksInNewTab: false, markdown: text },
      data: { aggs: [], searchSource: { query: { query: '', language: 'kuery' }, filter: [] } },
    },
  },
});

/**
 * panels: [[objeto Lens | markdown, x, y, w, h], ...] numa grade de 48 colunas.
 */
function dashboard(id, title, description, panels, timeFrom = 'now-7d') {
  const references = [];
  const panelsJSON = panels.map(([obj, x, y, w, h], i) => {
    const panelIndex = `p${i + 1}`;
    const gridData = { x, y, w, h, i: panelIndex };
    if (obj.kind === 'markdown') {
      return { type: 'visualization', gridData, panelIndex, embeddableConfig: obj.embeddableConfig };
    }
    references.push({ name: `${panelIndex}:panel_${panelIndex}`, type: obj.type, id: obj.id });
    // Cartões de métrica já exibem o rótulo; o título do painel ficaria duplicado.
    const hidePanelTitles = obj.attributes.visualizationType === 'lnsMetric';
    return {
      type: obj.type, gridData, panelIndex,
      embeddableConfig: { enhancements: {}, ...(hidePanelTitles ? { hidePanelTitles: true } : {}) },
      panelRefName: `panel_${panelIndex}`,
    };
  });
  return {
    type: 'dashboard',
    id,
    attributes: {
      title,
      description,
      timeRestore: true,
      timeFrom,
      timeTo: 'now',
      refreshInterval: { pause: false, value: 300000 },
      optionsJSON: JSON.stringify({ useMargins: true, syncColors: false, syncCursor: true, syncTooltips: false, hidePanelTitles: false }),
      panelsJSON: JSON.stringify(panelsJSON),
      kibanaSavedObjectMeta: { searchSourceJSON: JSON.stringify({ query: { query: '', language: 'kuery' }, filter: [] }) },
    },
    references,
    coreMigrationVersion: '8.8.0',
    typeMigrationVersion: '8.9.0',
  };
}

// Escopo: somente nomes de servidores do piloto. Dados antigos permanecem retidos.
const SERVER = '(host.name : (*srv* or *fisico*) and not host.name : (*note* or *micro*))';
const LOGON = `${SERVER} and event.dataset : "defender.devicelogonevents"`;
const IDENTITY = `${LOGON} and soc.identity.correlation_key : * and host.id : *`;
const ACCOUNT = `${IDENTITY} and not soc.identity.type : ("machine" or "system")`;
const ASR = `${SERVER} and event.dataset : "defender.deviceevents" and soc.asr.rule : *`;
const ACTIVE = 'not soc.object.status : "resolved"';
const COLLECTOR = 'event.dataset : "soc.collector_status" and soc.metrics.source : *';
const DATABASE = 'event.dataset : "soc.database_capacity" and soc.metrics.source : "database.capacity"';
const ELASTIC = 'event.dataset : "soc.elasticsearch_capacity" and soc.metrics.source : "elasticsearch.capacity"';
const ASSET = SERVER;

function search(id, title, dataView, query, columns) {
  return {
    type: 'search', id,
    attributes: { title, description: 'Documentos detalhados; abra no Discover e filtre pelos campos canônicos.',
      columns, sort: [['@timestamp', 'desc']],
      kibanaSavedObjectMeta: { searchSourceJSON: JSON.stringify({ query: { query, language: 'kuery' },
        filter: [], indexRefName: 'kibanaSavedObjectMeta.searchSourceJSON.index' }) } },
    references: [{ name: 'kibanaSavedObjectMeta.searchSourceJSON.index', type: 'index-pattern', id: dataView }],
    coreMigrationVersion: '8.8.0', typeMigrationVersion: '8.0.0',
  };
}
const NAV_ITEMS = [
  ['soc-dashboard-overview', 'Visão operacional'], ['soc-dashboard-acessos', 'Identidades e acessos'],
  ['soc-dashboard-servidor', 'Investigar servidor'], ['soc-dashboard-asr', 'ASR'],
  ['soc-dashboard-cobertura', 'Cobertura e capacidade'],
];
const nav = () => markdown(NAV_ITEMS.map(([id, title]) => `[${title}](/s/soc/app/dashboards#/view/${id})`).join(' · ') +
  '\n\n**Escopo:** nome contém srv ou fisico, exclui note ou micro. Para correlacionar, filtre por **host.id** e **soc.identity.correlation_key**. ' +
  'Fixe os filtros que deseja manter ao navegar; os links permanecem no espaço SOC. ' +
  '[Discover](/s/soc/app/discover) · [Alertas Elastic](/s/soc/app/security/alerts)');
const known = 'Estado conhecido no Defender; totais ignoram o seletor de tempo e não comprovam atualização recente.';
const ov = {
  incidents: metric('soc-ov-incidents-active', 'Incidentes Defender ativos — estado conhecido', 'soc-incidents', ACTIVE),
  alerts: metric('soc-ov-alerts-active', 'Alertas Defender ativos — estado conhecido', 'soc-alerts', ACTIVE),
  elastic: metric('soc-ov-elastic-alerts', 'Alertas Elastic — período selecionado', 'soc-elastic-alerts', ''),
  bySeverity: donut('soc-ov-incidents-severity', 'Incidentes Defender ativos por severidade — estado conhecido', 'soc-incidents', ACTIVE,
    'soc.object.severity', 'Severidade'),
  alertsBySource: timeline('soc-ov-alerts-source', 'Alertas Defender por última atualização conhecida', 'soc-alerts-timeline', '',
    'soc.object.service_source', 'Produto'),
  incidentsTable: table('soc-ov-incidents-table', 'Ranking de incidentes Defender ativos — estado conhecido', 'soc-incidents', ACTIVE, [
    ['soc.object.id', 'ID do incidente', 50], ['soc.object.title.keyword', 'Título', 1],
    ['soc.object.severity', 'Severidade', 1], ['soc.object.assigned_to', 'Responsável', 1],
  ]),
  elasticRules: ranking('soc-ov-elastic-rules', 'Top 10 regras com alertas Elastic no período', 'soc-elastic-alerts', '',
    'kibana.alert.rule.name', 'Regra', 10),
};
const ac = {
  ok: metric('soc-ac-success', 'Logons com sucesso', 'soc-events', `${LOGON} and event.outcome : "success"`),
  fail: metric('soc-ac-failure', 'Eventos de falha de logon', 'soc-events', `${LOGON} and event.outcome : "failure"`),
  hosts: metric('soc-ac-hosts', 'Servidores com logon observado', 'soc-events', IDENTITY, col.unique('host.id', 'Servidores distintos')),
  users: metric('soc-ac-users', 'Identidades correlacionáveis', 'soc-events', ACCOUNT, col.unique('soc.identity.correlation_key', 'Identidades distintas')),
  timeline: timeline('soc-ac-timeline', 'Logons no período por resultado', 'soc-events', LOGON, 'event.outcome', 'Resultado', 3),
  types: donut('soc-ac-types', 'Classificação de identidades observadas', 'soc-events', IDENTITY, 'soc.identity.type', 'Classificação'),
  scopes: donut('soc-ac-scopes', 'Escopo das identidades observadas', 'soc-events', IDENTITY, 'soc.identity.scope', 'Escopo'),
  confidence: donut('soc-ac-confidence', 'Base da correlação de identidade', 'soc-events', IDENTITY, 'soc.identity.confidence', 'Evidência'),
  spread: table('soc-ac-spread', 'Top 30 identidades por servidores distintos — rede e RDP', 'soc-events',
    `${ACCOUNT} and event.outcome : "success" and winlog.logon.type : ("Network" or "RemoteInteractive")`,
    [['soc.identity.correlation_key', 'Chave da identidade', 30], ['soc.identity.display', 'Conta exibida', 1]],
    [['u', col.unique('host.id', 'Servidores distintos')]], 'u'),
  localAdmin: table('soc-ac-local-admin', 'Top 30 contas com privilégio local observado', 'soc-events',
    `${IDENTITY} and soc.identity.is_local_admin : true`, [
      ['soc.identity.correlation_key', 'Identidade', 30], ['soc.identity.display', 'Conta', 1], ['host.id', 'Servidor ID', 10],
      ['host.name', 'Nome', 1], ['soc.identity.scope', 'Escopo', 1],
    ]),
  matrix: table('soc-ac-account-host-matrix', 'Matriz de acessos — top 20 identidades × até 10 servidores por identidade', 'soc-events',
    IDENTITY, [['soc.identity.correlation_key', 'Identidade canônica', 20], ['host.id', 'Servidor ID', 10]],
    [['ok', { ...col.count('Sucessos observados'), filter: { query: 'event.outcome : "success"', language: 'kuery' } }],
      ['fail', { ...col.count('Falhas observadas'), filter: { query: 'event.outcome : "failure"', language: 'kuery' } }]]),
};
const srv = {
  events: metric('soc-server-events', 'Eventos observados no período', 'soc-events', SERVER),
  accounts: metric('soc-server-identities', 'Identidades correlacionáveis', 'soc-events', IDENTITY, col.unique('soc.identity.correlation_key', 'Identidades')),
  failures: metric('soc-server-failures', 'Falhas de logon observadas', 'soc-events', `${LOGON} and event.outcome : "failure"`),
  timeline: timeline('soc-server-timeline', 'Atividade por conjunto de dados', 'soc-events', SERVER, 'event.dataset', 'Fonte'),
  rdp: table('soc-server-rdp', 'Top 30 caminhos RDP — origem, servidor e identidade', 'soc-events',
    `${IDENTITY} and winlog.logon.type : "RemoteInteractive"`, [
      ['host.id', 'Servidor ID', 30], ['host.name', 'Nome', 1], ['soc.identity.correlation_key', 'Identidade', 20],
      ['soc.identity.display', 'Conta', 1], ['source.ip', 'IP de origem', 10], ['event.outcome', 'Resultado', 2],
    ]),
  failuresTable: table('soc-server-failure-reasons', 'Top 30 identidades com falhas por servidor e motivo', 'soc-events',
    `${IDENTITY} and event.outcome : "failure"`, [
      ['soc.identity.correlation_key', 'Identidade', 30], ['host.id', 'Servidor ID', 20], ['event.reason', 'Motivo', 5],
    ]),
};
const asr = {
  block: metric('soc-asr-block', 'Eventos ASR em bloqueio', 'soc-events', `${ASR} and soc.asr.mode : "block"`),
  audit: metric('soc-asr-audit', 'Eventos ASR em auditoria', 'soc-events', `${ASR} and soc.asr.mode : "audit"`),
  hosts: metric('soc-asr-hosts', 'Servidores com ASR observado', 'soc-events', ASR, col.unique('host.id', 'Servidores distintos')),
  timeline: timeline('soc-asr-timeline', 'Eventos ASR por regra no período', 'soc-events', ASR, 'soc.asr.rule', 'Regra ASR'),
  rules: ranking('soc-asr-rules', 'Top 15 regras ASR por modo', 'soc-events', ASR, 'soc.asr.rule', 'Regra ASR', 15,
    { field: 'soc.asr.mode', label: 'Modo' }),
  hostsTable: table('soc-asr-hosts-table', 'Top 30 servidores por regra ASR e processo', 'soc-events', ASR, [
    ['host.id', 'Servidor ID', 30], ['host.name', 'Nome', 1], ['soc.asr.rule', 'Regra', 10],
    ['soc.asr.mode', 'Modo', 3], ['process.name', 'Processo de origem', 10],
  ]),
};
const cap = {
  expected: metric('soc-cap-expected', 'Servidores cadastrados como esperados', 'soc-devices', `${ASSET} and soc.asset.expected : true`),
  observed: metric('soc-cap-observed', 'Servidores conhecidos no Defender', 'soc-devices', `${ASSET} and soc.asset.observed : true`),
  missing: metric('soc-cap-missing', 'Esperados sem observação no Defender', 'soc-devices', `${ASSET} and soc.asset.expected : true and not soc.asset.observed : true`),
  assets: table('soc-cap-assets', 'Inventário conhecido — até 100 servidores; detalhe no Discover', 'soc-devices', ASSET, [
    ['host.id', 'Servidor ID', 100], ['host.name', 'Nome', 1], ['soc.asset.expected', 'Esperado', 2],
    ['soc.asset.observed', 'Observado', 2], ['soc.asset.sensor_health', 'Saúde do sensor', 1],
    ['soc.asset.onboarding_status', 'Onboarding', 1], ['soc.asset.owner', 'Responsável', 1],
    ['soc.asset.environment', 'Ambiente', 1], ['soc.asset.criticality', 'Criticidade', 1],
  ]),
  collection: table('soc-cap-collection', 'Última amostra de coleta por fonte no período', 'soc-metrics', COLLECTOR,
    [['soc.metrics.source', 'Fonte', 30]], [
      ['lag', col.last('soc.metrics.lag_seconds', 'Atraso (s)')],
      ['duration', col.last('soc.metrics.duration_ms', 'Duração (ms)')],
      ['fetched', col.last('soc.metrics.fetched', 'Recebidos na execução')],
      ['inserted', col.last('soc.metrics.inserted', 'Inseridos na execução')],
      ['changed', col.last('soc.metrics.changed', 'Alterados na execução')],
      ['calls', col.last('soc.metrics.api_calls', 'Chamadas na execução')],
      ['throttle', col.last('soc.metrics.throttled', 'Throttles na execução')],
    ]),
  db: metric('soc-cap-database', 'PostgreSQL — banco (bytes, última amostra)', 'soc-metrics', DATABASE,
    col.last('soc.metrics.database_bytes', 'Banco (bytes)')),
  raw: metric('soc-cap-raw', 'PostgreSQL — eventos (bytes, última amostra)', 'soc-metrics', DATABASE,
    col.last('soc.metrics.raw_bytes', 'Eventos (bytes)')),
  publication: metric('soc-cap-publication', 'PostgreSQL — publicação (bytes, última amostra)', 'soc-metrics', DATABASE,
    col.last('soc.metrics.publication_bytes', 'Publicação (bytes)')),
  history: metric('soc-cap-history', 'PostgreSQL — versões (bytes, última amostra)', 'soc-metrics', DATABASE,
    col.last('soc.metrics.history_bytes', 'Versões (bytes)')),
  heap: metric('soc-cap-es-heap', 'ES — heap usado (bytes, última amostra)', 'soc-metrics', ELASTIC,
    col.last('soc.metrics.elastic_heap_used_bytes', 'Heap usado (bytes)')),
  heapMax: metric('soc-cap-es-heap-max', 'ES — heap máximo (bytes, última amostra)', 'soc-metrics', ELASTIC,
    col.last('soc.metrics.elastic_heap_max_bytes', 'Heap máximo (bytes)')),
  disk: metric('soc-cap-es-disk', 'ES — disco disponível (bytes, última amostra)', 'soc-metrics', ELASTIC,
    col.last('soc.metrics.elastic_fs_available_bytes', 'Disco disponível (bytes)')),
  diskTotal: metric('soc-cap-es-disk-total', 'ES — disco total (bytes, última amostra)', 'soc-metrics', ELASTIC,
    col.last('soc.metrics.elastic_fs_total_bytes', 'Disco total (bytes)')),
  cpu: metric('soc-cap-es-cpu', 'ES — CPU do processo (%, última amostra)', 'soc-metrics', ELASTIC,
    col.last('soc.metrics.elastic_cpu_percent', 'CPU processo ES (%)')),
  store: metric('soc-cap-es-store', 'ES — armazenamento de índices (bytes)', 'soc-metrics', ELASTIC,
    col.last('soc.metrics.elastic_store_bytes', 'Índices (bytes)')),
  dbTrend: capacityTrend('soc-cap-pg-trend', 'Evolução PostgreSQL — último snapshot por intervalo (bytes)', DATABASE, [
    ['soc.metrics.database_bytes', 'Banco total'], ['soc.metrics.raw_bytes', 'Eventos'],
    ['soc.metrics.publication_bytes', 'Publicação'], ['soc.metrics.history_bytes', 'Versões'],
  ]),
  esTrend: capacityTrend('soc-cap-es-trend', 'Evolução Elasticsearch — último snapshot por intervalo (bytes)', ELASTIC, [
    ['soc.metrics.elastic_heap_used_bytes', 'Heap usado'], ['soc.metrics.elastic_store_bytes', 'Índices'],
    ['soc.metrics.elastic_fs_available_bytes', 'Disco disponível'],
  ]),
};
const detailSearches = [
  search('soc-search-logons', 'Logons detalhados — abrir no Discover para investigar', 'soc-events', LOGON,
    ['@timestamp', 'host.name', 'host.id', 'soc.identity.display', 'soc.identity.correlation_key', 'soc.identity.key', 'user.id', 'soc.identity.type',
      'soc.identity.scope', 'soc.identity.confidence', 'source.ip', 'winlog.logon.type', 'event.outcome', 'event.reason']),
  search('soc-search-server', 'Eventos detalhados do servidor — filtre host.id', 'soc-events', SERVER,
    ['@timestamp', 'host.name', 'host.id', 'event.dataset', 'event.action', 'soc.identity.display',
      'soc.identity.correlation_key', 'soc.identity.key', 'user.id', 'source.ip', 'process.name', 'process.command_line']),
  search('soc-search-asr', 'ASR detalhado — processo, arquivo e identidade', 'soc-events', ASR,
    ['@timestamp', 'host.name', 'soc.asr.rule', 'soc.asr.mode', 'soc.identity.display', 'soc.identity.correlation_key',
      'soc.identity.key', 'user.id', 'process.name', 'process.command_line', 'process.parent.name', 'file.path', 'file.hash.sha256']),
  search('soc-search-collection', 'Execuções de coleta — status e horário reais', 'soc-metrics', COLLECTOR,
    ['@timestamp', 'soc.metrics.source', 'soc.metrics.status', 'soc.metrics.finished_at', 'soc.metrics.lag_seconds',
      'soc.metrics.duration_ms', 'soc.metrics.fetched', 'soc.metrics.inserted', 'soc.metrics.api_calls', 'soc.metrics.throttled']),
  search('soc-search-assets', 'Cadastro e estado dos sensores — documentos detalhados', 'soc-devices', ASSET,
    ['host.name', 'host.id', 'soc.asset.expected', 'soc.asset.observed', 'soc.asset.owner',
      'soc.asset.environment', 'soc.asset.criticality', 'soc.asset.onboarding_status', 'soc.asset.sensor_health',
      'soc.asset.device_type', 'soc.asset.machine_group', 'soc.asset.os_platform', 'soc.asset.last_seen', 'soc.asset.snapshot_at']),
];
detailSearches[4].attributes.sort = [['soc.asset.last_seen', 'desc']];
const lensObjects = [...Object.values(ov), ...Object.values(ac), ...Object.values(srv), ...Object.values(asr), ...Object.values(cap)];
const dashboards = [
  dashboard('soc-dashboard-overview', 'SOC - Visão operacional', known, [
    [nav(), 0, 0, 48, 5], [markdown(`**${known}** Os incidentes/alertas Defender abrangem o tenant; o escopo de servidores é aplicado aos eventos e ao inventário. Alertas Elastic são detecções executadas neste espaço SOC e obedecem ao período selecionado.`), 0, 5, 48, 5],
    [ov.incidents, 0, 10, 16, 8], [ov.alerts, 16, 10, 16, 8], [ov.elastic, 32, 10, 16, 8],
    [ov.bySeverity, 0, 18, 16, 15], [ov.alertsBySource, 16, 18, 32, 15],
    [ov.incidentsTable, 0, 33, 48, 17], [ov.elasticRules, 0, 50, 48, 15],
  ], 'now-30d'),
  dashboard('soc-dashboard-acessos', 'SOC - Identidades e acessos', 'Contas por identidade canônica; nomes iguais não são mesclados.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Identidade:** use a chave canônica para correlacionar, domínio/usuário apenas para apresentação. Conta sem classificação permanece **unknown**; ausência de $ não comprova pessoa. Local admin significa privilégio observado no evento, não inventário completo do grupo Administradores. Contagens são documentos; relatórios agregados podem representar várias tentativas.'), 0, 5, 48, 6],
    [ac.ok, 0, 11, 12, 8], [ac.fail, 12, 11, 12, 8], [ac.hosts, 24, 11, 12, 8], [ac.users, 36, 11, 12, 8],
    [ac.timeline, 0, 19, 48, 14], [ac.types, 0, 33, 16, 14], [ac.scopes, 16, 33, 16, 14], [ac.confidence, 32, 33, 16, 14],
    [ac.spread, 0, 47, 48, 17], [ac.localAdmin, 0, 64, 48, 17],
    [ac.matrix, 0, 81, 48, 18], [detailSearches[0], 0, 99, 48, 20],
  ]),
  dashboard('soc-dashboard-servidor', 'SOC - Investigação por servidor', 'Filtre host.id e, opcionalmente, soc.identity.correlation_key para seguir uma conta.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Comece pelo servidor:** adicione um filtro `host.id` pelo botão de filtro ou clique no ID de uma tabela. Depois filtre `soc.identity.correlation_key` para acompanhar a mesma identidade. O nome do servidor pode mudar; o ID é a referência. Sem filtro, este painel mostra todos os servidores do escopo. Nas tabelas detalhadas, use **Abrir no Discover** para ampliar colunas e consultar o registro original.'), 0, 5, 48, 6],
    [srv.events, 0, 11, 16, 8], [srv.accounts, 16, 11, 16, 8], [srv.failures, 32, 11, 16, 8],
    [srv.timeline, 0, 19, 48, 14], [srv.rdp, 0, 33, 48, 18], [srv.failuresTable, 0, 51, 48, 16],
    [detailSearches[1], 0, 67, 48, 20],
  ]),
  dashboard('soc-dashboard-asr', 'SOC - ASR', 'Atividades ASR observadas nos servidores do escopo.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Eventos observados:** ASR pode registrar amostras; contagens não são total de tentativas. Auditoria indica que a regra teria bloqueado; bloqueio indica ação registrada pelo Defender. Correlacione host.id, identidade, processo e hash antes de concluir comprometimento.'), 0, 5, 48, 5],
    [asr.block, 0, 10, 16, 8], [asr.audit, 16, 10, 16, 8], [asr.hosts, 32, 10, 16, 8],
    [asr.timeline, 0, 18, 48, 14], [asr.rules, 0, 32, 48, 16], [asr.hostsTable, 0, 48, 48, 17],
    [detailSearches[2], 0, 65, 48, 20],
  ]),
  dashboard('soc-dashboard-cobertura', 'SOC - Cobertura e capacidade', 'Inventário conhecido, execução do coletor e capacidade dos serviços.', [
    [nav(), 0, 0, 48, 5],
    [markdown(`**Cobertura:** se “esperados” = 0, a situação é **SEM CADASTRO**, nunca 100%. Defender conhecido não é inventário total da empresa. Compare esperados com observados e valide saúde/último contato. Inventário é estado atual sem corte temporal.

**Capacidade:** cartões usam última amostra do período, não soma de snapshots. Confira o horário em Discover; vazio significa sem amostra. Métricas ES são do nó/processo ES; não representam CPU/RAM das VMs ou dos servidores monitorados. Não há coleta automática de CPU/RAM dos hosts nesta rodada.`), 0, 5, 48, 8],
    [cap.expected, 0, 13, 16, 8], [cap.observed, 16, 13, 16, 8], [cap.missing, 32, 13, 16, 8],
    [cap.assets, 0, 21, 48, 20], [cap.collection, 0, 41, 48, 18],
    [cap.db, 0, 59, 12, 8], [cap.raw, 12, 59, 12, 8], [cap.publication, 24, 59, 12, 8], [cap.history, 36, 59, 12, 8],
    [cap.heap, 0, 67, 16, 8], [cap.heapMax, 16, 67, 16, 8], [cap.cpu, 32, 67, 16, 8],
    [cap.disk, 0, 75, 16, 8], [cap.diskTotal, 16, 75, 16, 8], [cap.store, 32, 75, 16, 8],
    [cap.dbTrend, 0, 83, 48, 15], [cap.esTrend, 0, 98, 48, 15],
    [detailSearches[3], 0, 113, 48, 20], [detailSearches[4], 0, 133, 48, 20],
  ], 'now-24h'),
];

// Regras de detecção ---------------------------------------------------------------------

const RULES_DIR = join(ROOT, 'rules');
const rules = existsSync(RULES_DIR)
  ? readdirSync(RULES_DIR).filter((f) => f.endsWith('.json')).sort().map((f) => {
      const rule = JSON.parse(readFileSync(join(RULES_DIR, f), 'utf8'));
      if (`${rule.rule_id}.json` !== f) throw new Error(`${f}: rule_id "${rule.rule_id}" deve ser igual ao nome do arquivo`);
      return rule;
    })
  : [];

// Saída ----------------------------------------------------------------------------------

const outputs = {
  'objects.ndjson': [...dataViewObjects, ...lensObjects, ...detailSearches, ...dashboards],
  'rules.ndjson': rules,
};

const ids = new Set();
for (const o of outputs['objects.ndjson']) {
  const key = `${o.type}:${o.id}`;
  if (ids.has(key)) throw new Error(`id duplicado: ${key}`);
  ids.add(key);
}

let stale = false;
mkdirSync(DIST, { recursive: true });
for (const [file, objects] of Object.entries(outputs)) {
  const content = objects.map((o) => JSON.stringify(o)).join('\n') + (objects.length ? '\n' : '');
  const path = join(DIST, file);
  if (CHECK) {
    const current = existsSync(path) ? readFileSync(path, 'utf8') : '';
    if (current !== content) {
      console.error(`${file} desatualizado: rode node kibana/build.mjs`);
      stale = true;
    }
  } else {
    writeFileSync(path, content);
    console.log(`${file}: ${objects.length} objetos`);
  }
}
if (stale) process.exit(1);
