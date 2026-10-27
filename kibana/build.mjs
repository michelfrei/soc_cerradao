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
  { id: 'soc-posture', title: 'soc-posture', name: 'SOC - Postura atual TVM', timeless: true },
  { id: 'soc-insights', title: 'soc-insights', name: 'SOC - Insights de remediação', timeless: true },
  { id: 'soc-windows-updates', title: 'soc-windows-updates', name: 'SOC - Atualização do Windows (estado atual)', timeless: true },
  { id: 'soc-windows-updates-history', title: 'soc-windows-updates-history-*', name: 'SOC - Atualização do Windows (histórico diário)' },
  { id: 'soc-metrics', title: 'soc-metrics-*', name: 'SOC - Coleta e capacidade' },
  { id: 'soc-metrics-current', title: 'soc-metrics-*', name: 'SOC - Últimas execuções sem corte temporal', timeless: true },
  { id: 'soc-elastic-alerts', title: '.alerts-security.alerts-soc', name: 'SOC - Alertas de detecção Elastic' },
  // Logs brutos da firewall: dado pessoal, leitura só para soc_admin e soc_analyst.
  { id: 'fw-logs', title: 'fw-logs-*', name: 'SOC - Firewall (logs do FortiGate)' },
  { id: 'soc-fw-flows', title: 'soc-fw-flows-*', name: 'SOC - Firewall (agregados por hora)' },
  { id: 'soc-fw-sessions-state', title: 'soc-fw-sessions', name: 'SOC - Firewall (sessões de VPN e administração)', timeless: true },
];

const dataViewObjects = DATA_VIEWS.map((d) => ({
  type: 'index-pattern',
  id: d.id,
  attributes: { title: d.title, name: d.name, ...(!d.timeless ? { timeFieldName: '@timestamp' } : {}),
    ...(['soc-events', 'soc-devices', 'soc-posture'].includes(d.id) ? { fieldFormatMap: JSON.stringify({
      'host.id': { id: 'url', params: { type: 'link', labelTemplate: '{{value}}',
        urlTemplate: `/s/soc/app/discover#/?_a=(index:'${d.id}',query:(language:kuery,query:'${d.id === 'soc-posture' ? 'soc.posture.active%20:%20true%20and%20' : ''}host.id%20:%20%22{{value}}%22'))`,
        openLinkInCurrentTab: false } },
    }) } : {}) },
  references: [],
  coreMigrationVersion: '8.8.0',
  typeMigrationVersion: '8.0.0',
}));

// Colunas Lens ---------------------------------------------------------------------

// Lens conserva o tipo do campo em termos, inclusive boolean e ip (Kibana 9.5).
const TERM_TYPES = {
  'soc.asset.expected': 'boolean', 'soc.asset.observed': 'boolean',
  'soc.asset.internet_facing': 'boolean', 'soc.posture.active': 'boolean',
  'soc.posture.is_applicable': 'boolean', 'soc.posture.is_compliant': 'boolean',
  'soc.posture.exploit_available': 'boolean', 'exploit_available': 'boolean',
  'source.ip': 'ip', 'destination.ip': 'ip',
  'soc.network.local_ip': 'ip', 'soc.network.remote_ip': 'ip',
  'soc.network.local_port': 'number', 'soc.network.remote_port': 'number',
  'destination.port': 'number', 'tunnel_ip': 'ip',
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
  last: (field, label, dataType = 'number') => ({
    label, customLabel: true, dataType, operationType: 'last_value', sourceField: field,
    isBucketed: false, scale: dataType === 'number' ? 'ratio' : dataType === 'date' ? 'interval' : 'ordinal',
    params: { sortField: '@timestamp', showArrayValues: false },
    filter: { query: `${field} : *`, language: 'kuery' },
  }),
  sum: (field, label) => ({
    label, customLabel: true, dataType: 'number', operationType: 'sum', sourceField: field,
    isBucketed: false, scale: 'ratio', params: { emptyAsNull: false },
  }),
  // Um documento por grupo (ex.: insight_id): o máximo é o próprio valor, sem soma.
  max: (field, label, dataType = 'number') => ({
    label, customLabel: true, dataType, operationType: 'max', sourceField: field,
    isBucketed: false, scale: dataType === 'date' ? 'interval' : 'ratio', params: { emptyAsNull: true },
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
function dashboard(id, title, description, panels, timeFrom = 'now-7d', controls = []) {
  const references = [];
  // Controles (listas de valores) no topo: [campo, título, data view (padrão soc-events)].
  const controlPanels = Object.fromEntries(controls.map(([field, label, dataView = 'soc-events'], order) => {
    const cid = `ctl-${field.replace(/[^a-z0-9]+/gi, '-')}`;
    references.push({ name: `controlGroup_${cid}:optionsListDataView`, type: 'index-pattern', id: dataView });
    return [cid, {
      order, width: 'medium', grow: true, type: 'optionsListControl',
      explicitInput: { id: cid, dataViewId: dataView, fieldName: field, title: label, searchTechnique: 'prefix',
        selectedOptions: [], enhancements: {} },
    }];
  }));
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
      ...(controls.length ? {
        controlGroupInput: {
          controlStyle: 'oneLine', chainingSystem: 'HIERARCHICAL', showApplySelections: false,
          panelsJSON: JSON.stringify(controlPanels),
          ignoreParentSettingsJSON: JSON.stringify({ ignoreFilters: false, ignoreQuery: false, ignoreTimerange: false, ignoreValidations: false }),
        },
      } : {}),
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
const PROCESS = `${SERVER} and event.dataset : "defender.deviceprocessevents"`;
const NETWORK = `${SERVER} and event.dataset : "defender.devicenetworkevents"`;
const POSTURE = `${SERVER} and soc.posture.active : true`;
const VULNERABILITY = `${POSTURE} and soc.posture.kind : "vulnerability"`;
const CONFIGURATION = `${POSTURE} and soc.posture.kind : "configuration"`;
const TVM_SOURCES = 'soc.metrics.source : ("inventory.deviceinfo" or "snapshot.devicetvmsoftwarevulnerabilities" or "snapshot.devicetvmsecureconfigurationassessment")';
const TELEMETRY_SOURCES = 'soc.metrics.source : ("hunting.deviceprocessevents" or "hunting.devicenetworkevents" or "reconcile.deviceprocessevents" or "reconcile.devicenetworkevents")';
const PRIORITY_VULNERABILITY = `${VULNERABILITY} and vulnerability.severity : ("high" or "critical") and soc.posture.exploit_available : true`;

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
  ['soc-dashboard-processos-rede', 'Processos e conexões'], ['soc-dashboard-exposicao', 'Exposição e proteção'],
  ['soc-dashboard-acessos-servidores', 'Acessos aos servidores'], ['soc-dashboard-remediacao', 'Remediação'],
  ['soc-dashboard-windows-updates', 'Atualização do Windows'], ['soc-dashboard-firewall', 'Firewall'],
  ['soc-dashboard-firewall-acessos', 'Firewall: acessos e VPN'],
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
// Postura é estado atual, não uma série de snapshots somáveis. Cada documento
// ativo representa a chave estável emitida pelo coletor, incluindo o software.
function sourceFreshness(id, title, sources) {
  const result = table(id, title, 'soc-metrics-current', `${COLLECTOR} and ${sources}`,
    [['soc.metrics.source', 'Fonte', 20]], [
      ['status', col.last('soc.metrics.status', 'Status da última execução', 'string')],
      ['finished', col.last('soc.metrics.finished_at', 'Última conclusão (UTC)', 'date')],
      ['fetched', col.last('soc.metrics.fetched', 'Linhas na última execução')],
      ['lag', col.last('soc.metrics.lag_seconds', 'Atraso do checkpoint (s)')],
    ]);
  result.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Amostras preservadas';
  return result;
}
const pr = {
  processes: metric('soc-pr-processes', 'Criações de processo observadas no período', 'soc-events', PROCESS),
  connections: metric('soc-pr-connections', 'Eventos de rede observados no período', 'soc-events', NETWORK),
  hosts: metric('soc-pr-hosts', 'Servidores com processo ou rede observado', 'soc-events',
    `(${PROCESS}) or (${NETWORK})`, col.unique('host.id', 'Servidores distintos')),
  processNames: ranking('soc-pr-process-names', 'Top 15 processos criados — documentos observados', 'soc-events', PROCESS,
    'process.name', 'Processo criado', 15),
  parents: table('soc-pr-parent-child', 'Top 30 relações pai → processo criado', 'soc-events', PROCESS, [
    ['process.parent.name', 'Processo pai', 30], ['process.name', 'Processo criado', 10],
    ['host.id', 'Servidor ID — abrir no Discover', 10],
  ]),
  remote: table('soc-pr-remote-endpoints', 'Top 30 extremos remotos registrados — sem inferir direção', 'soc-events', NETWORK, [
    ['soc.network.remote_ip', 'IP remoto', 30], ['soc.network.remote_port', 'Porta remota', 10],
    ['network.transport', 'Transporte', 3], ['process.name', 'Processo iniciador', 10],
  ]),
  activity: timeline('soc-pr-activity', 'Atividade observada por fonte no período', 'soc-events',
    `(${PROCESS}) or (${NETWORK})`, 'event.dataset', 'Fonte', 2),
  freshness: sourceFreshness('soc-pr-freshness', 'Última execução conhecida — processos, rede e reconciliação', TELEMETRY_SOURCES),
};
const posture = {
  cves: metric('soc-posture-cves', 'CVEs distintos ativos — cardinalidade aproximada', 'soc-posture', VULNERABILITY,
    col.unique('vulnerability.id', 'CVEs distintos ativos')),
  instances: metric('soc-posture-instances', 'Instâncias ativas host/CVE/software/versão', 'soc-posture', VULNERABILITY),
  hosts: metric('soc-posture-hosts', 'Servidores com vulnerabilidade reportada ativa', 'soc-posture', VULNERABILITY,
    col.unique('host.id', 'Servidores distintos')),
  priority: metric('soc-posture-priority', 'Instâncias high/critical com exploit disponível', 'soc-posture', PRIORITY_VULNERABILITY),
  severity: donut('soc-posture-severity', 'Instâncias ativas por severidade reportada', 'soc-posture', VULNERABILITY,
    'vulnerability.severity', 'Severidade', 5),
  exploitUnknown: metric('soc-posture-exploit-unknown', 'Instâncias sem informação de exploit disponível', 'soc-posture',
    `${VULNERABILITY} and not soc.posture.exploit_available : *`),
  configFailures: metric('soc-posture-config-failures', 'Avaliações aplicáveis não conformes', 'soc-posture',
    `${CONFIGURATION} and soc.posture.is_applicable : true and soc.posture.is_compliant : false`),
  configUnknown: metric('soc-posture-config-unknown', 'Avaliações com aplicabilidade ou conformidade desconhecida', 'soc-posture',
    `${CONFIGURATION} and (not soc.posture.is_applicable : * or (soc.posture.is_applicable : true and not soc.posture.is_compliant : *))`),
  configNotApplicable: metric('soc-posture-config-not-applicable', 'Avaliações explicitamente não aplicáveis', 'soc-posture',
    `${CONFIGURATION} and soc.posture.is_applicable : false`),
  exposure: donut('soc-posture-exposure', 'Exposição reportada dos servidores observados', 'soc-devices',
    `${ASSET} and soc.asset.observed : true and soc.asset.exposure_level : *`, 'soc.asset.exposure_level', 'Nível de exposição'),
  internet: metric('soc-posture-internet-facing', 'Servidores observados reportados como internet-facing', 'soc-devices',
    `${ASSET} and soc.asset.observed : true and soc.asset.internet_facing : true`),
  internetUnknown: metric('soc-posture-internet-unknown', 'Servidores sem informação de exposição à Internet', 'soc-devices',
    `${ASSET} and soc.asset.observed : true and not soc.asset.internet_facing : *`),
  exposureUnknown: metric('soc-posture-exposure-unknown', 'Servidores sem nível de exposição informado', 'soc-devices',
    `${ASSET} and soc.asset.observed : true and not soc.asset.exposure_level : *`),
  staleSensor: metric('soc-posture-sensor-stale', 'Sensores observados sem contato há mais de 24 h', 'soc-devices',
    `${ASSET} and soc.asset.observed : true and soc.asset.last_seen < now-24h`),
  unknownSensor: metric('soc-posture-sensor-unknown', 'Servidores observados sem horário de último contato', 'soc-devices',
    `${ASSET} and soc.asset.observed : true and not soc.asset.last_seen : *`),
  staleRows: metric('soc-posture-stale-snapshot', 'Registros ativos com snapshot há mais de 36 h', 'soc-posture',
    `${POSTURE} and soc.posture.snapshot_at < now-36h`),
  priorityTable: table('soc-posture-priority-table', 'Priorizar investigação — top 50 CVEs high/critical com exploit disponível', 'soc-posture',
    PRIORITY_VULNERABILITY, [['vulnerability.id', 'CVE', 50], ['vulnerability.severity', 'Severidade', 2]],
    [['hosts', col.unique('host.id', 'Servidores distintos')]]),
  configTable: table('soc-posture-config-table', 'Top 30 configurações aplicáveis não conformes — estado reportado', 'soc-posture',
    `${CONFIGURATION} and soc.posture.is_applicable : true and soc.posture.is_compliant : false`, [
      ['soc.posture.configuration_id', 'Configuração ID', 30], ['soc.posture.configuration_name', 'Nome', 1],
      ['soc.posture.configuration_category', 'Categoria', 1],
    ], [['hosts', col.unique('host.id', 'Servidores distintos')]]),
  freshness: sourceFreshness('soc-posture-freshness', 'Última execução conhecida — inventário e snapshots TVM', TVM_SOURCES),
};
// A contagem de documentos destas tabelas é de instâncias/avaliações, nunca CVEs distintos.
posture.priorityTable.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Instâncias host/CVE/software/versão';
posture.configTable.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Avaliações host/configuração';
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
  search('soc-search-processes', 'Processos criados — comando, pai, usuário e IDs para correlação', 'soc-events', PROCESS,
    ['@timestamp', 'host.name', 'host.id', 'user.name', 'user.domain', 'user.id', 'process.name', 'process.command_line',
      'process.executable', 'process.entity_id', 'process.pid', 'process.parent.name', 'process.parent.command_line',
      'process.parent.entity_id', 'process.parent.pid', 'process.hash.sha256']),
  search('soc-search-network', 'Conexões registradas — processo iniciador e extremos local/remoto', 'soc-events', NETWORK,
    ['@timestamp', 'host.name', 'host.id', 'event.action', 'process.name', 'process.command_line', 'process.entity_id',
      'process.pid', 'user.name', 'user.domain', 'soc.network.local_ip', 'soc.network.local_port', 'soc.network.local_ip_type',
      'soc.network.remote_ip', 'soc.network.remote_port', 'soc.network.remote_url', 'soc.network.remote_ip_type', 'network.transport']),
  search('soc-search-vulnerabilities', 'Vulnerabilidades ativas — uma instância host/CVE/software/versão por documento', 'soc-posture', VULNERABILITY,
    ['soc.posture.snapshot_at', 'host.name', 'host.id', 'vulnerability.id', 'vulnerability.severity', 'vulnerability.score.base',
      'soc.posture.exploit_available', 'soc.posture.software_vendor', 'package.name', 'package.version', 'soc.posture.state']),
  search('soc-search-configurations', 'Avaliações ativas — aplicabilidade, conformidade e contexto', 'soc-posture', CONFIGURATION,
    ['soc.posture.snapshot_at', 'soc.posture.assessed_at', 'host.name', 'host.id', 'soc.posture.configuration_id', 'soc.posture.configuration_name',
      'soc.posture.configuration_category', 'soc.posture.configuration_subcategory', 'soc.posture.is_applicable',
      'soc.posture.is_compliant', 'soc.posture.context', 'soc.posture.state']),
  search('soc-search-exposure-assets', 'Exposição, valor do ativo e último contato conhecido do sensor', 'soc-devices', `${ASSET} and soc.asset.observed : true`,
    ['host.name', 'host.id', 'soc.asset.exposure_level', 'soc.asset.asset_value', 'soc.asset.internet_facing', 'soc.asset.sensor_health',
      'soc.asset.last_seen', 'soc.asset.snapshot_at', 'soc.asset.expected', 'soc.asset.owner', 'soc.asset.criticality']),
];
detailSearches[4].attributes.sort = [['soc.asset.last_seen', 'desc']];
for (const id of ['soc-search-vulnerabilities', 'soc-search-configurations']) {
  detailSearches.find((o) => o.id === id).attributes.sort = [['soc.posture.snapshot_at', 'desc']];
}
detailSearches.find((o) => o.id === 'soc-search-exposure-assets').attributes.sort = [['soc.asset.last_seen', 'desc']];
// Acessos aos servidores (visão consolidada, inspirada no painel Grafana) --------------

const GREEN = '#54B399';
const RED = '#E7664C';
const AMBER = '#D6BF57';
const BLUE = '#6092C0';
const OK = { query: 'event.outcome : "success"', language: 'kuery' };
const FAIL = { query: 'event.outcome : "failure"', language: 'kuery' };
const filtered = (c, query) => ({ ...c, filter: { query, language: 'kuery' } });
// Horário mais recente do grupo (max de @timestamp).
const lastSeen = () => ({
  label: 'Último', customLabel: true, dataType: 'date', operationType: 'max', sourceField: '@timestamp',
  isBucketed: false, scale: 'ratio', params: { emptyAsNull: true },
});

/** Cartão com valor principal, valor secundário opcional e cor fixa. */
function card(id, title, query, primary, secondary, color) {
  const columns = [['m', primary]];
  if (secondary) columns.push(['s', secondary]);
  return lens(id, title, 'soc-events', query, 'lnsMetric', columns, {
    layerId: LAYER, layerType: 'data', metricAccessor: 'm',
    ...(secondary ? { secondaryMetricAccessor: 's' } : {}), ...(color ? { color } : {}),
  });
}

/** Barras horizontais com sucesso (verde) e falha (vermelho) empilhados. */
function outcomeRanking(id, title, query, field, label, size = 10, { failuresOnly = false, missing = false } = {}) {
  const order = failuresOnly ? 'fail' : 'ok';
  const columns = [['y', col.terms(field, label, size, order, missing)]];
  if (!failuresOnly) columns.push(['ok', { ...col.count('Concedidos'), filter: OK }]);
  columns.push(['fail', { ...col.count('Negados'), filter: FAIL }]);
  const accessors = columns.slice(1).map(([cid]) => cid);
  return lens(id, title, 'soc-events', query, 'lnsXY', columns, xy('bar_horizontal_stacked', {
    xAccessor: 'y', accessors,
    yConfig: accessors.map((a) => ({ forAccessor: a, color: a === 'ok' ? GREEN : RED })),
  }));
}

Object.assign(TERM_TYPES, { 'soc.identity.generic': 'boolean', 'soc.identity.privileged': 'boolean' });

const asv = (() => {
  const HUMAN_TYPES = 'winlog.logon.type : ("Interactive" or "RemoteInteractive" or "CachedInteractive" or "Unlock" or "NetworkCleartext")';
  const CONSOLE_TYPES = 'winlog.logon.type : ("Interactive" or "RemoteInteractive" or "CachedInteractive" or "Unlock")';
  const PRIVATE = 'source.ip : ("10.0.0.0/8" or "172.16.0.0/12" or "192.168.0.0/16" or "127.0.0.0/8" or "169.254.0.0/16" or "::1" or "fe80::/10" or "fc00::/7")';
  const ident = (label = 'Identidades') => col.unique('soc.identity.correlation_key', label);
  return {
    // Cartões
    granted: card('soc-asv-granted', 'Acessos concedidos', LOGON, filtered(col.count('Acessos concedidos'), OK.query),
      filtered(col.count('Tentativas sem resultado'), 'event.action : "LogonAttempted"'), GREEN),
    denied: card('soc-asv-denied', 'Acessos negados', LOGON, filtered(col.count('Acessos negados'), FAIL.query),
      filtered(ident('Identidades com falha'), FAIL.query), RED),
    accounts: card('soc-asv-accounts', 'Contas distintas', ACCOUNT, ident('Contas distintas (exceto máquina e sistema)')),
    servers: card('soc-asv-servers', 'Servidores acessados', IDENTITY, col.unique('host.id', 'Servidores acessados')),
    rdp: card('soc-asv-rdp', 'Acessos RDP', `${LOGON} and winlog.logon.type : "RemoteInteractive"`,
      filtered(col.count('Acessos RDP concedidos'), OK.query), filtered(ident('Contas'), OK.query), BLUE),
    admin: card('soc-asv-admin', 'Com privilégio de admin', `${IDENTITY} and soc.identity.is_local_admin : true`,
      filtered(col.count('Com privilégio de admin local'), OK.query), filtered(ident('Contas'), OK.query), AMBER),
    cleartext: card('soc-asv-cleartext', 'Senha em texto claro', `${LOGON} and winlog.logon.type : "NetworkCleartext"`,
      col.count('Senha em texto claro (NetworkCleartext)'), ident('Contas'), AMBER),
    ntlm: card('soc-asv-ntlm', 'Autenticações NTLM', `${LOGON} and soc.logon.protocol : ("NTLM" or "ntlm")`,
      col.count('Autenticações NTLM'), ident('Contas'), AMBER),
    locked: card('soc-asv-locked', 'Contas bloqueadas', `${IDENTITY} and event.reason : "AccountLocked"`,
      ident('Contas bloqueadas (AccountLocked)'), col.count('Eventos'), RED),

    // Tempo e mapa de calor
    timeline: lens('soc-asv-timeline', 'Acessos ao longo do tempo — concedidos e negados', 'soc-events', LOGON, 'lnsXY',
      [['x', col.date()], ['ok', { ...col.count('Concedidos'), filter: OK }], ['fail', { ...col.count('Negados'), filter: FAIL }]],
      xy('bar_stacked', { xAccessor: 'x', accessors: ['ok', 'fail'],
        yConfig: [{ forAccessor: 'ok', color: GREEN }, { forAccessor: 'fail', color: RED }] })),
    heatmap: lens('soc-asv-heatmap', 'Mapa de calor — servidor × hora (top 25 servidores)', 'soc-events', IDENTITY, 'lnsHeatmap',
      [['y', col.terms('host.name', 'Servidor', 25, 'v')],
        ['x', { ...col.date('Hora'), params: { interval: '1h', includeEmptyRows: true, dropPartials: false } }],
        ['v', col.count('Acessos')]],
      {
        layerId: LAYER, layerType: 'data', shape: 'heatmap', xAccessor: 'x', yAccessor: 'y', valueAccessor: 'v',
        legend: { isVisible: true, position: 'right', type: 'heatmap_legend' },
        gridConfig: { type: 'heatmap_grid', isCellLabelVisible: false, isYAxisLabelVisible: true, isXAxisLabelVisible: true,
          isYAxisTitleVisible: false, isXAxisTitleVisible: false },
      }),

    // Rankings
    topServers: outcomeRanking('soc-asv-top-servers', 'Servidores mais acessados', IDENTITY, 'host.name', 'Servidor'),
    topAccounts: outcomeRanking('soc-asv-top-accounts', 'Contas com mais acessos (exceto máquina e sistema)', ACCOUNT,
      'soc.identity.display', 'Conta'),
    types: outcomeRanking('soc-asv-types', 'Tipos de acesso', LOGON, 'winlog.logon.type', 'Tipo'),
    topFailures: outcomeRanking('soc-asv-top-failures', 'Contas com mais falhas', ACCOUNT, 'soc.identity.display', 'Conta', 10,
      { failuresOnly: true }),
    failureOrigins: outcomeRanking('soc-asv-failure-origins', 'Origens das falhas (IP; vazio = não informada)', LOGON,
      'source.ip', 'Origem', 10, { failuresOnly: true, missing: true }),

    // Pontos de atenção — ordem e severidade revisadas pelo papel cyber
    publicSource: table('soc-asv-pa-public', '🔴 Acesso de IP público (rede, RDP ou texto claro)', 'soc-events',
      `${IDENTITY} and source.ip : * and not ${PRIVATE} and winlog.logon.type : ("Network" or "RemoteInteractive" or "NetworkCleartext")`,
      [['source.ip', 'Origem', 20], ['host.name', 'Servidor', 5], ['soc.identity.display', 'Conta', 5], ['event.outcome', 'Resultado', 2]],
      [['t', lastSeen()]]),
    spraying: table('soc-asv-pa-spraying', '🔴 Possível password spraying — origens com falha em várias contas', 'soc-events',
      `${ACCOUNT} and event.outcome : "failure" and not winlog.logon.type : ("Service" or "Batch")`,
      // Só a origem: agrupar também pelo nome do dispositivo dividiria a contagem de contas.
      [['source.ip', 'Origem (vazio = não informada)', 15]],
      [['u', ident('Contas distintas com falha')], ['t', lastSeen()]], 'u'),
    cleartextTable: table('soc-asv-pa-cleartext', '🟠 Senha em texto claro (NetworkCleartext) — crítico quando houver sucesso', 'soc-events',
      `${IDENTITY} and winlog.logon.type : "NetworkCleartext"`,
      [['soc.identity.display', 'Conta', 15], ['host.name', 'Servidor', 5], ['source.ip', 'Origem', 3], ['event.outcome', 'Resultado', 2]],
      [['t', lastSeen()]]),
    lockedTable: table('soc-asv-pa-locked', '🟠 Contas bloqueadas (AccountLocked)', 'soc-events',
      `${ACCOUNT} and event.reason : "AccountLocked"`,
      [['soc.identity.display', 'Conta', 20]],
      [['h', col.unique('host.id', 'Servidores')], ['t', lastSeen()]]),
    generic: table('soc-asv-pa-generic', '🟠 Contas genéricas em RDP/console', 'soc-events',
      `${IDENTITY} and soc.identity.generic : true and ${CONSOLE_TYPES}`,
      [['soc.identity.display', 'Conta', 15], ['host.name', 'Servidor', 10], ['event.outcome', 'Resultado', 2], ['source.ip', 'Origem', 3]],
      [['t', lastSeen()]]),
    offHours: table('soc-asv-pa-offhours', '🟠 Acessos humanos fora do horário (22h–6h ou fim de semana, Brasília)', 'soc-events',
      `${ACCOUNT} and soc.time.off_hours : true and event.outcome : "success" and ${HUMAN_TYPES}`,
      [['soc.identity.display', 'Conta', 20], ['host.name', 'Servidor', 5], ['winlog.logon.type', 'Tipo', 3]],
      [['t', lastSeen()]]),
    bursts: table('soc-asv-pa-bursts', '🟠 Rajadas de falha — conta, servidor e motivo (top 20)', 'soc-events',
      `${ACCOUNT} and event.outcome : "failure"`,
      [['soc.identity.display', 'Conta', 20], ['host.name', 'Servidor', 3], ['event.reason', 'Motivo', 3]],
      [['t', lastSeen()]]),
    sweep: table('soc-asv-pa-sweep', '🔵 Contas em muitos servidores (rede e RDP)', 'soc-events',
      `${ACCOUNT} and event.outcome : "success" and winlog.logon.type : ("Network" or "RemoteInteractive")`,
      [['soc.identity.display', 'Conta', 20]],
      [['u', col.unique('host.id', 'Servidores (rede ou RDP)')],
        ['r', filtered(col.unique('host.id', 'Servidores via RDP'), 'winlog.logon.type : "RemoteInteractive"')], ['t', lastSeen()]], 'u'),
    runas: table('soc-asv-pa-runas', '🔵 NewCredentials (runas /netonly) — conta e servidor', 'soc-events',
      `${IDENTITY} and winlog.logon.type : "NewCredentials"`,
      [['soc.identity.display', 'Conta', 15], ['host.name', 'Servidor', 5]], [['t', lastSeen()]]),
    localNetwork: table('soc-asv-pa-local', '🔵 Contas locais via rede ou RDP', 'soc-events',
      `${ACCOUNT} and soc.identity.scope : "local" and event.outcome : "success" and winlog.logon.type : ("Network" or "RemoteInteractive")`,
      [['soc.identity.display', 'Conta local', 15], ['host.name', 'Servidor', 3], ['source.ip', 'Origem', 3]], [['t', lastSeen()]]),

    // Detalhamento
    deniedTable: table('soc-asv-denied-table', 'Acessos negados agrupados — servidor, conta, motivo, tipo, protocolo e origem', 'soc-events',
      `${IDENTITY} and event.outcome : "failure"`,
      [['host.name', 'Servidor', 20], ['soc.identity.display', 'Conta', 5], ['event.reason', 'Motivo', 3],
        ['winlog.logon.type', 'Tipo', 2], ['soc.logon.protocol', 'Protocolo', 2], ['source.ip', 'Origem', 2]],
      [['t', lastSeen()]]),
    adminConsole: table('soc-asv-admin-console', 'Acessos RDP/console com privilégio de administrador', 'soc-events',
      `${IDENTITY} and soc.identity.is_local_admin : true and event.outcome : "success" and ${CONSOLE_TYPES}`,
      [['soc.identity.display', 'Conta', 20], ['host.name', 'Servidor', 10], ['soc.identity.generic', 'Conta genérica', 2]],
      [['t', lastSeen()]]),
  };
})();
// Remediação: um documento por insight_id; estado atual sem corte temporal -----------

const OPEN = 'status : "open"';
const rem = {
  open: metric('soc-rem-open', 'Ações de remediação abertas', 'soc-insights', OPEN),
  p1: metric('soc-rem-p1', 'Abertas com prioridade P1 (crítica)', 'soc-insights', `${OPEN} and priority : "P1"`),
  exploit: metric('soc-rem-exploit', 'Abertas com exploit disponível reportado', 'soc-insights', `${OPEN} and exploit_available : true`),
  closed: metric('soc-rem-closed', 'Não mais reportadas (não comprova correção)', 'soc-insights', 'status : "no_longer_reported"'),
  category: donut('soc-rem-category', 'Ações abertas por tipo de remediação', 'soc-insights', OPEN, 'category', 'Tipo', 7),
  priority: donut('soc-rem-priority', 'Ações abertas por prioridade', 'soc-insights', OPEN, 'priority', 'Prioridade', 4),
  queue: table('soc-rem-queue', 'Fila priorizada — top 50 ações abertas', 'soc-insights', OPEN, [
    ['title.keyword', 'Ação', 50], ['category', 'Tipo', 1], ['priority', 'Prioridade', 1], ['owner', 'Responsável sugerido', 1],
  ], [['score', col.max('priority_score', 'Pontuação')], ['dev', col.max('affected_device_count', 'Servidores únicos')],
    ['cves', col.max('cve_count', 'CVEs distintas')]], 'score'),
  gpo: table('soc-rem-gpo', 'GPOs propostas — política e valor', 'soc-insights', `${OPEN} and category : "gpo_configuration"`, [
    ['gpo_name', 'GPO sugerida', 20], ['gpo_settings.policy', 'Política', 10], ['gpo_settings.value', 'Valor', 3],
  ], [['dev', col.max('affected_device_count', 'Servidores únicos')]]),
  investigation: table('soc-rem-investigation', 'Configurações sem ação validada — investigar e catalogar', 'soc-insights',
    `${OPEN} and category : "investigation"`, [
      ['title.keyword', 'Configuração', 30], ['recommendation_ids', 'scid', 1], ['suggested_catalog_key', 'Sugestão do catálogo (não confirmada)', 1],
    ], [['dev', col.max('affected_device_count', 'Servidores únicos')]]),
};
rem.queue.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Documentos (1 por ação)';
const remediationSearch = search('soc-search-insights', 'Insights detalhados — passos, validação, reversão e lacunas', 'soc-insights', OPEN,
  ['priority', 'title', 'category', 'remediation_type', 'affected_device_count', 'cve_count', 'recommendation_ids', 'owner', 'effort',
    'status', 'first_seen', 'last_seen', 'insight_id']);
remediationSearch.attributes.sort = [['priority_score', 'desc']];
detailSearches.push(remediationSearch);

// Atualização do Windows: um documento por servidor SRV*, estado atual sem corte temporal ---

const WU = 'host.name : srv*';
const wu = {
  total: metric('soc-wu-total', 'Servidores SRV* Windows Server monitorados', 'soc-windows-updates', WU),
  ok: metric('soc-wu-ok', 'Em dia com a atualização de segurança', 'soc-windows-updates', `${WU} and status : "em_dia"`),
  pending: metric('soc-wu-pending', 'Com atualização de segurança pendente', 'soc-windows-updates', `${WU} and status : "pendente"`),
  unknown: metric('soc-wu-unknown', 'Não determinado', 'soc-windows-updates', `${WU} and status : "nao_determinado"`),
  stale: metric('soc-wu-stale', 'Coleta desatualizada', 'soc-windows-updates', `${WU} and status : "coleta_desatualizada"`),
  status: donut('soc-wu-status', 'Servidores por situação', 'soc-windows-updates', WU, 'status_label', 'Situação', 4),
  version: ranking('soc-wu-version', 'Servidores por versão do Windows Server e situação', 'soc-windows-updates', WU,
    'windows.product', 'Windows Server', 6, { field: 'status_label', label: 'Situação' }),
  table: table('soc-wu-table', 'Situação por servidor — atualização de segurança do Windows', 'soc-windows-updates', WU, [
    ['host.name', 'Servidor', 200], ['windows.product', 'Windows Server', 1], ['windows.build', 'Build', 1],
    ['update.latest_kb', 'Última atualização de segurança disponível', 1], ['update.installed_kb', 'Atualização refletida na build atual', 1],
    ['update.pending_kb', 'Atualização pendente (cumulativa)', 1], ['update.reboot_required_label', 'Pode exigir reinicialização', 1],
    ['status_label', 'Situação', 1],
  ], [['rel', col.max('update.latest_release_date', 'Lançamento Microsoft', 'date')],
    ['days', col.max('update.days_since_latest_release', 'Dias desde o lançamento (pendentes)')],
    ['older', col.max('update.pending_superseded_count', 'Atualizações anteriores substituídas')],
    ['seen', col.max('collection.collected_at', 'Última coleta', 'date')]]),
  exposure: table('soc-wu-exposure', 'Exposição por servidor — atraso do Windows e vulnerabilidades reportadas pelo Defender', 'soc-windows-updates', WU, [
    ['host.name', 'Servidor', 200], ['windows.product', 'Windows Server', 1], ['update.oldest_pending_kb', 'Atualização pendente mais antiga', 1],
  ], [['since', col.max('update.oldest_pending_release_date', 'Lançada em (desatualizado desde)', 'date')],
    ['cves', col.max('vulnerabilities.cve_count', 'CVEs distintas (todo software)')],
    ['crit', col.max('vulnerabilities.critical_cve_count', 'Críticas')],
    ['expl', col.max('vulnerabilities.exploit_cve_count', 'Com exploit público')]], 'cves'),
  exploitTotal: metric('soc-wu-exploit', 'Servidores com CVE com exploit público', 'soc-windows-updates', `${WU} and vulnerabilities.exploit_cve_count > 0`),
  trend: timeline('soc-wu-trend', 'Histórico diário — servidores por situação', 'soc-windows-updates-history', WU, 'status_label', 'Situação', 4),
};
wu.table.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Documentos (1 por servidor)';
wu.trend.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Servidores';
wu.exposure.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Documentos (1 por servidor)';
const wuSearch = search('soc-search-windows-updates', 'Detalhe por servidor — motivo, evidências do Defender e datas de coleta', 'soc-windows-updates', WU,
  ['host.name', 'windows.product', 'windows.version', 'status_label', 'status_reason', 'update.latest_kb', 'update.latest_release_date',
    'update.installed_kb', 'update.installed_match', 'update.pending_kb', 'update.reboot_required_label',
    'update.oldest_pending_kb', 'update.oldest_pending_release_date', 'vulnerabilities.cve_count', 'vulnerabilities.critical_cve_count',
    'vulnerabilities.exploit_cve_count', 'update.defender_recommended_kbs', 'collection.device_last_seen', 'collection.build_snapshot_at', 'collection.catalog_updated_at', 'collection.collected_at']);
wuSearch.attributes.sort = [['host.name', 'asc']];
detailSearches.push(wuSearch);

// Firewall: logs do FortiGate via FortiAnalyzer (fw-logs-*) e agregados por hora (soc-fw-flows-*) ---

const FW = 'event.dataset : "fortigate.traffic"';
const FW_BLOCKED = `${FW} and soc.fw.verdict : "blocked"`;
const FW_INBOUND = `${FW} and network.direction : "inbound"`;
const FW_SERVER = 'kind : "server"';
const fw = {
  sessions: metric('soc-fw-sessions', 'Sessões registradas', 'fw-logs', FW),
  blocked: metric('soc-fw-blocked', 'Sessões bloqueadas (deny ou UTM)', 'fw-logs', FW_BLOCKED),
  inbound: metric('soc-fw-inbound', 'Sessões vindas da internet', 'fw-logs', FW_INBOUND),
  sources: metric('soc-fw-sources', 'Origens distintas', 'fw-logs', FW, col.unique('source.ip', 'Origens distintas')),
  timeline: timeline('soc-fw-timeline', 'Sessões no tempo por veredito', 'fw-logs', FW, 'soc.fw.verdict', 'Veredito', 2),
  categories: ranking('soc-fw-categories', 'Bloqueios por categoria web (UTM)', 'fw-logs', `${FW_BLOCKED} and fortinet.firewall.catdesc : *`,
    'fortinet.firewall.catdesc', 'Categoria', 12),
  rules: ranking('soc-fw-rules', 'Sessões por política e veredito', 'fw-logs', FW, 'rule.name', 'Política', 12,
    { field: 'soc.fw.verdict', label: 'Veredito' }),
  countries: donut('soc-fw-countries', 'Destinos por país', 'fw-logs', `${FW} and destination.geo.country_name : *`,
    'destination.geo.country_name', 'País', 8),
  blockedSources: table('soc-fw-blocked-sources', 'Origens com mais bloqueios — top 30', 'fw-logs', FW_BLOCKED, [
    ['source.ip', 'Origem', 30], ['fortinet.firewall.srcname', 'Nome do dispositivo', 1], ['observer.ingress.interface.name', 'Interface', 1],
  ], [['dst', col.unique('destination.ip', 'Destinos distintos')]]),
  inboundTable: table('soc-fw-inbound-table', 'Entradas vindas da internet — origem, destino e porta', 'fw-logs', FW_INBOUND, [
    ['source.ip', 'Origem', 30], ['destination.ip', 'Destino', 1], ['destination.port', 'Porta', 1], ['soc.fw.verdict', 'Veredito', 1],
  ]),
  servers: table('soc-fw-servers', 'Fluxos de e para os servidores (agregado por hora)', 'soc-fw-flows', FW_SERVER, [
    ['destination.ip', 'Destino', 30], ['destination.port', 'Porta', 3], ['source.ip', 'Origem', 3], ['soc.fw.verdict', 'Veredito', 1],
  ], [['ses', col.sum('fw.sessions', 'Sessões')], ['bytes', col.sum('fw.bytes_total', 'Bytes')]], 'ses'),
};
fw.servers.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Horas com tráfego';
const fwSearch = search('soc-search-firewall', 'Logs da firewall — sessões detalhadas', 'fw-logs', FW,
  ['source.ip', 'user.name', 'destination.ip', 'destination.port', 'destination.domain', 'network.application', 'event.action',
    'fortinet.firewall.utmaction', 'fortinet.firewall.catdesc', 'rule.name', 'soc.fw.verdict', 'network.bytes']);
detailSearches.push(fwSearch);

// Firewall: acesso administrativo, VPN e sessões abertas ------------------------------------
// soc.fw.access.user é a conta do FortiGate (local/LDAP), não a identidade canônica do Defender.

const FW_EVENT = 'event.dataset : "fortigate.event"';
const ADMIN = `${FW_EVENT} and soc.fw.access.kind : "admin"`;
const ADMIN_LOGIN = `${ADMIN} and event.action : "login"`;
const VPN = `${FW_EVENT} and soc.fw.access.kind : "vpn"`;
const VPN_RESULT = `${VPN} and soc.fw.access.outcome : *`;
const SESSION_OPEN = 'state : ("open" or "stale")';
const fwa = {
  vpnOpen: metric('soc-fwa-vpn-open', 'VPN conectadas agora', 'soc-fw-sessions-state', 'kind : "vpn" and state : "open"'),
  adminOpen: metric('soc-fwa-admin-open', 'Administradores conectados agora', 'soc-fw-sessions-state', 'kind : "admin" and state : "open"'),
  stale: metric('soc-fwa-stale', 'Sem fechamento registrado', 'soc-fw-sessions-state', 'state : "stale"'),
  openTable: table('soc-fwa-open-table', 'Sessões abertas — usuário, origem e início', 'soc-fw-sessions-state', SESSION_OPEN, [
    ['user', 'Usuário', 100], ['kind', 'Tipo', 1], ['channel', 'Canal', 1], ['source.ip', 'Origem', 1], ['tunnel_ip', 'IP do túnel', 1],
    ['state_label', 'Situação', 1],
  ], [['start', col.max('started_at', 'Início', 'date')], ['dur', col.max('duration_seconds', 'Duração (s)')]], 'start'),
  adminOk: metric('soc-fwa-admin-ok', 'Logins administrativos com sucesso', 'fw-logs', `${ADMIN_LOGIN} and soc.fw.access.outcome : "success"`),
  adminFail: metric('soc-fwa-admin-fail', 'Falhas de login administrativo', 'fw-logs', `${ADMIN_LOGIN} and soc.fw.access.outcome : "failure"`),
  adminFailSources: metric('soc-fwa-admin-fail-sources', 'Origens com falha de login', 'fw-logs', `${ADMIN_LOGIN} and soc.fw.access.outcome : "failure"`,
    col.unique('source.ip', 'Origens com falha de login')),
  adminTimeline: timeline('soc-fwa-admin-timeline', 'Logins administrativos no tempo por resultado', 'fw-logs', ADMIN_LOGIN, 'soc.fw.access.outcome', 'Resultado', 2),
  adminFailTable: table('soc-fwa-admin-fail-table', 'Falhas de login administrativo — conta, origem e motivo', 'fw-logs',
    `${ADMIN_LOGIN} and soc.fw.access.outcome : "failure"`, [
      ['soc.fw.access.user', 'Conta', 50], ['source.ip', 'Origem', 3], ['soc.fw.access.channel', 'Canal', 1], ['fortinet.firewall.reason', 'Motivo', 1],
    ]),
  adminOkTable: table('soc-fwa-admin-ok-table', 'Logins administrativos com sucesso — conta, origem e perfil', 'fw-logs',
    `${ADMIN_LOGIN} and soc.fw.access.outcome : "success"`, [
      ['soc.fw.access.user', 'Conta', 50], ['source.ip', 'Origem', 3], ['soc.fw.access.channel', 'Canal', 1], ['fortinet.firewall.profile', 'Perfil', 1],
    ]),
  vpnUp: metric('soc-fwa-vpn-up', 'Túneis VPN estabelecidos', 'fw-logs', `${VPN} and event.action : "tunnel-up"`),
  vpnFail: metric('soc-fwa-vpn-fail', 'Falhas de conexão VPN', 'fw-logs', `${VPN} and soc.fw.access.outcome : "failure"`),
  vpnUsers: metric('soc-fwa-vpn-users', 'Usuários de VPN distintos', 'fw-logs', `${VPN} and event.action : "tunnel-up"`,
    col.unique('soc.fw.access.user', 'Usuários de VPN distintos')),
  vpnTimeline: timeline('soc-fwa-vpn-timeline', 'Conexões VPN no tempo por resultado', 'fw-logs', VPN_RESULT, 'soc.fw.access.outcome', 'Resultado', 2),
  vpnTable: table('soc-fwa-vpn-table', 'Conexões VPN — usuário, origem e tipo', 'fw-logs', `${VPN} and event.action : "tunnel-up"`, [
    ['soc.fw.access.user', 'Usuário', 100], ['source.ip', 'Origem', 3], ['soc.fw.access.channel', 'Tipo', 1],
  ]),
  vpnFailTable: table('soc-fwa-vpn-fail-table', 'Falhas de VPN — usuário, origem e motivo', 'fw-logs', `${VPN} and soc.fw.access.outcome : "failure"`, [
    ['soc.fw.access.user', 'Usuário', 50], ['source.ip', 'Origem', 3], ['fortinet.firewall.reason', 'Motivo', 1],
  ]),
};
fwa.openTable.attributes.state.datasourceStates.formBased.layers[LAYER].columns.m.label = 'Documentos (1 por sessão)';
const fwaSearch = search('soc-search-firewall-acessos', 'Eventos de acesso — login administrativo e VPN', 'fw-logs', `${FW_EVENT} and soc.fw.access.kind : *`,
  ['soc.fw.access.kind', 'event.action', 'soc.fw.access.outcome', 'soc.fw.access.user', 'source.ip', 'soc.fw.access.channel',
    'fortinet.firewall.tunnelip', 'fortinet.firewall.reason', 'message']);
detailSearches.push(fwaSearch);

const lensObjects = [...Object.values(ov), ...Object.values(ac), ...Object.values(srv), ...Object.values(asr), ...Object.values(cap),
  ...Object.values(pr), ...Object.values(posture), ...Object.values(asv), ...Object.values(rem), ...Object.values(wu), ...Object.values(fw), ...Object.values(fwa)];
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
  dashboard('soc-dashboard-processos-rede', 'SOC - Processos e conexões', 'Investigar processos criados e conexões registradas com correlação por servidor e identificador de processo.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Investigue por host.id:** clique no ID para abrir o Discover com esse servidor, ou aplique o filtro no painel. Correlacione **host.id + process.entity_id** quando o identificador estiver presente. PID pode ser reutilizado; sua igualdade não comprova que se trata do mesmo processo. Nos eventos de criação, process.* é o processo criado e process.parent.* é o iniciador; nos eventos de rede, process.* é o iniciador da conexão. Usuário pode estar ausente.\n\n**Rede:** local e remoto seguem os campos do Defender; não representam uma direção inferida. Não há bytes, volume transferido ou conclusão de sucesso nesta fonte normalizada. Contagens são documentos observados, não inventário completo de processos ou conexões. Antes de interpretar ausência de eventos, confira a última execução das fontes no final do painel.'), 0, 5, 48, 9],
    [pr.processes, 0, 14, 16, 8], [pr.connections, 16, 14, 16, 8], [pr.hosts, 32, 14, 16, 8],
    [pr.activity, 0, 22, 48, 14], [pr.processNames, 0, 36, 48, 15],
    [pr.parents, 0, 51, 48, 17], [pr.remote, 0, 68, 48, 18],
    [detailSearches.find((o) => o.id === 'soc-search-processes'), 0, 86, 48, 22],
    [detailSearches.find((o) => o.id === 'soc-search-network'), 0, 108, 48, 22],
    [pr.freshness, 0, 130, 48, 18],
    [markdown('**Disponibilidade da telemetria:** esta tabela ignora o seletor de tempo e mostra a última execução conhecida por fonte. Fonte ausente = sem métrica conhecida; não significa coleta saudável. Status diferente de success ou conclusão antiga exige verificar erro, permissão, licença, limite da consulta e atraso. A conclusão da consulta não comprova contato recente do sensor; confira DeviceInfo em Exposição e proteção.'), 0, 148, 48, 6],
  ]),
  dashboard('soc-dashboard-exposicao', 'SOC - Exposição e proteção', 'Estado atual reportado: exposição dos ativos, vulnerabilidades TVM e avaliações de configuração. Sem corte temporal global.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Estado atual reportado, sem corte pelo seletor de tempo:** somente registros TVM com **soc.posture.active:true**. Um documento de vulnerabilidade representa a combinação **host/CVE/software/versão**; o mesmo CVE em vários servidores ou softwares aumenta instâncias, não CVEs distintos. A cardinalidade de CVEs/hosts é aproximada. Snapshots completos atualizam o estado; uma falha preserva a informação anterior, que pode estar antiga.\n\n**Prioridade para investigar:** high/critical com exploit disponível exige atenção, mas **exploit disponível não significa exploração observada**. CVSS é exibido quando informado, sem presumir score ausente. Registros que deixam de ser observados em um snapshot completo saem da lista ativa; isso **não comprova correção**. Servidor offline, mudança de escopo e perda de cobertura também precisam ser considerados.'), 0, 5, 48, 10],
    [posture.cves, 0, 15, 12, 9], [posture.instances, 12, 15, 12, 9], [posture.hosts, 24, 15, 12, 9], [posture.priority, 36, 15, 12, 9],
    [posture.severity, 0, 24, 24, 15], [posture.exposure, 24, 24, 24, 15],
    [posture.internet, 0, 39, 16, 9], [posture.internetUnknown, 16, 39, 16, 9], [posture.exposureUnknown, 32, 39, 16, 9],
    [posture.configFailures, 0, 48, 16, 9], [posture.configUnknown, 16, 48, 16, 9], [posture.configNotApplicable, 32, 48, 16, 9],
    [posture.priorityTable, 0, 57, 48, 18], [posture.configTable, 0, 75, 48, 18],
    [detailSearches.find((o) => o.id === 'soc-search-vulnerabilities'), 0, 93, 48, 23],
    [detailSearches.find((o) => o.id === 'soc-search-configurations'), 0, 116, 48, 23],
    [markdown('**Exposição e proteção:** IsInternetFacing ausente é **desconhecido**, nunca false. ExposureLevel e AssetValue são valores reportados pelo Defender, não criticidade local validada. Uma avaliação não aplicável não é falha; campo ausente não é conformidade. O dado de configuração não comprova sozinho que todas as políticas de proteção estejam ativas. Clique em host.id para detalhar o estado do mesmo servidor no Discover.\n\n**Atualização:** último contato do sensor, avaliação (`soc.posture.assessed_at`), snapshot e conclusão da consulta são relógios diferentes. Uma consulta recente pode retornar avaliação antiga; horário ausente é desconhecido. Os limites de 24 h para contato e 36 h para snapshot são sinais operacionais para revisão, não confirmação de comprometimento.'), 0, 139, 48, 9],
    [posture.staleSensor, 0, 148, 16, 9], [posture.unknownSensor, 16, 148, 16, 9], [posture.staleRows, 32, 148, 16, 9],
    [posture.exploitUnknown, 0, 157, 48, 8],
    [detailSearches.find((o) => o.id === 'soc-search-exposure-assets'), 0, 165, 48, 22],
    [posture.freshness, 0, 187, 48, 18],
    [markdown('**Vazio não é saudável:** verifique cada fonte na tabela de execuções, o horário de conclusão e os sensores. Fonte ausente, falha ou última conclusão antiga deixa a cobertura indeterminada. Snapshot TVM completo com zero linhas pode ser um resultado válido, mas uma tabela indisponível, licença ausente ou consulta truncada é falha de coleta. Não substitua essa validação por zero no cartão. A tabela ignora o seletor de tempo e mostra a última execução preservada nas métricas (retenção de 60 dias). “Amostras preservadas” são cópias periódicas do estado do coletor, não quantidade de execuções.'), 0, 205, 48, 7],
  ], 'now-24h'),
];

dashboards.push(dashboard('soc-dashboard-acessos-servidores', 'SOC - Acessos aos servidores',
  'Visão consolidada de autenticações nos servidores: indicadores, pontos de atenção, distribuição no tempo, mapa de calor e detalhamento.', [
    [nav(), 0, 0, 48, 5],
    [asv.granted, 0, 5, 5, 7], [asv.denied, 5, 5, 5, 7], [asv.accounts, 10, 5, 6, 7], [asv.servers, 16, 5, 5, 7],
    [asv.rdp, 21, 5, 5, 7], [asv.admin, 26, 5, 6, 7], [asv.cleartext, 32, 5, 5, 7], [asv.ntlm, 37, 5, 6, 7], [asv.locked, 43, 5, 5, 7],
    [markdown('### Pontos de atenção\n🔴 crítico · 🟠 atenção · 🔵 informativo. Cada tabela é um ranking limitado (top N): ordene pelas colunas e **clique em um valor para filtrar o painel inteiro**. ' +
      'Use os controles acima (servidor, conta, tipo, resultado, origem) para recortar; o botão de cada tabela abre os eventos no Discover. ' +
      'Fora do horário = 22h–6h ou fim de semana (Brasília); revise com a operação se turnos ou safra tornam isso normal.'), 0, 12, 48, 5],
    [asv.publicSource, 0, 17, 24, 12], [asv.spraying, 24, 17, 24, 12],
    [asv.cleartextTable, 0, 29, 24, 12], [asv.lockedTable, 24, 29, 24, 12],
    [asv.generic, 0, 41, 24, 12], [asv.offHours, 24, 41, 24, 12],
    [asv.bursts, 0, 53, 24, 12], [asv.sweep, 24, 53, 24, 12],
    [asv.runas, 0, 65, 24, 10], [asv.localNetwork, 24, 65, 24, 10],
    [asv.timeline, 0, 75, 48, 12],
    [asv.heatmap, 0, 87, 48, 20],
    [asv.topServers, 0, 107, 16, 15], [asv.topAccounts, 16, 107, 16, 15], [asv.types, 32, 107, 16, 15],
    [asv.topFailures, 0, 122, 24, 15], [asv.failureOrigins, 24, 122, 24, 15],
    [asv.deniedTable, 0, 137, 48, 18],
    [asv.adminConsole, 0, 155, 48, 16],
    [detailSearches[0], 0, 171, 48, 20],
  ], 'now-24h', [
    ['host.name', 'Servidor'], ['soc.identity.display', 'Conta'], ['winlog.logon.type', 'Tipo de acesso'],
    ['event.outcome', 'Resultado'], ['source.ip', 'Origem'],
  ]));

dashboards.push(dashboard('soc-dashboard-remediacao', 'SOC - Remediação',
  'Ações capazes de tratar conjuntos de achados do Defender (GPO, atualização, substituição ou investigação). Estado atual, sem corte temporal.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Um documento por ação (insight_id estável).** Cada achado TVM ativo entra em um único bloco; servidores são contados uma vez por ação, ' +
      'mas o mesmo servidor aparece em várias ações. **Não some servidores entre linhas.** Prioridade combina exploit disponível, exposição à Internet, ' +
      'valor do ativo, severidade e abrangência — não só CVSS. Exploit disponível não comprova exploração observada.\n\n' +
      '**GPO** só aparece quando o scid está vinculado a uma entrada validada do catálogo (`collector/config/remediation-catalog.json`); o resto fica em ' +
      '**investigação** com a orientação do Defender marcada como não validada. **Não mais reportada** significa que o Defender deixou de reportar os achados, ' +
      'não prova de correção. Confira `data_gaps` antes de decidir; valores ausentes são desconhecidos, não zero.'), 0, 5, 48, 9],
    [rem.open, 0, 14, 12, 8], [rem.p1, 12, 14, 12, 8], [rem.exploit, 24, 14, 12, 8], [rem.closed, 36, 14, 12, 8],
    [rem.category, 0, 22, 24, 15], [rem.priority, 24, 22, 24, 15],
    [rem.queue, 0, 37, 48, 22], [rem.gpo, 0, 59, 48, 16], [rem.investigation, 0, 75, 48, 16],
    [remediationSearch, 0, 91, 48, 24],
  ], 'now-24h'));

dashboards.push(dashboard('soc-dashboard-windows-updates', 'SOC - Atualização do Windows',
  'Atualização de segurança do Windows nos servidores SRV* (Windows Server), com dados do Defender e do catálogo de segurança da Microsoft.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Escopo:** servidores cujo nome começa com SRV e com Windows Server. Só atualizações de segurança do sistema operacional, a partir do ' +
      'Security Update Guide da Microsoft; previews opcionais não tornam o servidor pendente. Cada servidor é comparado com a atualização da **própria build** ' +
      '(14393 = 2016, 17763 = 2019, 20348 = 2022). As atualizações são **cumulativas**: a pendente substitui as anteriores.\n\n' +
      '**Atualização refletida na build atual** é o KB cuja build corresponde à do servidor segundo o Defender; não é o histórico de instalação. ' +
      '**Pode exigir reinicialização** é a informação da Microsoft sobre a atualização pendente; não indica que o servidor está com reinicialização pendente. ' +
      'Sem prazo de implantação definido, a situação é só **em dia** ou **pendente**. Data de instalação, reinicialização pendente e última inicialização ' +
      'não são fornecidas pelo Defender e não aparecem aqui. Horários em America/Sao_Paulo.'), 0, 5, 48, 8],
    [wu.total, 0, 13, 10, 8], [wu.ok, 10, 13, 10, 8], [wu.pending, 20, 13, 10, 8], [wu.unknown, 30, 13, 9, 8], [wu.stale, 39, 13, 9, 8],
    [wu.status, 0, 21, 16, 14], [wu.version, 16, 21, 32, 14],
    [wu.table, 0, 35, 48, 24],
    [markdown('**Exposição por servidor:** "Atualização pendente mais antiga" é a primeira atualização de segurança da própria build que o servidor ainda não tem, ' +
      'e a data mostra desde quando ele está desatualizado. Não é o KB mais antigo recomendado pelo Defender, que pode citar KBs de outra build. ' +
      'CVEs são distintas por servidor e incluem todo o software, não só o Windows; não some entre servidores. Exploit público disponível não comprova exploração.'), 0, 59, 40, 6],
    [wu.exploitTotal, 40, 59, 8, 6],
    [wu.exposure, 0, 65, 48, 24],
    [wuSearch, 0, 89, 48, 22],
    [wu.trend, 0, 111, 48, 14],
  ], 'now-30d', [
    ['host.name', 'Servidor', 'soc-windows-updates'], ['windows.product', 'Windows Server', 'soc-windows-updates'],
    ['status_label', 'Situação', 'soc-windows-updates'],
  ]));

dashboards.push(dashboard('soc-dashboard-firewall', 'SOC - Firewall',
  'Tráfego do FortiGate recebido pelo FortiAnalyzer: bloqueios, políticas, entradas da internet e fluxos dos servidores.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Fonte:** logs de tráfego do FortiGate encaminhados pelo FortiAnalyzer (um documento por sessão encerrada). ' +
      '**Bloqueada** = ação deny ou bloqueio UTM (webfilter, aplicação); uma sessão com UTM bloqueado pode aparecer como close ou reset. ' +
      'Direção vem dos papéis das interfaces (lan/wan): **vindas da internet** = interface de origem wan. ' +
      'Contagens são sessões registradas pela firewall, não usuários nem acessos únicos.\n\n' +
      '**Dado pessoal:** usuário, MAC e sites acessados identificam pessoas. Os logs brutos ficam 10 dias e só os papéis soc_admin e ' +
      'soc_analyst os leem; os agregados por hora (soc-fw-flows) seguem a retenção do histórico. Use para investigação de segurança.'), 0, 5, 48, 7],
    [fw.sessions, 0, 12, 12, 8], [fw.blocked, 12, 12, 12, 8], [fw.inbound, 24, 12, 12, 8], [fw.sources, 36, 12, 12, 8],
    [fw.timeline, 0, 20, 48, 14],
    [fw.categories, 0, 34, 24, 16], [fw.rules, 24, 34, 24, 16],
    [fw.blockedSources, 0, 50, 32, 18], [fw.countries, 32, 50, 16, 18],
    [fw.inboundTable, 0, 68, 48, 18],
    [markdown('**Servidores:** agregados por hora calculados pelo coletor para origem ou destino nas redes de servidores (padrão 172.16.159.0/24). ' +
      '"Horas com tráfego" conta documentos (uma linha por hora e fluxo); some **Sessões**, não horas. Uma hora pode ser recalculada e ' +
      'substituída com dados que chegaram atrasados.'), 0, 86, 48, 5],
    [fw.servers, 0, 91, 48, 20],
    [fwSearch, 0, 111, 48, 22],
  ], 'now-24h', [
    ['source.ip', 'Origem', 'fw-logs'], ['destination.ip', 'Destino', 'fw-logs'], ['rule.name', 'Política', 'fw-logs'],
    ['soc.fw.verdict', 'Veredito', 'fw-logs'],
  ]));

dashboards.push(dashboard('soc-dashboard-firewall-acessos', 'SOC - Firewall: acessos e VPN',
  'Logins administrativos no FortiGate, conexões VPN e sessões abertas agora.', [
    [nav(), 0, 0, 48, 5],
    [markdown('**Sessões abertas agora** (sem corte pelo seletor de tempo): túneis VPN e logins administrativos sem fechamento registrado, ' +
      'recalculados pelo coletor a cada 5 minutos a partir dos últimos 7 dias de logs. **Sem fechamento registrado** = aberta há mais de ' +
      '2 h (VPN, que envia status a cada ~10 min) ou 24 h (administração) sem evento novo: pode ter caído sem log; confira no FortiGate. ' +
      'Quem já estava conectado antes da coleta aparece no primeiro status do túnel, com o início calculado pela duração informada. ' +
      'A tabela de sessões de tráfego da firewall não vem nos logs e não aparece aqui.\n\n' +
      '**Contas** são as do FortiGate (local ou LDAP), sem correlação com a identidade do Defender. O acesso do Claude (claude/soc_readonly) ' +
      'e do fgt-gateway também aparece como login administrativo por SSH.'), 0, 5, 48, 7],
    [fwa.vpnOpen, 0, 12, 16, 8], [fwa.adminOpen, 16, 12, 16, 8], [fwa.stale, 32, 12, 16, 8],
    [fwa.openTable, 0, 20, 48, 18],
    [markdown('### Acesso administrativo ao FortiGate\nLogins pela interface web (https), SSH e console. Falhas de contas inexistentes ou ' +
      'vindas da internet indicam tentativa de acesso indevido.'), 0, 38, 48, 4],
    [fwa.adminOk, 0, 42, 16, 8], [fwa.adminFail, 16, 42, 16, 8], [fwa.adminFailSources, 32, 42, 16, 8],
    [fwa.adminTimeline, 0, 50, 48, 13],
    [fwa.adminFailTable, 0, 63, 24, 18], [fwa.adminOkTable, 24, 63, 24, 18],
    [markdown('### VPN\nTúneis SSL e IPsec. Falha = login recusado ou negociação com erro. Túnel IPsec entre sites aparece sem usuário.'), 0, 81, 48, 4],
    [fwa.vpnUp, 0, 85, 16, 8], [fwa.vpnFail, 16, 85, 16, 8], [fwa.vpnUsers, 32, 85, 16, 8],
    [fwa.vpnTimeline, 0, 93, 48, 13],
    [fwa.vpnTable, 0, 106, 24, 18], [fwa.vpnFailTable, 24, 106, 24, 18],
    [fwaSearch, 0, 124, 48, 22],
  ], 'now-7d', [
    ['soc.fw.access.user', 'Conta / usuário', 'fw-logs'], ['source.ip', 'Origem', 'fw-logs'], ['soc.fw.access.outcome', 'Resultado', 'fw-logs'],
  ]));

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
