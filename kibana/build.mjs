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
  { id: 'soc-incidents', title: 'soc-incidents', name: 'SOC - Incidentes' },
  { id: 'soc-alerts', title: 'soc-alerts', name: 'SOC - Alertas' },
  { id: 'soc-history', title: 'soc-*-history-*', name: 'SOC - Histórico' },
];

const dataViewObjects = DATA_VIEWS.map((d) => ({
  type: 'index-pattern',
  id: d.id,
  attributes: { title: d.title, name: d.name, timeFieldName: '@timestamp' },
  references: [],
  coreMigrationVersion: '8.8.0',
  typeMigrationVersion: '8.0.0',
}));

// Colunas Lens ---------------------------------------------------------------------

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
  terms: (field, label, size, orderBy, missingBucket = false) => ({
    label, customLabel: true, dataType: 'string', operationType: 'terms', sourceField: field,
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
    references.push({ name: `${panelIndex}:panel_${panelIndex}`, type: 'lens', id: obj.id });
    // Cartões de métrica já exibem o rótulo; o título do painel ficaria duplicado.
    const hidePanelTitles = obj.attributes.visualizationType === 'lnsMetric';
    return {
      type: 'lens', gridData, panelIndex,
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

// Visão geral (incidentes e alertas da Microsoft) -------------------------------------

const ACTIVE = 'not soc.object.status : "resolved"';
const ov = {
  incidents: metric('soc-ov-incidents-active', 'Incidentes ativos', 'soc-incidents', ACTIVE),
  alerts: metric('soc-ov-alerts-active', 'Alertas ativos', 'soc-alerts', ACTIVE),
  alertsHigh: metric('soc-ov-alerts-high', 'Alertas ativos de severidade alta', 'soc-alerts',
    `${ACTIVE} and soc.object.severity : "high"`),
  bySeverity: donut('soc-ov-incidents-severity', 'Incidentes ativos por severidade', 'soc-incidents', ACTIVE,
    'soc.object.severity', 'Severidade'),
  alertsBySource: timeline('soc-ov-alerts-source', 'Alertas por produto (última atualização)', 'soc-alerts', '',
    'soc.object.service_source', 'Produto'),
  incidentsTable: table('soc-ov-incidents-table', 'Incidentes ativos', 'soc-incidents', ACTIVE, [
    ['soc.object.title.keyword', 'Incidente', 50], ['soc.object.severity', 'Severidade', 5],
    ['soc.object.status', 'Status', 5], ['soc.object.assigned_to', 'Responsável', 10],
  ]),
  alertsTable: table('soc-ov-alerts-table', 'Alertas ativos por título', 'soc-alerts', ACTIVE, [
    ['soc.object.title.keyword', 'Alerta', 30], ['soc.object.severity', 'Severidade', 5],
    ['soc.object.service_source', 'Produto', 5],
  ]),
};

// Acessos (Frentes 1 e 4) ---------------------------------------------------------------

const LOGON = 'event.dataset : "defender.devicelogonevents"';
const HUMAN = `${LOGON} and not user.name : *$`;
const ac = {
  ok: metric('soc-ac-success', 'Logons bem-sucedidos', 'soc-events', `${LOGON} and event.outcome : "success"`),
  fail: metric('soc-ac-failure', 'Logons com falha', 'soc-events', `${LOGON} and event.outcome : "failure"`),
  hosts: metric('soc-ac-hosts', 'Servidores com logon', 'soc-events', LOGON, col.unique('host.name', 'Servidores com logon')),
  users: metric('soc-ac-users', 'Contas (exceto máquina)', 'soc-events', HUMAN, col.unique('user.name', 'Contas (exceto máquina)')),
  timeline: timeline('soc-ac-timeline', 'Logons ao longo do tempo por resultado', 'soc-events', LOGON,
    'event.outcome', 'Resultado', 3),
  types: donut('soc-ac-types', 'Tipos de logon', 'soc-events', LOGON, 'winlog.logon.type', 'Tipo'),
  rdpHosts: ranking('soc-ac-rdp-hosts', 'Servidores com mais RDP', 'soc-events',
    `${LOGON} and winlog.logon.type : "RemoteInteractive"`, 'host.name', 'Servidor', 10,
    { field: 'event.outcome', label: 'Resultado' }),
  rdpPaths: table('soc-ac-rdp-paths', 'RDP: origem → servidor → conta', 'soc-events',
    `${LOGON} and winlog.logon.type : "RemoteInteractive" and event.outcome : "success"`, [
      ['source.ip', 'Origem (IP)', 30], ['host.name', 'Servidor', 30], ['user.name', 'Conta', 30],
    ]),
  failures: table('soc-ac-failures', 'Falhas de logon por conta e motivo (exceto contas de máquina)', 'soc-events',
    `${HUMAN} and event.outcome : "failure"`, [
      ['user.name', 'Conta', 30], ['host.name', 'Servidor', 20], ['event.reason', 'Motivo', 5],
    ]),
  spread: table('soc-ac-spread', 'Contas em mais servidores (rede e RDP)', 'soc-events',
    `${HUMAN} and event.outcome : "success" and winlog.logon.type : ("Network" or "RemoteInteractive")`,
    [['user.name', 'Conta', 30]],
    [['u', col.unique('host.name', 'Servidores distintos')]], 'u'),
};

// ASR (Frente 3) -------------------------------------------------------------------------

const ASR = 'event.dataset : "defender.deviceevents" and soc.asr.rule : *';
const asr = {
  block: metric('soc-asr-block', 'Eventos ASR em bloqueio', 'soc-events', `${ASR} and soc.asr.mode : "block"`),
  audit: metric('soc-asr-audit', 'Eventos ASR em auditoria', 'soc-events', `${ASR} and soc.asr.mode : "audit"`),
  hosts: metric('soc-asr-hosts', 'Servidores com ASR', 'soc-events', ASR, col.unique('host.name', 'Servidores com ASR')),
  timeline: timeline('soc-asr-timeline', 'Eventos ASR ao longo do tempo por regra', 'soc-events', ASR,
    'soc.asr.rule', 'Regra ASR'),
  rules: ranking('soc-asr-rules', 'Regras ASR por modo', 'soc-events', ASR, 'soc.asr.rule', 'Regra ASR', 15,
    { field: 'soc.asr.mode', label: 'Modo' }),
  hostsTable: table('soc-asr-hosts-table', 'ASR por servidor, regra e arquivo', 'soc-events', ASR, [
    ['host.name', 'Servidor', 30], ['soc.asr.rule', 'Regra', 10], ['soc.asr.mode', 'Modo', 3],
    ['file.name', 'Arquivo', 10], ['process.name', 'Processo de origem', 10],
  ]),
  files: table('soc-asr-files', 'Arquivos mais afetados', 'soc-events', ASR, [['file.name', 'Arquivo', 20]],
    [['u', col.unique('host.name', 'Servidores distintos')]], 'u'),
};

const lensObjects = [...Object.values(ov), ...Object.values(ac), ...Object.values(asr)];

const dashboards = [
  dashboard('soc-dashboard-overview', 'SOC - Visão geral',
    'Incidentes e alertas importados do Microsoft Defender (estado atual).', [
      [ov.incidents, 0, 0, 12, 7], [ov.alerts, 12, 0, 12, 7], [ov.alertsHigh, 24, 0, 12, 7], [ov.bySeverity, 36, 0, 12, 14],
      [ov.alertsBySource, 0, 7, 36, 14],
      [ov.incidentsTable, 0, 21, 48, 16],
      [ov.alertsTable, 0, 37, 48, 14],
    ], 'now-30d'),
  dashboard('soc-dashboard-acessos', 'SOC - Acessos e movimentação',
    'Autenticações nos servidores do piloto (DeviceLogonEvents). Frentes 1 e 4.', [
      [ac.ok, 0, 0, 12, 7], [ac.fail, 12, 0, 12, 7], [ac.hosts, 24, 0, 12, 7], [ac.users, 36, 0, 12, 7],
      [ac.timeline, 0, 7, 32, 14], [ac.types, 32, 7, 16, 14],
      [ac.rdpHosts, 0, 21, 24, 15], [ac.spread, 24, 21, 24, 15],
      [ac.rdpPaths, 0, 36, 24, 16], [ac.failures, 24, 36, 24, 16],
    ]),
  dashboard('soc-dashboard-asr', 'SOC - ASR',
    'Regras de redução de superfície de ataque (DeviceEvents). Frente 3.', [
      [markdown('**Atenção:** o Advanced Hunting registra eventos ASR amostrados (um por processo único por hora). ' +
        'Os números são **eventos observados**, não o total de tentativas no servidor.'), 0, 0, 48, 4],
      [asr.block, 0, 4, 16, 7], [asr.audit, 16, 4, 16, 7], [asr.hosts, 32, 4, 16, 7],
      [asr.timeline, 0, 11, 48, 14],
      [asr.rules, 0, 25, 24, 16], [asr.files, 24, 25, 24, 16],
      [asr.hostsTable, 0, 41, 48, 16],
    ]),
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
  'objects.ndjson': [...dataViewObjects, ...lensObjects, ...dashboards],
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
