import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const root = new URL('../', import.meta.url);
const load = (name) => readFileSync(new URL(`dist/${name}.ndjson`, root), 'utf8').trim().split('\n').map(JSON.parse);
const objects = load('objects');
const rules = load('rules');
const get = (id) => objects.find((o) => o.id === id);
const dashboards = objects.filter((o) => o.type === 'dashboard');
const lenses = objects.filter((o) => o.type === 'lens');
const columns = (o) => Object.values(o.attributes.state.datasourceStates.formBased.layers.layer1.columns);

test('Lens field types match mapped boolean/IP/numeric fields and temporal last-value requirements', () => {
  const mapping = JSON.parse(readFileSync(new URL('../elasticsearch/mappings/soc-mappings.json', root), 'utf8'));
  const mapped = (field) => field.split('.').reduce((node, key) => node?.properties?.[key], mapping);
  for (const o of lenses) for (const c of columns(o)) {
    const type = mapped(c.sourceField)?.type;
    if (c.operationType === 'terms' && ['boolean', 'ip'].includes(type)) assert.equal(c.dataType, type, `${o.id}: ${c.sourceField}`);
    if (c.operationType === 'terms' && ['integer', 'long', 'float', 'double'].includes(type)) assert.equal(c.dataType, 'number', `${o.id}: ${c.sourceField}`);
    if (c.operationType === 'last_value') {
      assert.equal(mapped(c.params.sortField)?.type, 'date', `${o.id}: last_value sort is temporal`);
      assert.ok(['soc-metrics', 'soc-metrics-current'].includes(o.references[0].id));
      if (o.references[0].id === 'soc-metrics') assert.equal(get('soc-metrics').attributes.timeFieldName, c.params.sortField);
      else assert.equal(get('soc-metrics-current').attributes.timeFieldName, undefined);
      const fieldType = mapped(c.sourceField)?.type;
      const expected = fieldType === 'keyword' ? 'string' : fieldType === 'date' ? 'date' : 'number';
      assert.equal(c.dataType, expected, `${o.id}: ${c.sourceField} last-value output`);
    }
  }
});

test('all saved-object IDs and references resolve, including dashboard panel references', () => {
  const ids = new Set(objects.map((o) => `${o.type}:${o.id}`));
  assert.equal(ids.size, objects.length);
  for (const o of objects) for (const r of o.references) assert.ok(ids.has(`${r.type}:${r.id}`), `${o.id} -> ${r.id}`);
  for (const d of dashboards) for (const p of JSON.parse(d.attributes.panelsJSON)) {
    if (p.panelRefName) assert.ok(d.references.some((r) => r.name === `${p.panelIndex}:${p.panelRefName}`));
  }
});

test('nine dashboards have valid nonoverlapping panel layouts', () => {
  assert.equal(dashboards.length, 9);
  for (const d of dashboards) {
    const panels = JSON.parse(d.attributes.panelsJSON);
    for (const [i, p] of panels.entries()) {
      const a = p.gridData;
      assert.ok(a.x >= 0 && a.y >= 0 && a.w > 0 && a.h > 0 && a.x + a.w <= 48, d.id);
      for (const q of panels.slice(i + 1)) {
        const b = q.gridData;
        assert.ok(a.x + a.w <= b.x || b.x + b.w <= a.x || a.y + a.h <= b.y || b.y + b.h <= a.y, `${d.id}: panels overlap`);
      }
    }
  }
});

test('current-state and inventory totals cannot disappear behind the global time filter', () => {
  for (const id of ['soc-incidents', 'soc-alerts', 'soc-devices', 'soc-posture', 'soc-metrics-current']) {
    assert.equal(get(id).attributes.timeFieldName, undefined, id);
  }
  assert.equal(get('soc-alerts-timeline').attributes.timeFieldName, '@timestamp');
  const ref = get('soc-ov-alerts-source').references[0];
  assert.equal(ref.id, 'soc-alerts-timeline');
  assert.match(get('soc-ov-incidents-active').attributes.title, /estado conhecido/);
  assert.equal(get('soc-elastic-alerts').attributes.title, '.alerts-security.alerts-soc');
});

test('all event visualizations and detailed searches apply the requested server scope', () => {
  // Dashboards também referenciam soc-events pelos controles; o escopo vale para visualizações e buscas.
  for (const o of objects.filter((o) => ['lens', 'search'].includes(o.type) && o.references.some((r) => r.id === 'soc-events'))) {
    const query = o.type === 'lens' ? o.attributes.state.query.query
      : JSON.parse(o.attributes.kibanaSavedObjectMeta.searchSourceJSON).query.query;
    for (const term of ['*srv*', '*fisico*', '*note*', '*micro*']) assert.ok(query.includes(term), `${o.id} missing ${term}`);
    assert.match(query, /not host\.name/);
  }
});

test('identity aggregation uses a domain/host qualified correlation key, never bare user names', () => {
  for (const o of lenses) for (const c of columns(o)) {
    assert.notEqual(c.sourceField, 'user.name', o.id);
    assert.notEqual(c.sourceField, 'soc.identity.key', `${o.id}: SID can split failed and successful logons`);
  }
  assert.ok(columns(get('soc-ac-users')).some((c) => c.sourceField === 'soc.identity.correlation_key'));
  assert.ok(columns(get('soc-ac-spread')).some((c) => c.sourceField === 'host.id'));
});

test('capacity snapshots use last values and exact source/dataset filters, never snapshot sums', () => {
  const capacity = lenses.filter((o) => o.id.startsWith('soc-cap-') && columns(o).some((c) => c.operationType === 'last_value'));
  assert.equal(capacity.length, 13);
  for (const o of capacity) {
    assert.ok(!columns(o).some((c) => c.operationType === 'sum'));
    const q = o.attributes.state.query.query;
    assert.match(q, /event\.dataset/);
    assert.match(q, /soc\.metrics\.source/);
    for (const c of columns(o).filter((c) => c.operationType === 'last_value')) assert.equal(c.params.sortField, '@timestamp');
  }
});

test('capacity evolution uses one last value per histogram bucket and matrix keeps canonical axes', () => {
  for (const id of ['soc-cap-pg-trend', 'soc-cap-es-trend']) {
    const cs = columns(get(id));
    assert.equal(cs.filter((c) => c.operationType === 'date_histogram').length, 1);
    assert.ok(cs.filter((c) => !c.isBucketed).every((c) => c.operationType === 'last_value'));
    assert.equal(get(id).attributes.state.visualization.preferredSeriesType, 'line');
  }
  const matrix = get('soc-ac-account-host-matrix');
  assert.match(matrix.attributes.title, /top 20 identidades.*10 servidores/);
  assert.deepEqual(columns(matrix).filter((c) => c.isBucketed).map((c) => c.sourceField),
    ['soc.identity.correlation_key', 'host.id']);
  assert.equal(columns(matrix).filter((c) => c.filter && c.operationType === 'count').length, 2);
});

test('rules remain observation-only v2 and protect canonical host/account correlation', () => {
  assert.equal(rules.length, 8);
  for (const r of rules) {
    assert.equal(r.version, 2);
    assert.deepEqual(r.actions, []);
    assert.equal(r.enabled, true);
    assert.ok(r.tags.includes('SOC-observacao'));
    assert.ok(r.query.includes('host.id'));
    for (const term of ['*srv*', '*fisico*', '*note*', '*micro*']) assert.ok(r.query.includes(term), r.rule_id);
    for (const f of [...(r.new_terms_fields || []), ...(r.threshold?.field || []), ...(r.threshold?.cardinality || []).map((c) => c.field)]) {
      assert.ok(!['user.name', 'host.name', 'soc.identity.key'].includes(f), `${r.rule_id}: unsafe grouping ${f}`);
    }
    if (r.tags.includes('Logon')) assert.ok(r.query.includes('soc.identity.correlation_key'));
  }
  const eql = rules.find((r) => r.type === 'eql');
  assert.match(eql.query, /sequence by soc\.identity\.correlation_key with maxspan=30m/);
  assert.match(eql.query, /with runs=5/);
  assert.equal(eql.from, 'now-2h');
  assert.equal(eql.interval, '10m');
});

test('navigation stays in the SOC space, and coverage never assumes an empty inventory is complete', () => {
  for (const d of dashboards) {
    const panels = JSON.parse(d.attributes.panelsJSON);
    const text = panels.filter((p) => p.type === 'visualization').map((p) => p.embeddableConfig.savedVis.params.markdown).join('\n');
    assert.match(text, /\/s\/soc\/app\/dashboards/);
    assert.ok(!/\]\(\/app\//.test(text));
    assert.ok(text.includes('soc.identity.correlation_key'));
  }
  assert.match(get('soc-dashboard-cobertura').attributes.panelsJSON, /SEM CADASTRO/);
  assert.equal(get('soc-search-assets').attributes.sort[0][0], 'soc.asset.last_seen');
  for (const d of dashboards) for (const target of dashboards) {
    assert.ok(d.attributes.panelsJSON.includes(`/s/soc/app/dashboards#/view/${target.id}`), `${d.id} missing navigation to ${target.id}`);
  }
});

test('current posture always excludes tombstones and separates CVE cardinality from software instances', () => {
  assert.equal(get('soc-posture').attributes.title, 'soc-posture');
  for (const o of objects.filter((o) => o.references.some((r) => r.id === 'soc-posture'))) {
    const query = o.type === 'lens' ? o.attributes.state.query.query
      : JSON.parse(o.attributes.kibanaSavedObjectMeta.searchSourceJSON).query.query;
    assert.match(query, /soc\.posture\.active : true/, o.id);
    assert.match(query, /not host\.name/, o.id);
  }
  assert.deepEqual(columns(get('soc-posture-cves')).map((c) => [c.operationType, c.sourceField]), [['unique_count', 'vulnerability.id']]);
  assert.equal(columns(get('soc-posture-instances'))[0].operationType, 'count');
  assert.match(get('soc-posture-instances').attributes.title, /host\/CVE\/software\/versão/);
  assert.match(get('soc-posture-priority').attributes.state.query.query, /severity : \("high" or "critical"\)/);
  assert.match(get('soc-posture-priority').attributes.state.query.query, /exploit_available : true/);
  const text = get('soc-dashboard-exposicao').attributes.panelsJSON;
  for (const expected of ['não significa exploração observada', 'não comprova correção', 'Vazio não é saudável', 'avaliação antiga']) assert.ok(text.includes(expected), expected);
  const configs = get('soc-search-configurations');
  assert.ok(configs.attributes.columns.includes('soc.posture.snapshot_at'));
  assert.ok(configs.attributes.columns.includes('soc.posture.assessed_at'));
  assert.ok(configs.attributes.columns.includes('soc.posture.is_applicable'));
  assert.ok(configs.attributes.columns.includes('soc.posture.is_compliant'));
});

test('unknown exposure and compliance are explicit and current-source freshness ignores the global time range', () => {
  assert.match(get('soc-posture-internet-unknown').attributes.state.query.query, /not soc\.asset\.internet_facing : \*/);
  assert.match(get('soc-posture-exposure-unknown').attributes.state.query.query, /not soc\.asset\.exposure_level : \*/);
  assert.match(get('soc-posture-config-failures').attributes.state.query.query, /is_applicable : true and soc\.posture\.is_compliant : false/);
  for (const id of ['soc-pr-freshness', 'soc-posture-freshness']) {
    const o = get(id);
    assert.equal(o.references[0].id, 'soc-metrics-current');
    assert.equal(columns(o).find((c) => c.operationType === 'count').label, 'Amostras preservadas');
    const status = columns(o).find((c) => c.sourceField === 'soc.metrics.status');
    const finished = columns(o).find((c) => c.sourceField === 'soc.metrics.finished_at');
    assert.equal(status.operationType, 'last_value');
    assert.equal(status.params.sortField, '@timestamp');
    assert.equal(finished.operationType, 'last_value');
    assert.equal(finished.dataType, 'date');
    assert.ok(!o.attributes.state.query.query.includes('status : "success"'), 'latest failure must remain visible');
    assert.ok(columns(o).find((c) => c.sourceField === 'soc.metrics.source').params.size >= 20);
  }
  assert.ok(columns(get('soc-cap-collection')).find((c) => c.sourceField === 'soc.metrics.source').params.size >= 20, 'all 13 sources fit');
});

test('process/network investigation uses explicit dataset contracts and exposes correlation evidence', () => {
  const process = get('soc-search-processes');
  const network = get('soc-search-network');
  const pq = JSON.parse(process.attributes.kibanaSavedObjectMeta.searchSourceJSON).query.query;
  const nq = JSON.parse(network.attributes.kibanaSavedObjectMeta.searchSourceJSON).query.query;
  assert.match(pq, /defender\.deviceprocessevents/);
  assert.match(nq, /defender\.devicenetworkevents/);
  for (const field of ['host.id', 'process.entity_id', 'process.command_line', 'process.parent.name', 'process.parent.entity_id', 'user.name']) assert.ok(process.attributes.columns.includes(field), field);
  for (const field of ['host.id', 'process.entity_id', 'process.command_line', 'soc.network.local_ip', 'soc.network.local_port', 'soc.network.remote_ip', 'soc.network.remote_port', 'soc.network.remote_url']) assert.ok(network.attributes.columns.includes(field), field);
  for (const field of ['network.direction', 'network.bytes', 'source.bytes', 'destination.bytes']) assert.ok(!network.attributes.columns.includes(field), field);
  const text = get('soc-dashboard-processos-rede').attributes.panelsJSON;
  assert.ok(text.includes('PID pode ser reutilizado'));
  assert.ok(text.includes('host.id + process.entity_id'));
});

test('host IDs link to scoped Discover views and roles can read posture without event write access', () => {
  for (const id of ['soc-events', 'soc-devices', 'soc-posture']) {
    const format = JSON.parse(get(id).attributes.fieldFormatMap)['host.id'];
    assert.equal(format.id, 'url');
    const url = decodeURIComponent(format.params.urlTemplate.replace('{{value}}', '0123456789abcdef'));
    assert.ok(url.startsWith('/s/soc/app/discover#/'));
    assert.ok(url.includes(`index:'${id}'`));
    assert.ok(url.includes('host.id : "0123456789abcdef"'));
    if (id === 'soc-posture') assert.ok(url.includes('soc.posture.active : true'));
  }
  for (const file of readdirSync(new URL('roles/', root))) {
    const role = JSON.parse(readFileSync(new URL(`roles/${file}`, root), 'utf8'));
    const dataPrivilege = role.elasticsearch.indices.find((p) => p.names.includes('soc-*'));
    assert.ok(dataPrivilege, file);
    assert.deepEqual([...dataPrivilege.privileges].sort(), ['read', 'view_index_metadata']);
    assert.ok(role.kibana.every((p) => p.spaces.length === 1 && p.spaces[0] === 'soc'), file);
  }
});

test('acessos aos servidores: controles, pontos de atenção em ordem e cores fixas', () => {
  const d = get('soc-dashboard-acessos-servidores');
  const controls = JSON.parse(d.attributes.controlGroupInput.panelsJSON);
  const fields = Object.values(controls).sort((a, b) => a.order - b.order).map((c) => c.explicitInput.fieldName);
  assert.deepEqual(fields, ['host.name', 'soc.identity.display', 'winlog.logon.type', 'event.outcome', 'source.ip']);
  for (const id of Object.keys(controls)) {
    assert.ok(d.references.some((r) => r.name === `controlGroup_${id}:optionsListDataView` && r.id === 'soc-events'), id);
  }
  const titles = d.references.filter((r) => r.type === 'lens').map((r) => get(r.id).attributes.title);
  const points = titles.filter((t) => /^(🔴|🟠|🔵)/u.test(t));
  assert.equal(points.length, 10);
  const rank = { '🔴': 0, '🟠': 1, '🔵': 2 };
  const order = points.map((t) => rank[[...t][0]]);
  assert.deepEqual(order, [...order].sort((a, b) => a - b), 'pontos de atenção fora da ordem de severidade');
  const timeline = get('soc-asv-timeline').attributes.state.visualization.layers[0].yConfig;
  assert.deepEqual(timeline.map((y) => y.color), ['#54B399', '#E7664C']);
  // IP público exclui todas as faixas privadas.
  assert.match(get('soc-asv-pa-public').attributes.state.query.query, /10\.0\.0\.0\/8.*172\.16\.0\.0\/12.*192\.168\.0\.0\/16/);
});

test('remediation dashboard reads soc-insights without time cut and never sums devices across insights', () => {
  assert.equal(get('soc-insights').attributes.timeFieldName, undefined);
  assert.ok(get('soc-dashboard-remediacao'));
  const remediation = lenses.filter((o) => o.id.startsWith('soc-rem-'));
  assert.ok(remediation.length >= 7);
  for (const o of remediation) {
    assert.equal(o.references[0].id, 'soc-insights', o.id);
    for (const c of columns(o)) {
      if (['affected_device_count', 'cve_count', 'priority_score'].includes(c.sourceField)) assert.equal(c.operationType, 'max', `${o.id}: ${c.sourceField}`);
      assert.notEqual(c.operationType, 'sum', o.id);
    }
  }
  const nav = JSON.parse(get('soc-dashboard-overview').attributes.panelsJSON)[0].embeddableConfig.savedVis.params.markdown;
  assert.match(nav, /soc-dashboard-remediacao/);
});
