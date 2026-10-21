import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const load = (name) => readFileSync(new URL(`dist/${name}.ndjson`, root), 'utf8').trim().split('\n').map(JSON.parse);
const objects = load('objects');
const rules = load('rules');
const get = (id) => objects.find((o) => o.id === id);
const dashboards = objects.filter((o) => o.type === 'dashboard');
const lenses = objects.filter((o) => o.type === 'lens');
const columns = (o) => Object.values(o.attributes.state.datasourceStates.formBased.layers.layer1.columns);

test('Lens field types match mapped boolean/IP fields and temporal last-value requirements', () => {
  const mapping = JSON.parse(readFileSync(new URL('../elasticsearch/mappings/soc-mappings.json', root), 'utf8'));
  const mapped = (field) => field.split('.').reduce((node, key) => node?.properties?.[key], mapping);
  for (const o of lenses) for (const c of columns(o)) {
    const type = mapped(c.sourceField)?.type;
    if (c.operationType === 'terms' && ['boolean', 'ip'].includes(type)) assert.equal(c.dataType, type, `${o.id}: ${c.sourceField}`);
    if (c.operationType === 'last_value') {
      assert.equal(mapped(c.params.sortField)?.type, 'date', `${o.id}: last_value sort is temporal`);
      assert.equal(o.references[0].id, 'soc-metrics');
      assert.equal(get('soc-metrics').attributes.timeFieldName, c.params.sortField);
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

test('five dashboards have valid nonoverlapping panel layouts', () => {
  assert.equal(dashboards.length, 5);
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
  for (const id of ['soc-incidents', 'soc-alerts', 'soc-devices']) {
    assert.equal(get(id).attributes.timeFieldName, undefined, id);
  }
  assert.equal(get('soc-alerts-timeline').attributes.timeFieldName, '@timestamp');
  const ref = get('soc-ov-alerts-source').references[0];
  assert.equal(ref.id, 'soc-alerts-timeline');
  assert.match(get('soc-ov-incidents-active').attributes.title, /estado conhecido/);
  assert.equal(get('soc-elastic-alerts').attributes.title, '.alerts-security.alerts-soc');
});

test('all event visualizations and detailed searches apply the requested server scope', () => {
  for (const o of objects.filter((o) => o.references.some((r) => r.id === 'soc-events'))) {
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
});
