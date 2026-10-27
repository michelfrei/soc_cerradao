import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const mapping = JSON.parse(readFileSync(new URL('../mappings/soc-mappings.json', import.meta.url), 'utf8'));
const field = (path) => path.split('.').reduce((node, name) => node?.properties?.[name], mapping);

test('explicit mappings cover process instances, parent instances and their accounts', () => {
  assert.equal(mapping.dynamic, false);
  for (const prefix of ['process', 'process.parent']) {
    for (const name of ['name', 'entity_id', 'hash.sha1', 'hash.sha256', 'user.name', 'user.domain', 'user.id']) {
      assert.equal(field(`${prefix}.${name}`)?.type, 'keyword', `${prefix}.${name}`);
    }
    assert.equal(field(`${prefix}.pid`)?.type, 'long');
    assert.equal(field(`${prefix}.start`)?.type, 'date');
    assert.equal(field(`${prefix}.command_line`)?.type, 'wildcard');
    assert.equal(field(`${prefix}.executable`)?.type, 'keyword');
  }
});

test('network endpoints are typed without inventing direction, bytes or success', () => {
  for (const name of ['local_ip', 'remote_ip']) assert.equal(field(`soc.network.${name}`)?.type, 'ip');
  for (const name of ['local_port', 'remote_port']) assert.equal(field(`soc.network.${name}`)?.type, 'long');
  for (const name of ['local_ip_type', 'remote_ip_type', 'remote_url']) assert.equal(field(`soc.network.${name}`)?.type, 'keyword');
  assert.equal(field('network.transport')?.type, 'keyword');
  assert.equal(field('network.direction'), undefined);
  assert.equal(field('network.bytes'), undefined);
});

test('current posture has explicit optional boolean/date/vulnerability/configuration fields', () => {
  for (const name of ['active', 'is_applicable', 'is_compliant', 'exploit_available']) assert.equal(field(`soc.posture.${name}`)?.type, 'boolean');
  for (const name of ['state', 'kind', 'configuration_id', 'configuration_name', 'configuration_category', 'configuration_subcategory', 'software_vendor']) {
    assert.equal(field(`soc.posture.${name}`)?.type, 'keyword');
  }
  assert.equal(field('soc.posture.snapshot_at')?.type, 'date');
  assert.equal(field('soc.posture.assessed_at')?.type, 'date');
  assert.equal(field('soc.posture.context')?.type, 'flattened');
  assert.equal(field('vulnerability.id')?.type, 'keyword');
  assert.equal(field('vulnerability.severity')?.type, 'keyword');
  assert.equal(field('vulnerability.score.base')?.type, 'double');
  for (const name of ['name', 'version']) assert.equal(field(`package.${name}`)?.type, 'keyword');
  assert.equal(field('soc.asset.internet_facing')?.type, 'boolean');
  assert.equal(field('soc.asset.exposure_level')?.type, 'keyword');
  assert.equal(field('soc.asset.asset_value')?.type, 'keyword');
});

test('posture template is current state and receives explicit shared mappings without event ILM', () => {
  const template = JSON.parse(readFileSync(new URL('../templates/index-soc-posture.json', import.meta.url), 'utf8'));
  assert.deepEqual(template.index_patterns, ['soc-posture']);
  assert.deepEqual(template.composed_of, ['soc-mappings']);
  assert.equal(template.template.settings['index.lifecycle.name'], undefined);
});

test('software posture keeps end-of-support status and date typed', () => {
  assert.equal(field('soc.posture.end_of_support_status')?.type, 'keyword');
  assert.equal(field('soc.posture.end_of_support_date')?.type, 'date');
});

test('insights template has its own explicit contract with unknown-capable numeric/boolean fields', () => {
  const template = JSON.parse(readFileSync(new URL('../templates/index-soc-insights.json', import.meta.url), 'utf8'));
  const insights = JSON.parse(readFileSync(new URL('../mappings/soc-insights-mappings.json', import.meta.url), 'utf8'));
  const f = (path) => path.split('.').reduce((node, name) => node?.properties?.[name], insights);
  assert.deepEqual(template.index_patterns, ['soc-insights']);
  assert.deepEqual(template.composed_of, ['soc-insights-mappings']);
  assert.equal(template.template.settings['index.lifecycle.name'], undefined);
  assert.equal(insights.dynamic, false);
  for (const name of ['@timestamp', 'schema_version', 'analysis_id', 'insight_id', 'source', 'title', 'description', 'category',
    'priority', 'risk_rationale', 'cve_ids', 'recommendation_ids', 'affected_products', 'affected_device_count', 'remediation_type',
    'remediation_steps', 'gpo_settings', 'dependencies', 'expected_outcome', 'validation_steps', 'rollback_steps', 'references',
    'data_gaps', 'status', 'first_seen', 'last_seen']) {
    assert.ok(insights.properties[name], name);
  }
  for (const name of ['insight_id', 'category', 'priority', 'status', 'cve_ids', 'recommendation_ids', 'source.finding_ids']) assert.equal(f(name)?.type, 'keyword', name);
  for (const name of ['affected_device_count', 'internet_facing_device_count', 'expected_outcome.finding_reduction']) assert.equal(f(name)?.type, 'integer', name);
  for (const name of ['first_seen', 'last_seen', 'resolved_at', '@timestamp']) assert.equal(f(name)?.type, 'date', name);
  assert.equal(f('exploit_available')?.type, 'boolean');
  assert.equal(f('gpo_settings.policy')?.type, 'keyword');
});

test('firewall raw logs: data stream with its own explicit mapping, 30-day ILM and reader-restricted name', () => {
  const fw = JSON.parse(readFileSync(new URL('../mappings/fw-logs-mappings.json', import.meta.url), 'utf8'));
  const f = (path) => path.split('.').reduce((node, name) => node?.properties?.[name], fw);
  assert.equal(fw.dynamic, false);
  for (const name of ['source.ip', 'destination.ip', 'source.nat.ip', 'fortinet.firewall.remip']) assert.equal(f(name)?.type, 'ip', name);
  for (const name of ['source.port', 'destination.port']) assert.equal(f(name)?.type, 'integer', name);
  for (const name of ['source.bytes', 'destination.bytes', 'network.bytes', 'event.duration']) assert.equal(f(name)?.type, 'long', name);
  for (const name of ['soc.fw.verdict', 'network.direction', 'rule.name', 'user.name', 'fortinet.firewall.catdesc']) assert.equal(f(name)?.type, 'keyword', name);
  const template = JSON.parse(readFileSync(new URL('../templates/index-fw-logs-fortigate.json', import.meta.url), 'utf8'));
  assert.deepEqual(template.index_patterns, ['fw-logs-*']);
  assert.deepEqual(template.data_stream, {});
  assert.equal(template.template.settings['index.lifecycle.name'], 'fw-logs-retention');
  const ilm = JSON.parse(readFileSync(new URL('../ilm/fw-logs-retention.json', import.meta.url), 'utf8'));
  assert.equal(ilm.policy.phases.delete.min_age, '30d');
  assert.ok(ilm.policy.phases.hot.actions.rollover.max_age);
});

test('firewall hourly aggregates have their own mapping and long-term history ILM', () => {
  const flows = JSON.parse(readFileSync(new URL('../mappings/soc-fw-flows-mappings.json', import.meta.url), 'utf8'));
  const f = (path) => path.split('.').reduce((node, name) => node?.properties?.[name], flows);
  assert.equal(flows.dynamic, false);
  for (const name of ['fw.sessions', 'fw.bytes_sent', 'fw.bytes_received', 'fw.bytes_total']) assert.equal(f(name)?.type, 'long', name);
  assert.equal(f('source.ip')?.type, 'ip');
  assert.equal(f('computed_at')?.type, 'date');
  const template = JSON.parse(readFileSync(new URL('../templates/index-soc-fw-flows.json', import.meta.url), 'utf8'));
  assert.deepEqual(template.composed_of, ['soc-fw-flows-mappings']);
  assert.equal(template.template.settings['index.lifecycle.name'], 'soc-history-retention');
});
