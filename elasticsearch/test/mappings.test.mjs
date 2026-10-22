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
