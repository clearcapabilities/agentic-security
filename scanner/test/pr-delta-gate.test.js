// R24 — net-new CI gate tests. Pure: blocks only on introduced findings.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { netNewGate } from '../src/pr-delta.js';

const delta = (introduced) => ({
  introduced,
  // persistent/resolved must be IRRELEVANT to the gate — include some to prove it.
  persistent: [{ severity: 'critical', vuln: 'pre-existing crit' }],
  resolved: [{ severity: 'high' }],
});

test('blocks on an introduced finding at/above threshold', () => {
  const g = netNewGate(delta([{ severity: 'critical', vuln: 'X' }, { severity: 'low' }]), 'critical');
  assert.equal(g.fail, true);
  assert.equal(g.blocked.length, 1);
  assert.equal(g.introducedCount, 2);
});

test('pre-existing (persistent) findings never fail the gate', () => {
  // No introduced findings, but a persistent CRITICAL exists → must pass.
  const g = netNewGate(delta([]), 'critical');
  assert.equal(g.fail, false);
  assert.equal(g.blocked.length, 0);
});

test('threshold respected: low/medium introduced does not trip fail-on=critical', () => {
  assert.equal(netNewGate(delta([{ severity: 'low' }, { severity: 'medium' }]), 'critical').fail, false);
});

test('fail-on=medium trips on an introduced medium', () => {
  const g = netNewGate(delta([{ severity: 'medium', vuln: 'M' }]), 'medium');
  assert.equal(g.fail, true);
});

test('fail-on=none never fails', () => {
  assert.equal(netNewGate(delta([{ severity: 'critical' }]), 'none').fail, false);
});

test('tolerates a malformed delta', () => {
  assert.equal(netNewGate(null, 'critical').fail, false);
  assert.equal(netNewGate({}, 'high').fail, false);
});
