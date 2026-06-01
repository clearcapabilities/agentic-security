// R11 — OpenVEX export tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toVex } from '../src/report/index.js';

const scan = {
  supplyChain: [
    { type: 'vulnerable_dep', name: 'lodash', ecosystem: 'npm', version: '4.17.20',
      purl: 'pkg:npm/lodash@4.17.20', cveAliases: ['CVE-2020-8203', 'CVE-2021-23337'],
      reachabilityTier: 'function-reachable', scaVerdictReason: 'patch bump to 4.17.21', fixedVersions: ['4.17.21'] },
    { type: 'vulnerable_dep', name: 'left-pad', ecosystem: 'npm', version: '1.0.0',
      osvId: 'GHSA-xxxx', reachabilityTier: 'transitive-only' },
    { type: 'vulnerable_dep', name: 'foo', ecosystem: 'pypi', version: '1.0',
      osvId: 'PYSEC-1', reachabilityTier: 'import-reachable' },
    { type: 'vulnerable_dep', name: 'bar', ecosystem: 'npm', version: '2.0', osvId: 'CVE-X', reachabilityTier: undefined },
    { type: 'unpinned_dep', name: 'ignored' }, // must be skipped
  ],
};

test('toVex emits a valid OpenVEX document', () => {
  const doc = toVex(scan, { scanId: 's1', startedAt: '2026-06-01T00:00:00Z' });
  assert.equal(doc['@context'], 'https://openvex.dev/ns/v0.2.0');
  assert.equal(doc.author, 'agentic-security');
  assert.equal(doc.version, 1);
  assert.ok(Array.isArray(doc.statements));
});

test('reachability → VEX status mapping', () => {
  const doc = toVex(scan, {});
  const byCve = Object.fromEntries(doc.statements.map(s => [s.vulnerability.name, s]));
  // function-reachable → affected (one statement per CVE alias)
  assert.equal(byCve['CVE-2020-8203'].status, 'affected');
  assert.equal(byCve['CVE-2021-23337'].status, 'affected');
  assert.match(byCve['CVE-2020-8203'].action_statement, /4\.17\.21/);
  // transitive-only → not_affected with the execute-path justification
  assert.equal(byCve['GHSA-xxxx'].status, 'not_affected');
  assert.equal(byCve['GHSA-xxxx'].justification, 'vulnerable_code_not_in_execute_path');
  // import-reachable → affected
  assert.equal(byCve['PYSEC-1'].status, 'affected');
  // unknown tier → under_investigation
  assert.equal(byCve['CVE-X'].status, 'under_investigation');
});

test('skips non-vulnerable_dep entries and deps without a CVE id', () => {
  const doc = toVex(scan, {});
  // 2 (lodash aliases) + 1 (left-pad) + 1 (foo) + 1 (bar) = 5 statements; unpinned_dep skipped.
  assert.equal(doc.statements.length, 5);
  assert.ok(doc.statements.every(s => s.products[0]['@id'].startsWith('pkg:')));
});
