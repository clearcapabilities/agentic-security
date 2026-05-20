// Expanded sanitizer catalog tests.
//
// Asserts the merged catalog is well-formed and significantly larger than
// before — the whole point of this round is moving from "mid-tier" sanitizer
// coverage to a 500+-entry surface.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CATALOG, _catalogSize } from '../src/dataflow/catalog.js';
import { EXPANDED_SANITIZERS, _expandedSanitizerStats } from '../src/dataflow/catalog-expanded.js';

const ALL_SANITIZERS = CATALOG.filter(e => e.kind === 'sanitizer');

test('expanded sanitizer module exports at least 300 entries', () => {
  assert.ok(EXPANDED_SANITIZERS.length >= 300,
    `expected >= 300 expanded sanitizers, got ${EXPANDED_SANITIZERS.length}`);
});

test('merged catalog has >= 300 total sanitizers (was ~48 before expansion)', () => {
  assert.ok(ALL_SANITIZERS.length >= 300,
    `expected >= 300 merged sanitizers, got ${ALL_SANITIZERS.length}`);
});

test('per-language coverage hits minimum thresholds', () => {
  const byLang = {};
  for (const s of ALL_SANITIZERS) byLang[s.language] = (byLang[s.language] || 0) + 1;
  // Top three languages get strong coverage; minor languages get enough to
  // be useful but not exhaustive.
  assert.ok((byLang.js  || 0) >= 80, `js sanitizers: ${byLang.js || 0} < 80`);
  assert.ok((byLang.py  || 0) >= 80, `py sanitizers: ${byLang.py || 0} < 80`);
  assert.ok((byLang.java|| 0) >= 40, `java sanitizers: ${byLang.java || 0} < 40`);
  assert.ok((byLang.rb  || 0) >= 20, `rb sanitizers: ${byLang.rb || 0} < 20`);
  assert.ok((byLang.php || 0) >= 20, `php sanitizers: ${byLang.php || 0} < 20`);
  assert.ok((byLang.go  || 0) >= 20, `go sanitizers: ${byLang.go || 0} < 20`);
});

test('all expanded entries carry the required shape', () => {
  for (const e of EXPANDED_SANITIZERS) {
    assert.equal(e.kind, 'sanitizer', `entry ${e.id} not a sanitizer`);
    assert.ok(typeof e.id === 'string' && e.id.length > 0, 'missing id');
    assert.ok(typeof e.language === 'string', `${e.id} missing language`);
    assert.ok(e.match && e.match.type === 'call' && typeof e.match.callee === 'string',
      `${e.id} missing match.callee`);
    assert.ok(typeof e.effect === 'string', `${e.id} missing effect`);
    assert.ok(Array.isArray(e.appliesTo) && e.appliesTo.length > 0,
      `${e.id} missing appliesTo`);
  }
});

test('no duplicate IDs across the entire merged catalog', () => {
  const seen = new Map();
  for (const e of CATALOG) {
    if (!e.id) continue;
    if (seen.has(e.id)) {
      assert.fail(`duplicate id "${e.id}" — first seen ${seen.get(e.id)}`);
    }
    seen.set(e.id, `${e.kind} ${e.language || ''}`);
  }
});

test('appliesTo values are from the documented family vocabulary', () => {
  // The dataflow engine uses these family tags to scope sanitization effects.
  // Adding a new family is fine; this test catches typos like 'xxss' / 'xsss'.
  const KNOWN_FAMILIES = new Set([
    'xss', 'sql', 'cmd', 'url', 'path', 'regex', 'ldap', 'xpath', 'xml',
    'xxe', 'json', 'mongo-operator', 'ssrf', 'deserial', 'redos', '*',
  ]);
  for (const e of EXPANDED_SANITIZERS) {
    for (const family of e.appliesTo) {
      if (!KNOWN_FAMILIES.has(family)) {
        assert.fail(`${e.id}: unknown family "${family}" — add to KNOWN_FAMILIES if intentional`);
      }
    }
  }
});

test('every expanded entry indexes by callee name', () => {
  // Sanity: matchSinkOrSanitizer looks up by the final identifier in the
  // callee path. Confirm none of our entries accidentally have a callee
  // shape that won't be matched (e.g. a dotted path where the final
  // segment is empty).
  for (const e of EXPANDED_SANITIZERS) {
    const tail = String(e.match.callee).split('.').pop();
    assert.ok(tail && /^[A-Za-z_][\w$]*$/.test(tail),
      `${e.id}: callee "${e.match.callee}" has unmatchable tail`);
  }
});

test('_expandedSanitizerStats reports total + by-language', () => {
  const s = _expandedSanitizerStats();
  assert.equal(s.total, EXPANDED_SANITIZERS.length);
  for (const lang of ['js', 'py', 'java', 'rb', 'php', 'go']) {
    assert.ok(typeof s.byLanguage[lang] === 'number');
  }
});

test('CATALOG size sanity: now >> the pre-expansion baseline', () => {
  // Before this round: ~200 entries. After: 500+.
  const n = _catalogSize();
  assert.ok(n >= 500, `expected >= 500 catalog entries, got ${n}`);
});
