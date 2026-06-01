// R10 — Gradle transitive dependency graph parsing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifests } from '../src/engine.js';

const GRADLE_OUTPUT = `
compileClasspath - Compile classpath for source set 'main'.
+--- org.springframework:spring-core:5.3.20
|    \\--- org.springframework:spring-jcl:5.3.20
+--- com.google.guava:guava:30.0-jre -> 31.1-jre
\\--- com.fasterxml.jackson.core:jackson-databind:2.13.0 (*)

testCompileClasspath - Test compile classpath
\\--- org.junit.jupiter:junit-jupiter:5.8.2
`;

test('parses gradle dependencies tree: direct + transitive + resolved version', () => {
  const comps = parseManifests({ 'gradle-dependencies.txt': GRADLE_OUTPUT });
  const by = Object.fromEntries(comps.map(c => [c.name, c]));

  // Direct dep
  assert.ok(by['org.springframework:spring-core'], 'spring-core present');
  assert.equal(by['org.springframework:spring-core'].version, '5.3.20');
  assert.equal(by['org.springframework:spring-core'].ecosystem, 'maven');

  // Transitive dep (indented under spring-core)
  assert.ok(by['org.springframework:spring-jcl'], 'spring-jcl (transitive) present');
  assert.equal(by['org.springframework:spring-jcl'].isTransitive, true);

  // Conflict-resolved version: 30.0-jre -> 31.1-jre must record the resolved one
  assert.equal(by['com.google.guava:guava'].version, '31.1-jre');

  // (*) marker stripped, dep still parsed
  assert.ok(by['com.fasterxml.jackson.core:jackson-databind']);
});

test('config headers and blank lines produce no spurious components', () => {
  const comps = parseManifests({ 'gradle-dependencies.txt': GRADLE_OUTPUT });
  assert.ok(comps.every(c => c.name.includes(':')), 'every component is a group:artifact');
  // 5 real deps in the fixture
  assert.equal(comps.filter(c => c.ecosystem === 'maven').length, 5);
});
