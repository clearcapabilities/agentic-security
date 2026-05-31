// Kotlin structural (taint-independent) injection detectors — roadmap Tier 1.
// These close the 6 Kotlin false-negatives in the CVE-replay corpus: a
// dangerous sink built with a string template / concat (or insecure XML/deser
// config) is the vuln shape regardless of variable names, which the taint
// engine misses on standalone DAO/handler methods that have no in-file source.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanKotlin } from '../src/sast/kotlin.js';

const has = (findings, cwe) => findings.some(f => f.cwe === cwe);

test('SQL injection — string template in executeQuery (CWE-89)', () => {
  const v = scanKotlin('UserDao.kt', 'fun find(name: String){ stmt.executeQuery("SELECT * FROM u WHERE n=\'${name}\'") }');
  assert.ok(has(v, 'CWE-89'));
  // parameterized → clean
  assert.equal(scanKotlin('UserDao.kt', 'fun find(name: String){ val p = conn.prepareStatement("SELECT * FROM u WHERE n = ?"); p.setString(1, name) }').filter(f => f.cwe === 'CWE-89').length, 0);
});

test('Command injection — concat in Runtime.exec (CWE-78)', () => {
  assert.ok(has(scanKotlin('App.kt', 'fun h(host: String){ Runtime.getRuntime().exec("ping -c 1 " + host) }'), 'CWE-78'));
  assert.equal(scanKotlin('App.kt', 'fun h(host: String){ ProcessBuilder(listOf("ping","-c","1",host)).start() }').filter(f => f.cwe === 'CWE-78').length, 0);
});

test('Path traversal — concat/template in File() (CWE-22)', () => {
  assert.ok(has(scanKotlin('Files.kt', 'fun read(name: String){ File("/var/data/" + name).readText() }'), 'CWE-22'));
});

test('SSRF — URL from a non-literal, suppressed by a host guard (CWE-918)', () => {
  assert.ok(has(scanKotlin('Proxy.kt', 'fun f(raw: String){ URL(raw).readText() }'), 'CWE-918'));
  assert.equal(scanKotlin('Proxy.kt', 'fun f(raw: String){ val u = URL(raw); require(u.host !in setOf("169.254.169.254")); u.readText() }').filter(f => f.cwe === 'CWE-918').length, 0);
  // literal URL → not flagged
  assert.equal(scanKotlin('Proxy.kt', 'fun f(){ URL("https://fixed.example.com").readText() }').filter(f => f.cwe === 'CWE-918').length, 0);
});

test('XXE — XML factory without secure processing, guard suppresses (CWE-611)', () => {
  assert.ok(has(scanKotlin('Parse.kt', 'fun p(xml: ByteArray){ val f = DocumentBuilderFactory.newInstance(); f.newDocumentBuilder().parse(ByteArrayInputStream(xml)) }'), 'CWE-611'));
  assert.equal(scanKotlin('Parse.kt', 'fun p(){ val f = DocumentBuilderFactory.newInstance(); f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); f.newDocumentBuilder() }').filter(f => f.cwe === 'CWE-611').length, 0);
});

test('Insecure deserialization — ObjectInputStream.readObject (CWE-502)', () => {
  assert.ok(has(scanKotlin('Deser.kt', 'fun d(b: ByteArray): Any { val o = ObjectInputStream(ByteArrayInputStream(b)); return o.readObject() }'), 'CWE-502'));
});

test('no findings on a fully-clean Kotlin file', () => {
  assert.deepEqual(scanKotlin('Clean.kt', 'fun add(a: Int, b: Int): Int = a + b'), []);
});
