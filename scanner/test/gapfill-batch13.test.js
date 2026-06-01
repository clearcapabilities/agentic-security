// Tier-4 batch-13 detector extensions: cross-language ReDoS, weak password
// hash, open redirect, deserialization, PHP SSRF.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRegexReDoS } from '../src/sast/redos-nfa.js';
import { scanWeakPasswordHash } from '../src/sast/weak-password-hash.js';
import { scanOpenRedirect } from '../src/sast/open-redirect.js';
import { scanRuby } from '../src/sast/ruby.js';
import { scanGoStructural } from '../src/sast/go-structural.js';
import { scanPhp } from '../src/sast/php.js';

const has = (arr, cwe) => arr.some((f) => f.cwe === cwe);
const none = (arr, cwe) => arr.every((f) => f.cwe !== cwe);

test('ReDoS — catastrophic regex flagged in Java/PHP/C#/Kotlin/Ruby; safe regex clean', () => {
  assert.ok(has(scanRegexReDoS('R.java', 'Pattern.compile("(a+)+$")'), 'CWE-1333'));
  assert.ok(has(scanRegexReDoS('r.php', '<?php preg_match("/(a+)+$/", $s);'), 'CWE-1333'));
  assert.ok(has(scanRegexReDoS('R.cs', 'Regex.IsMatch(s, "(a+)+$")'), 'CWE-1333'));
  assert.ok(has(scanRegexReDoS('R.kt', 'Regex("(a+)+$").matches(s)'), 'CWE-1333'));
  assert.ok(has(scanRegexReDoS('r.rb', 'x =~ /(a+)+$/'), 'CWE-1333'));
  assert.ok(none(scanRegexReDoS('R.java', 'Pattern.compile("^a+$")'), 'CWE-1333'));
});

test('weak password hash — MD5/SHA1 in password context fires for Ruby/C#/Kotlin/PHP/Python', () => {
  assert.ok(has(scanWeakPasswordHash('h.rb', 'def store(password)\n  Digest::MD5.hexdigest(password)\nend'), 'CWE-916'));
  assert.ok(has(scanWeakPasswordHash('H.cs', 'class H { byte[] f(string password){ return MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password)); } }'), 'CWE-916'));
  assert.ok(has(scanWeakPasswordHash('H.kt', 'fun f(password: String) = MessageDigest.getInstance("MD5").digest(password.toByteArray())'), 'CWE-916'));
  assert.ok(has(scanWeakPasswordHash('h.php', '<?php function f($password){ return md5($password); }'), 'CWE-916'));
  // bcrypt nearby suppresses
  assert.ok(none(scanWeakPasswordHash('h.rb', 'def store(password)\n  BCrypt::Password.create(password)\nend'), 'CWE-916'));
});

test('open redirect — Go/Ruby/PHP/C#/Kotlin fire; allow-listed clean', () => {
  assert.ok(has(scanOpenRedirect('r.go', 'package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request){ http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound) }'), 'CWE-601'));
  assert.ok(has(scanOpenRedirect('r.rb', 'def go\n  redirect_to params[:next]\nend'), 'CWE-601'));
  assert.ok(has(scanOpenRedirect('r.php', '<?php header("Location: " . $_GET["next"]);'), 'CWE-601'));
  assert.ok(has(scanOpenRedirect('R.cs', 'class R { IActionResult Go(string next){ return Redirect(next); } }'), 'CWE-601'));
  assert.ok(has(scanOpenRedirect('R.kt', 'fun go(next: String, resp: HttpServletResponse){ resp.sendRedirect(next) }'), 'CWE-601'));
  // allow-listed / local-only → clean
  assert.ok(none(scanOpenRedirect('r.rb', 'def go\n  redirect_to params[:next], only_path: true\nend'), 'CWE-601'));
  assert.ok(none(scanOpenRedirect('r.php', '<?php $n = in_array($_GET["next"], $allow, true) ? $_GET["next"] : "/"; header("Location: " . $n);'), 'CWE-601'));
  // literal target → clean
  assert.ok(none(scanOpenRedirect('r.go', 'package main\nimport "net/http"\nfunc h(w http.ResponseWriter, r *http.Request){ http.Redirect(w, r, "/home", http.StatusFound) }'), 'CWE-601'));
});

test('deserialization — Ruby Marshal.load (var) and Go gob fire', () => {
  assert.ok(has(scanRuby('c.rb', 'def load(blob)\n  Marshal.load(blob)\nend'), 'CWE-502'));
  assert.ok(has(scanGoStructural('d.go', 'package main\nimport ("bytes";"encoding/gob")\nfunc d(b []byte){ var v any; gob.NewDecoder(bytes.NewReader(b)).Decode(&v) }'), 'CWE-502'));
  // bare-literal Marshal.load is not flagged by the structural rule
  assert.ok(none(scanRuby('c.rb', 'Marshal.load("static")'), 'CWE-502'));
});

test('PHP SSRF — cURL fetch of $_GET URL fires', () => {
  assert.ok(has(scanPhp('s.php', '<?php $ch = curl_init($_GET["url"]); curl_exec($ch);'), 'CWE-918'));
});
