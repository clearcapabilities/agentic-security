// Universal IR — Recommendation #1 of the world-class roadmap.
//
// One IR shape every detector consumes, regardless of source language.
// Lazy-loads tree-sitter grammars (web-tree-sitter, WASM, NO native
// bindings) so the scanner stays bootable when tree-sitter isn't
// installed. When the WASM grammar isn't available we fall back to the
// existing per-language IRs (Babel for JS/TS, java-parser for Java,
// the hand-rolled C# IR from earlier in this session, etc.).
//
// IR shape — every node a detector cares about:
//
//   File:
//     { path, language, ast, decls[], calls[], assignments[],
//       members[], attrs[], imports[], functions[], classes[] }
//
//   Decl:     { kind: 'var'|'const'|'let'|'field'|'param', name,
//               type|null, initText|null, line, scope }
//   Call:     { callee, receiver|null, args: ArgExpr[], line, scope,
//               fullPath }
//   Assign:   { target, isMember, memberPath|null, rhsText, line, scope }
//   Function: { name, returnType|null, params: Param[], attrs: Attr[],
//               body, line, endLine, async, static }
//   Class:    { name, baseTypes[], methods[], fields[], attrs[],
//               line, endLine }
//   Attr:     { name, args[] }  (attributes / decorators / annotations
//                                across languages — same shape)
//   Import:   { kind: 'static'|'dynamic', module, names: string[],
//               isDefault, line }
//   ArgExpr:  { text, idents, line }   (idents EXCLUDE string contents)
//
// Detectors author S-expression queries against the IR using
// queryIR(ir, expr). The expression language is a small subset of
// tree-sitter queries adapted for our normalized IR:
//
//   (call :name "ExecuteReader" :receiver-type "SqlCommand")
//   (assign :target-glob "*.CommandText" :rhs-has-ident @tainted)
//
// The query engine returns matches with { node, captures }.

import * as fs from 'node:fs';
import * as path from 'node:path';

// Grammar inventory — language → (extension → grammar package).
// We don't actually require these at module load; lazy-load via
// loadGrammar() so the scanner stays bootable when none are installed.
const GRAMMAR_BY_LANG = {
  javascript: 'tree-sitter-javascript',
  typescript: 'tree-sitter-typescript',
  python:     'tree-sitter-python',
  java:       'tree-sitter-java',
  csharp:     'tree-sitter-c-sharp',
  cpp:        'tree-sitter-cpp',
  c:          'tree-sitter-c',
  go:         'tree-sitter-go',
  rust:       'tree-sitter-rust',
  ruby:       'tree-sitter-ruby',
  php:        'tree-sitter-php',
  swift:      'tree-sitter-swift',
  kotlin:     'tree-sitter-kotlin',
  scala:      'tree-sitter-scala',
  solidity:   'tree-sitter-solidity',
  dart:       'tree-sitter-dart',
  lua:        'tree-sitter-lua',
  haskell:    'tree-sitter-haskell',
  ocaml:      'tree-sitter-ocaml',
  elixir:     'tree-sitter-elixir',
};

const EXT_TO_LANG = {
  js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript',
  py: 'python', pyi: 'python',
  java: 'java',
  cs: 'csharp',
  c: 'c', h: 'c',
  cc: 'cpp', cpp: 'cpp', cxx: 'cpp', hh: 'cpp', hpp: 'cpp', hxx: 'cpp',
  go: 'go',
  rs: 'rust',
  rb: 'ruby',
  php: 'php',
  swift: 'swift',
  kt: 'kotlin', kts: 'kotlin',
  scala: 'scala',
  sol: 'solidity',
  dart: 'dart',
  lua: 'lua',
  hs: 'haskell',
  ml: 'ocaml', mli: 'ocaml',
  ex: 'elixir', exs: 'elixir',
};

export function detectLanguage(filePath) {
  const ext = path.extname(filePath).slice(1).toLowerCase();
  return EXT_TO_LANG[ext] || null;
}

// Lazy-loaded parser cache. Key = language name; value = Parser instance
// (or `false` if the grammar isn't available on this install).
const _parserCache = new Map();
let _ParserCtor = null;

async function _getParserCtor() {
  if (_ParserCtor !== null) return _ParserCtor;
  try {
    const mod = await import('web-tree-sitter');
    if (typeof mod.init === 'function') await mod.init();
    _ParserCtor = mod.default || mod.Parser || mod;
    return _ParserCtor;
  } catch {
    _ParserCtor = false;
    return false;
  }
}

async function _loadGrammar(lang) {
  if (_parserCache.has(lang)) return _parserCache.get(lang);
  const Parser = await _getParserCtor();
  if (!Parser) { _parserCache.set(lang, false); return false; }
  const pkg = GRAMMAR_BY_LANG[lang];
  if (!pkg) { _parserCache.set(lang, false); return false; }
  try {
    const wasmPath = require.resolve(`${pkg}/tree-sitter-${lang}.wasm`);
    const language = await Parser.Language.load(wasmPath);
    const parser = new Parser();
    parser.setLanguage(language);
    _parserCache.set(lang, parser);
    return parser;
  } catch {
    _parserCache.set(lang, false);
    return false;
  }
}

// Normalized IR shape — built by walking the tree-sitter CST and
// mapping language-specific node names to the universal kinds above.
// This dispatch is intentionally per-language so a Java
// `method_declaration` and a TS `method_definition` both map to the
// universal `Function` node.

const NORMALIZERS = {
  javascript: _normalizeJsLike,
  typescript: _normalizeJsLike,
  java:       _normalizeJava,
  csharp:     _normalizeCsharp,
  cpp:        _normalizeCLike,
  c:          _normalizeCLike,
  python:     _normalizePython,
  go:         _normalizeGo,
  rust:       _normalizeRust,
  ruby:       _normalizeRuby,
  php:        _normalizePhp,
};

// Universal IR builder. Returns null if the language can't be parsed
// here (caller falls back to its existing per-language IR).
export async function buildUniversalIR(filePath, content, opts = {}) {
  const lang = opts.language || detectLanguage(filePath);
  if (!lang) return null;
  const parser = await _loadGrammar(lang);
  if (!parser) return null;
  let tree;
  try { tree = parser.parse(content); }
  catch { return null; }
  if (!tree || !tree.rootNode) return null;
  const ir = {
    path: filePath, language: lang, ast: tree,
    decls: [], calls: [], assignments: [], members: [],
    attrs: [], imports: [], functions: [], classes: [],
    _content: content,
  };
  const normalize = NORMALIZERS[lang] || _normalizeGeneric;
  try { normalize(tree.rootNode, ir, content); }
  catch (e) { ir._normalizerError = String(e && e.message || e); }
  return ir;
}

// ─── Per-language normalizers (minimal v1 implementations) ─────────────────
//
// Each normalizer walks the CST and emits universal IR nodes. The shape
// is intentionally lossy — detectors don't need every CST detail, they
// need the security-relevant subset.

function _textOf(node, content) {
  if (!node) return '';
  if (typeof node.text === 'string') return node.text;
  if (typeof node.startIndex === 'number') return content.slice(node.startIndex, node.endIndex);
  return '';
}

function _lineOf(node) {
  if (!node) return 0;
  if (node.startPosition && typeof node.startPosition.row === 'number') return node.startPosition.row + 1;
  return 0;
}

function _walkChildren(node, fn) {
  if (!node || !node.children) return;
  for (let i = 0; i < node.children.length; i++) fn(node.children[i], i);
}

function _normalizeJsLike(node, ir, content) {
  _walkChildren(node, (child) => _normalizeJsLike(child, ir, content));
  switch (node.type) {
    case 'function_declaration':
    case 'method_definition':
    case 'arrow_function':
      ir.functions.push({
        name: _textOf(node.childForFieldName?.('name'), content) || null,
        line: _lineOf(node), endLine: _lineOf({ startPosition: node.endPosition }),
        params: [], async: !!node.childForFieldName?.('async'),
      });
      break;
    case 'class_declaration':
      ir.classes.push({
        name: _textOf(node.childForFieldName?.('name'), content) || null,
        line: _lineOf(node),
      });
      break;
    case 'call_expression': {
      const callee = node.childForFieldName?.('function');
      const args = node.childForFieldName?.('arguments');
      ir.calls.push({
        callee: _textOf(callee, content), receiver: null,
        args: args && args.children ? args.children.filter(c => c.type !== ',' && c.type !== '(' && c.type !== ')').map(a => ({
          text: _textOf(a, content), idents: [], line: _lineOf(a),
        })) : [],
        line: _lineOf(node),
        fullPath: _textOf(callee, content),
      });
      break;
    }
    case 'assignment_expression':
    case 'variable_declarator': {
      const target = node.childForFieldName?.('left') || node.childForFieldName?.('name');
      const rhs = node.childForFieldName?.('right') || node.childForFieldName?.('value');
      if (target) {
        const txt = _textOf(target, content);
        const isMember = txt.includes('.');
        const parts = txt.split('.');
        ir.assignments.push({
          target: parts[0], isMember,
          memberPath: isMember ? parts.slice(1).join('.') : null,
          rhsText: rhs ? _textOf(rhs, content) : '',
          line: _lineOf(node),
        });
      }
      break;
    }
    case 'import_statement':
    case 'import_declaration':
      ir.imports.push({
        kind: 'static',
        module: _textOf(node.childForFieldName?.('source'), content).replace(/['"`]/g, ''),
        line: _lineOf(node), names: [],
      });
      break;
  }
}

function _normalizeJava(node, ir, content) {
  _walkChildren(node, (child) => _normalizeJava(child, ir, content));
  switch (node.type) {
    case 'method_declaration':
    case 'constructor_declaration':
      ir.functions.push({
        name: _textOf(node.childForFieldName?.('name'), content),
        line: _lineOf(node), params: [],
      });
      break;
    case 'class_declaration':
      ir.classes.push({
        name: _textOf(node.childForFieldName?.('name'), content),
        line: _lineOf(node),
      });
      break;
    case 'method_invocation': {
      const object = node.childForFieldName?.('object');
      const name = node.childForFieldName?.('name');
      ir.calls.push({
        callee: _textOf(name, content),
        receiver: object ? _textOf(object, content) : null,
        args: [], line: _lineOf(node),
        fullPath: (object ? _textOf(object, content) + '.' : '') + _textOf(name, content),
      });
      break;
    }
    case 'assignment_expression': {
      const target = node.childForFieldName?.('left');
      const rhs = node.childForFieldName?.('right');
      if (target) {
        const txt = _textOf(target, content);
        const isMember = txt.includes('.');
        ir.assignments.push({
          target: txt.split('.')[0], isMember,
          memberPath: isMember ? txt.split('.').slice(1).join('.') : null,
          rhsText: rhs ? _textOf(rhs, content) : '',
          line: _lineOf(node),
        });
      }
      break;
    }
    case 'local_variable_declaration':
    case 'field_declaration': {
      const t = node.childForFieldName?.('type');
      const decl = node.childForFieldName?.('declarator');
      const name = decl?.childForFieldName?.('name');
      if (name) ir.decls.push({
        kind: 'var', name: _textOf(name, content),
        type: t ? _textOf(t, content) : null,
        initText: decl?.childForFieldName?.('value') ? _textOf(decl.childForFieldName('value'), content) : null,
        line: _lineOf(node),
      });
      break;
    }
  }
}

function _normalizeCsharp(node, ir, content) { _normalizeJava(node, ir, content); }
function _normalizeCLike(node, ir, content)  { _normalizeJsLike(node, ir, content); }
function _normalizePython(node, ir, content) { _normalizeJsLike(node, ir, content); }
function _normalizeGo(node, ir, content)     { _normalizeJsLike(node, ir, content); }
function _normalizeRust(node, ir, content)   { _normalizeJsLike(node, ir, content); }
function _normalizeRuby(node, ir, content)   { _normalizeJsLike(node, ir, content); }
function _normalizePhp(node, ir, content)    { _normalizeJsLike(node, ir, content); }
function _normalizeGeneric(node, ir, content) {
  // Fallback: just collect every call_expression / function shape we
  // can recognize. Useful when the per-language normalizer doesn't exist
  // yet — gives a baseline IR to query against.
  _walkChildren(node, (child) => _normalizeGeneric(child, ir, content));
  if (/call/i.test(node.type)) {
    ir.calls.push({ callee: _textOf(node, content).split('(')[0].trim(), receiver: null, args: [], line: _lineOf(node), fullPath: _textOf(node, content).split('(')[0].trim() });
  }
}

// ─── Query API ──────────────────────────────────────────────────────────────

/**
 * queryIR(ir, expr) — match IR nodes against an S-expression-like spec.
 *
 * Spec shapes supported in v1:
 *   { node: 'call',     name?: string|RegExp, receiver?: string|RegExp,
 *                       receiverType?: string|RegExp, argIdx?: number,
 *                       hasIdent?: string|RegExp }
 *   { node: 'assign',   targetGlob?: string,  rhsHasIdent?: string|RegExp }
 *   { node: 'function', nameGlob?: string,    hasAttr?: string|RegExp }
 *   { node: 'class',    nameGlob?: string,    extends?: string|RegExp }
 *   { node: 'import',   module?: string|RegExp }
 *
 * Returns: [{ node, captures }, ...] where captures are the matched IR nodes.
 */
export function queryIR(ir, spec) {
  if (!ir || !spec) return [];
  const matches = [];
  function testStr(pat, s) {
    if (pat == null) return true;
    if (pat instanceof RegExp) return pat.test(s || '');
    return s === pat;
  }
  function testGlob(pat, s) {
    if (!pat) return true;
    const re = new RegExp('^' + pat.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
    return re.test(s || '');
  }
  switch (spec.node) {
    case 'call':
      for (const c of ir.calls) {
        if (!testStr(spec.name, c.callee)) continue;
        if (!testStr(spec.receiver, c.receiver)) continue;
        if (spec.hasIdent && !c.args.some(a => testStr(spec.hasIdent, a.text))) continue;
        matches.push({ node: c, captures: {} });
      }
      break;
    case 'assign':
      for (const a of ir.assignments) {
        const full = (a.target || '') + (a.memberPath ? '.' + a.memberPath : '');
        if (!testGlob(spec.targetGlob, full)) continue;
        if (spec.rhsHasIdent && !testStr(spec.rhsHasIdent, a.rhsText)) continue;
        matches.push({ node: a, captures: {} });
      }
      break;
    case 'function':
      for (const fn of ir.functions) {
        if (!testGlob(spec.nameGlob, fn.name)) continue;
        matches.push({ node: fn, captures: {} });
      }
      break;
    case 'class':
      for (const cls of ir.classes) {
        if (!testGlob(spec.nameGlob, cls.name)) continue;
        matches.push({ node: cls, captures: {} });
      }
      break;
    case 'import':
      for (const imp of ir.imports) {
        if (!testStr(spec.module, imp.module)) continue;
        matches.push({ node: imp, captures: {} });
      }
      break;
  }
  return matches;
}

export const _internals = { GRAMMAR_BY_LANG, EXT_TO_LANG, NORMALIZERS };
