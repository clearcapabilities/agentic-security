// C# tokenizer — produces a token stream that respects C# string/comment
// semantics, so downstream detectors don't have to dodge string literals and
// commented-out code the way regex-on-raw-text does.
//
// Token shape:
//   { kind, value, line, col, start, end }
//
// kinds:
//   'ident'        | identifier (letters, digits, _; can begin with '@' to escape keyword)
//   'kw'           | keyword (subset; only those that affect detector logic)
//   'num'          | numeric literal (int, float, hex, binary, with suffix)
//   'string'       | regular "..." string literal (escapes processed)
//   'verbatim'     | @"..." verbatim literal (no escape processing)
//   'interp'       | $"..." or $@"..." interpolated string; value is the
//                    raw source between the quotes; the embedded {expr} holes
//                    are kept as nested tokens via meta.parts (a list of
//                    {kind:'lit',text} | {kind:'expr',tokens} entries).
//   'char'         | '.' character literal
//   'op'           | punctuation / operator (=, ==, +, +=, &&, ?., null!, etc.)
//   'attr-open'    | '[' that begins an attribute (heuristic — see below)
//   'attr-close'   | ']' that closes an attribute
//   'lbrace'       | '{'
//   'rbrace'       | '}'
//   'lparen'       | '('
//   'rparen'       | ')'
//   'lbracket'     | '['  (non-attribute)
//   'rbracket'     | ']'  (non-attribute)
//   'comma'        | ','
//   'semi'         | ';'
//   'dot'          | '.'
//   'arrow'        | '=>'
//   'eof'          | end of input
//
// We do NOT produce 'comment' tokens — comments are stripped entirely. Line
// numbers stay correct because we count newlines we consume.
//
// The tokenizer is conservative: when it can't determine intent (e.g. is
// `[` an attribute start or an indexer?), it labels with the heuristic that
// best serves security detectors and never panics.

const KEYWORDS = new Set([
  'abstract', 'as', 'async', 'await', 'base', 'bool', 'break', 'byte', 'case',
  'catch', 'char', 'checked', 'class', 'const', 'continue', 'decimal', 'default',
  'delegate', 'do', 'double', 'else', 'enum', 'event', 'explicit', 'extern',
  'false', 'finally', 'fixed', 'float', 'for', 'foreach', 'goto', 'if',
  'implicit', 'in', 'int', 'interface', 'internal', 'is', 'lock', 'long',
  'namespace', 'new', 'null', 'object', 'operator', 'out', 'override', 'params',
  'partial', 'private', 'protected', 'public', 'readonly', 'ref', 'return',
  'sbyte', 'sealed', 'short', 'sizeof', 'stackalloc', 'static', 'string',
  'struct', 'switch', 'this', 'throw', 'true', 'try', 'typeof', 'uint',
  'ulong', 'unchecked', 'unsafe', 'ushort', 'using', 'var', 'virtual', 'void',
  'volatile', 'when', 'where', 'while', 'yield',
]);

// Multi-char operator longest-match table; ordered longest-first.
const OPS = [
  '<<=', '>>=', '??=', '...',
  '==', '!=', '<=', '>=', '&&', '||', '<<', '>>',
  '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '=>', '??', '?.', '?[', '->',
  '+', '-', '*', '/', '%', '&', '|', '^', '~', '!', '=', '<', '>', '?', ':',
];

function isIdentStart(c) { return /[A-Za-z_]/.test(c); }
function isIdentCont(c)  { return /[A-Za-z0-9_]/.test(c); }
function isDigit(c)      { return c >= '0' && c <= '9'; }

class Reader {
  constructor(src) {
    this.src = src;
    this.i = 0;
    this.line = 1;
    this.col = 1;
  }
  eof() { return this.i >= this.src.length; }
  peek(off = 0) { return this.src[this.i + off]; }
  startsWith(s) { return this.src.startsWith(s, this.i); }
  advance(n = 1) {
    for (let k = 0; k < n && this.i < this.src.length; k++) {
      const c = this.src[this.i++];
      if (c === '\n') { this.line++; this.col = 1; } else { this.col++; }
    }
  }
  slice(from, to) { return this.src.slice(from, to); }
}

function skipWhitespaceAndComments(r) {
  while (!r.eof()) {
    const c = r.peek();
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r') { r.advance(); continue; }
    // Line comment
    if (c === '/' && r.peek(1) === '/') {
      while (!r.eof() && r.peek() !== '\n') r.advance();
      continue;
    }
    // Block comment
    if (c === '/' && r.peek(1) === '*') {
      r.advance(2);
      while (!r.eof() && !(r.peek() === '*' && r.peek(1) === '/')) r.advance();
      if (!r.eof()) r.advance(2);
      continue;
    }
    // Preprocessor directives — skip the entire line. We don't model them.
    if (c === '#' && r.col === 1) {
      while (!r.eof() && r.peek() !== '\n') r.advance();
      continue;
    }
    return;
  }
}

function readStringLiteral(r, startLine, startCol, kind = 'string') {
  // kind === 'string' for "...", 'verbatim' for @"...", 'interp' for $"..."
  const start = r.i;
  r.advance(); // opening "
  const value = [];
  while (!r.eof()) {
    const c = r.peek();
    if (kind === 'verbatim') {
      if (c === '"' && r.peek(1) === '"') { value.push('"'); r.advance(2); continue; }
      if (c === '"') { r.advance(); break; }
      value.push(c); r.advance();
    } else {
      if (c === '\\') {
        const next = r.peek(1) || '';
        // escape sequence; consume two chars for the common cases, more for \uXXXX
        if (next === 'u' || next === 'U') {
          const len = next === 'u' ? 4 : 8;
          value.push(r.slice(r.i, r.i + 2 + len));
          r.advance(2 + len);
        } else {
          value.push(c + next);
          r.advance(2);
        }
        continue;
      }
      if (c === '"') { r.advance(); break; }
      if (c === '\n' && kind !== 'verbatim') { /* malformed; stop */ break; }
      value.push(c); r.advance();
    }
  }
  return { kind, value: value.join(''), line: startLine, col: startCol, start, end: r.i };
}

function readInterpolatedString(r, startLine, startCol) {
  // $"..." or $@"..." — captures parts as { kind: 'lit'|'expr', text|tokens }
  const start = r.i;
  r.advance(); // $
  const isVerbatim = r.peek() === '@';
  if (isVerbatim) r.advance();
  if (r.peek() !== '"') {
    // not actually an interpolated string after all; back up to '$' as op
    r.i = start; r.line = startLine; r.col = startCol;
    return null;
  }
  r.advance(); // opening "
  const parts = [];
  let buf = [];
  const flushLit = () => { if (buf.length) { parts.push({ kind: 'lit', text: buf.join('') }); buf = []; } };
  while (!r.eof()) {
    const c = r.peek();
    if (c === '"') {
      // Verbatim: "" → literal "
      if (isVerbatim && r.peek(1) === '"') { buf.push('"'); r.advance(2); continue; }
      r.advance(); break;
    }
    if (c === '{') {
      if (r.peek(1) === '{') { buf.push('{'); r.advance(2); continue; }
      flushLit();
      r.advance();
      // Read raw text until matching '}', respecting nested braces.
      let depth = 1;
      const exprStart = r.i;
      while (!r.eof() && depth > 0) {
        const ch = r.peek();
        if (ch === '{') { depth++; r.advance(); continue; }
        if (ch === '}') { depth--; if (depth === 0) break; r.advance(); continue; }
        // Skip nested string literals inside interpolation holes — they
        // contain braces we don't want to count as expression braces.
        if (ch === '"') { skipInlineString(r); continue; }
        r.advance();
      }
      const exprText = r.slice(exprStart, r.i);
      if (!r.eof()) r.advance(); // consume '}'
      // Tokenize the embedded expression so detectors can see identifier
      // references like `userInput` inside `$"…{userInput}…"`.
      const tokens = tokenize(exprText, { embedded: true });
      parts.push({ kind: 'expr', text: exprText, tokens });
      continue;
    }
    if (!isVerbatim && c === '\\') {
      const next = r.peek(1) || '';
      buf.push(c + next); r.advance(2); continue;
    }
    buf.push(c); r.advance();
  }
  flushLit();
  return { kind: 'interp', verbatim: isVerbatim, parts, line: startLine, col: startCol, start, end: r.i };
}

function skipInlineString(r) {
  // Inside an interpolation hole there can be a nested string. Consume it
  // exactly so brace-counting around it is right.
  if (r.peek() !== '"') return;
  r.advance();
  while (!r.eof()) {
    const c = r.peek();
    if (c === '\\') { r.advance(2); continue; }
    if (c === '"') { r.advance(); return; }
    r.advance();
  }
}

function readCharLiteral(r, startLine, startCol) {
  const start = r.i;
  r.advance(); // '
  let v = '';
  while (!r.eof() && r.peek() !== "'") {
    if (r.peek() === '\\') { v += r.slice(r.i, r.i + 2); r.advance(2); continue; }
    v += r.peek(); r.advance();
  }
  if (!r.eof()) r.advance();
  return { kind: 'char', value: v, line: startLine, col: startCol, start, end: r.i };
}

function readNumber(r, startLine, startCol) {
  const start = r.i;
  // hex, binary, decimal — also handle suffixes (u, l, f, m, d).
  if (r.peek() === '0' && (r.peek(1) === 'x' || r.peek(1) === 'X')) {
    r.advance(2);
    while (!r.eof() && /[0-9A-Fa-f_]/.test(r.peek())) r.advance();
  } else if (r.peek() === '0' && (r.peek(1) === 'b' || r.peek(1) === 'B')) {
    r.advance(2);
    while (!r.eof() && /[01_]/.test(r.peek())) r.advance();
  } else {
    while (!r.eof() && (isDigit(r.peek()) || r.peek() === '_')) r.advance();
    if (r.peek() === '.' && isDigit(r.peek(1))) {
      r.advance();
      while (!r.eof() && (isDigit(r.peek()) || r.peek() === '_')) r.advance();
    }
    if (r.peek() === 'e' || r.peek() === 'E') {
      r.advance();
      if (r.peek() === '+' || r.peek() === '-') r.advance();
      while (!r.eof() && isDigit(r.peek())) r.advance();
    }
  }
  // Numeric suffixes
  while (!r.eof() && /[uUlLfFmMdD]/.test(r.peek())) r.advance();
  return { kind: 'num', value: r.slice(start, r.i), line: startLine, col: startCol, start, end: r.i };
}

function readIdentifier(r, startLine, startCol, allowAt = false) {
  const start = r.i;
  if (allowAt && r.peek() === '@') r.advance();
  while (!r.eof() && isIdentCont(r.peek())) r.advance();
  const value = r.slice(start, r.i);
  if (value.startsWith('@')) {
    // @class etc — strip the @ for matching, but mark the token as ident not kw
    return { kind: 'ident', value: value.slice(1), at: true, line: startLine, col: startCol, start, end: r.i };
  }
  return { kind: KEYWORDS.has(value) ? 'kw' : 'ident', value, line: startLine, col: startCol, start, end: r.i };
}

function readOperator(r, startLine, startCol) {
  for (const op of OPS) {
    if (r.startsWith(op)) {
      const start = r.i;
      r.advance(op.length);
      return { kind: 'op', value: op, line: startLine, col: startCol, start, end: r.i };
    }
  }
  // Single fallback
  const start = r.i;
  const ch = r.peek();
  r.advance();
  return { kind: 'op', value: ch, line: startLine, col: startCol, start, end: r.i };
}

// Heuristic attribute detection: a `[` that appears at statement-start
// position (after a newline / whitespace / `{`) and is followed by an
// identifier looks like an attribute. Indexers/array literals will fail
// this test because they follow an expression / identifier directly.
function looksLikeAttributeStart(r, prevToken) {
  if (!prevToken) return true;
  // Attribute if preceded by structural punctuation, NOT an expression.
  const k = prevToken.kind;
  if (k === 'lbrace' || k === 'rbrace' || k === 'semi' || k === 'attr-close') return true;
  if (k === 'kw' && (prevToken.value === 'public' || prevToken.value === 'private' || prevToken.value === 'protected' || prevToken.value === 'internal' || prevToken.value === 'static' || prevToken.value === 'override' || prevToken.value === 'virtual' || prevToken.value === 'abstract' || prevToken.value === 'sealed' || prevToken.value === 'partial' || prevToken.value === 'async')) return true;
  return false;
}

export function tokenize(src, opts = {}) {
  if (typeof src !== 'string' || !src.length) return [];
  const r = new Reader(src);
  const out = [];
  let prevToken = null;

  while (!r.eof()) {
    skipWhitespaceAndComments(r);
    if (r.eof()) break;
    const c = r.peek();
    const startLine = r.line, startCol = r.col;

    // Verbatim @"..." or @ident
    if (c === '@') {
      if (r.peek(1) === '"') {
        r.advance(); // consume @
        const tok = readStringLiteral(r, startLine, startCol, 'verbatim');
        out.push(tok); prevToken = tok; continue;
      }
      if (isIdentStart(r.peek(1)) || r.peek(1) === '_') {
        const tok = readIdentifier(r, startLine, startCol, true);
        out.push(tok); prevToken = tok; continue;
      }
    }

    // Interpolated $"..." or $@"..."
    if (c === '$') {
      if (r.peek(1) === '"' || (r.peek(1) === '@' && r.peek(2) === '"')) {
        const tok = readInterpolatedString(r, startLine, startCol);
        if (tok) { out.push(tok); prevToken = tok; continue; }
      }
    }

    if (c === '"') {
      const tok = readStringLiteral(r, startLine, startCol, 'string');
      out.push(tok); prevToken = tok; continue;
    }
    if (c === "'") {
      const tok = readCharLiteral(r, startLine, startCol);
      out.push(tok); prevToken = tok; continue;
    }
    if (isDigit(c)) {
      const tok = readNumber(r, startLine, startCol);
      out.push(tok); prevToken = tok; continue;
    }
    if (isIdentStart(c)) {
      const tok = readIdentifier(r, startLine, startCol);
      out.push(tok); prevToken = tok; continue;
    }
    // Structural punctuation
    if (c === '{') { r.advance(); const t = { kind: 'lbrace', value: '{', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }
    if (c === '}') { r.advance(); const t = { kind: 'rbrace', value: '}', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }
    if (c === '(') { r.advance(); const t = { kind: 'lparen', value: '(', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }
    if (c === ')') { r.advance(); const t = { kind: 'rparen', value: ')', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }
    if (c === '[') {
      r.advance();
      const isAttr = !opts.embedded && looksLikeAttributeStart(r, prevToken);
      const t = { kind: isAttr ? 'attr-open' : 'lbracket', value: '[', line: startLine, col: startCol, start: r.i - 1, end: r.i };
      out.push(t); prevToken = t; continue;
    }
    if (c === ']') {
      r.advance();
      // Match the most recent attr-open if open count is positive.
      let attrDepth = 0;
      for (let k = out.length - 1; k >= 0; k--) {
        if (out[k].kind === 'attr-open') attrDepth++;
        else if (out[k].kind === 'attr-close') attrDepth--;
        else if (out[k].kind === 'lbracket' || out[k].kind === 'rbracket') break;
      }
      const isAttr = attrDepth > 0;
      const t = { kind: isAttr ? 'attr-close' : 'rbracket', value: ']', line: startLine, col: startCol, start: r.i - 1, end: r.i };
      out.push(t); prevToken = t; continue;
    }
    if (c === ',') { r.advance(); const t = { kind: 'comma', value: ',', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }
    if (c === ';') { r.advance(); const t = { kind: 'semi',  value: ';', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }
    if (c === '.' && !isDigit(r.peek(1))) { r.advance(); const t = { kind: 'dot', value: '.', line: startLine, col: startCol, start: r.i - 1, end: r.i }; out.push(t); prevToken = t; continue; }

    // Operators (after structural punctuation so '?.', '=>' work)
    const tok = readOperator(r, startLine, startCol);
    if (tok.value === '=>') tok.kind = 'arrow';
    out.push(tok); prevToken = tok;
  }

  out.push({ kind: 'eof', line: r.line, col: r.col, start: r.i, end: r.i });
  return out;
}

// Utility: collect all identifier names that appear anywhere in a token slice,
// including those nested inside interpolated-string expression holes.
export function identsIn(tokens) {
  const names = [];
  for (const t of tokens || []) {
    if (!t) continue;
    if (t.kind === 'ident') names.push(t.value);
    if (t.kind === 'interp') {
      for (const p of t.parts || []) {
        if (p.kind === 'expr') names.push(...identsIn(p.tokens));
      }
    }
  }
  return names;
}
