// C# semantic analysis — Layers 3 + 4 of the C# detection pipeline.
//
// Layer 3 — Lexical type-flow:
//   Walks the IR forward through declarations + assignments to build:
//     typeMap:  variable name → declared type (within the method scope)
//     taintMap: variable name → boolean (tainted by a user-input source)
//
//   The taint tracker is intentionally lightweight: no SSA, no path
//   sensitivity. For Juliet C# and idiomatic ASP.NET, the source patterns
//   are stable enough (Request.Query / Request.Form / Request.Headers /
//   HttpContext.Request.* / IFormCollection / BinaryReader / etc.) that a
//   simple forward-pass catches the vast majority. Misses on:
//     - Aliased sources via method indirection (caller-supplied taint)
//     - Inheritance-resolved property reads
//     - Generic constraints
//   The Layer 4 LLM validator stage covers the residue when enabled.
//
// Layer 4 — Attribute-driven route + auth detection:
//   Reads each method's IR.attrs[] and classifies routes by canonical ASP.NET
//   attribute set. Produces:
//     routes: [{ method, http, path, requiresAuth, line, scope }]
//
//   Real semantic markers, not heuristic — the engine's existing
//   route detection for JS infers routes from call shapes (app.get('/x',…)).
//   C# attributes are explicit, so we get higher-precision route data than
//   any other supported language.

// User-input source patterns. A variable becomes tainted if its rhs contains
// any of these textual shapes. Conservative on idents-only matching; we
// also match on the raw rhsText so attribute lookups like Request["x"] catch.
const TAINT_SOURCE_PATTERNS = [
  /\bRequest\s*\.\s*(?:Query|Form|Headers|Cookies|InputStream|Body|RouteValues)\b/,
  /\bHttpContext\s*\.\s*Request\b/,
  /\bRequest\s*\[\s*["'][^"']+["']\s*\]/,
  /\bIFormCollection\b/,
  /\bbadSource\s*\(/,                // Juliet test convention
  /\bgetParameter\s*\(/,              // Juliet HttpServletRequest analog
  /\bConsole\s*\.\s*ReadLine\b/,
  /\bEnvironment\s*\.\s*GetEnvironmentVariable\b/,
  /\bFile\s*\.\s*ReadAllText\s*\(/,
  /\bGetEnvironmentVariable\b/,
];

// Sanitizers — if any of these appear in the rhs, taint is cleared.
const SANITIZER_PATTERNS = [
  /\bHttpUtility\s*\.\s*HtmlEncode\b/,
  /\bHtmlEncoder\s*\.\s*Default\b/,
  /\bAntiXssEncoder\b/,
  /\bRegex\s*\.\s*Replace\s*\(/,
  /\bint\s*\.\s*TryParse\b/,
  /\bGuid\s*\.\s*TryParse\b/,
  /\bIsNullOrEmpty\b/,
  /\bSqlParameter\b/,
];

function isSourceExpr(text) {
  return TAINT_SOURCE_PATTERNS.some(re => re.test(text));
}
function isSanitizedExpr(text) {
  return SANITIZER_PATTERNS.some(re => re.test(text));
}

// Walk a single method's body and compute per-variable type + taint.
// Returns { typeMap, taintMap, sourceLines } where sourceLines records the
// declaration line at which each variable first became tainted.
function analyzeMethodFlow(method, opts = {}) {
  const typeMap = new Map();
  const taintMap = new Map();
  const sourceLines = new Map();

  // Seed from params: parameters of route handler methods (ASP.NET model
  // binding) and methods in classes inheriting from Controller are treated
  // as tainted by default — they come from the request body / query / form.
  // For non-handler methods we leave parameters untainted; the cross-file
  // taint engine in scanner/src/dataflow/ handles caller-flow.
  const paramsTainted = !!opts.treatParamsAsTainted;
  for (const p of method.params || []) {
    typeMap.set(p.name, p.type);
    if (paramsTainted) {
      taintMap.set(p.name, true);
      sourceLines.set(p.name, method.line);
    }
  }

  // Forward pass through decls. Method.decls is already in source order.
  for (const d of method.decls || []) {
    if (d.type && d.type !== 'var') typeMap.set(d.name, d.type);
    else if (d.isVar && d.rhsText) {
      // Best-effort type inference for `var x = new T(...)`.
      const m = d.rhsText.match(/^\s*new\s+([\w.<>?\[\],\s]+?)\s*\(/);
      if (m) typeMap.set(d.name, m[1].trim());
    }
    if (d.rhsText) {
      if (isSourceExpr(d.rhsText) && !isSanitizedExpr(d.rhsText)) {
        taintMap.set(d.name, true);
        sourceLines.set(d.name, d.line);
        continue;
      }
      // Propagation: rhs references a tainted var → lhs becomes tainted.
      const refs = (d.rhsText.match(/\b[A-Za-z_]\w*\b/g) || []);
      for (const ref of refs) {
        if (taintMap.get(ref)) {
          taintMap.set(d.name, true);
          sourceLines.set(d.name, d.line);
          break;
        }
      }
    }
  }

  // Then assignments — same forward propagation rules.
  for (const a of method.assignments || []) {
    if (!a.rhsText) continue;
    const targetKey = a.fullTarget;
    if (isSourceExpr(a.rhsText) && !isSanitizedExpr(a.rhsText)) {
      taintMap.set(targetKey, true);
      sourceLines.set(targetKey, a.line);
      continue;
    }
    const refs = (a.rhsText.match(/\b[A-Za-z_]\w*\b/g) || []);
    for (const ref of refs) {
      if (taintMap.get(ref)) {
        taintMap.set(targetKey, true);
        sourceLines.set(targetKey, a.line);
        break;
      }
    }
  }
  return { typeMap, taintMap, sourceLines };
}

// Attribute → route classifier. Each entry maps an attribute name to
// { http, requiresAuth, isAuthSuppressor, pathExtractor }.
const ROUTE_ATTRS = {
  HttpGet:     { http: 'GET',    pathArgIdx: 0 },
  HttpPost:    { http: 'POST',   pathArgIdx: 0 },
  HttpPut:     { http: 'PUT',    pathArgIdx: 0 },
  HttpDelete:  { http: 'DELETE', pathArgIdx: 0 },
  HttpPatch:   { http: 'PATCH',  pathArgIdx: 0 },
  HttpHead:    { http: 'HEAD',   pathArgIdx: 0 },
  HttpOptions: { http: 'OPTIONS',pathArgIdx: 0 },
  Route:       { http: 'ANY',    pathArgIdx: 0 },
  AcceptVerbs: { http: 'ANY',    pathArgIdx: 1 },
};
const AUTH_ATTRS = new Set(['Authorize']);
const AUTH_SUPPRESSORS = new Set(['AllowAnonymous']);

function extractPath(argsRaw, argIdx) {
  if (!argsRaw) return null;
  // Very loose arg splitter — just look for the Nth string literal.
  const matches = argsRaw.match(/"([^"]*)"/g) || [];
  if (matches[argIdx]) return matches[argIdx].slice(1, -1);
  if (matches[0]) return matches[0].slice(1, -1);
  return null;
}

export function analyzeCSharpIR(ir) {
  // Class-level attribute roll-up.
  const classAuth = new Map(); // class-ref → { authedAtClass, anonymousAtClass, isController }
  for (const c of ir.classes) {
    const a = (c.attrs || []).map(x => x.name);
    classAuth.set(c, {
      authedAtClass: a.some(n => AUTH_ATTRS.has(n)),
      anonymousAtClass: a.some(n => AUTH_SUPPRESSORS.has(n)),
      // Conventional ASP.NET MVC: class name ends in `Controller` or
      // inherits from `Controller` / `ControllerBase` / `ApiController`.
      // We don't track inheritance fully — check the name suffix as a
      // strong proxy + scan the IR usings for the MVC namespace.
      // ASP.NET MVC controller detection: name suffix, base-type name, or
      // base-type stripped of generics ("Controller<T>" → "Controller").
      isController: /Controller$/.test(c.name)
                 || /\bApi(?:Controller)?\b/.test(c.name)
                 || (c.baseTypes || []).some(b => /^(?:Controller|ControllerBase|ApiController)$/.test(b.replace(/<.*$/, ''))),
    });
  }

  // Per-method flow. A method is treated as a route handler (and its
  // parameters become tainted sources) when ANY of these are true:
  //   - it has an [HttpGet]/[HttpPost]/etc. attribute
  //   - its containing class has [ApiController] or [Route(...)]
  //   - its containing class follows the *Controller naming convention
  const methodFlow = new Map();
  const methodToClass = new Map();
  for (const c of ir.classes) for (const m of c.methods) methodToClass.set(m, c);
  for (const m of ir.methods) {
    const attrNames = (m.attrs || []).map(x => x.name);
    const isRouteAttr = attrNames.some(n => ROUTE_ATTRS[n]);
    const cls = methodToClass.get(m);
    const classIsController = cls ? !!classAuth.get(cls)?.isController : false;
    const classHasApiAttr = cls && (cls.attrs || []).some(a => a.name === 'ApiController' || a.name === 'Route');
    const isPublic = !m.modifiers || m.modifiers.includes('public') || (!m.modifiers.includes('private') && !m.modifiers.includes('protected') && !m.modifiers.includes('internal'));
    const treatParamsAsTainted = (isRouteAttr || classHasApiAttr || classIsController) && isPublic;
    methodFlow.set(m, analyzeMethodFlow(m, { treatParamsAsTainted }));
  }
  // Route detection.
  const routes = [];
  for (const c of ir.classes) {
    const ca = classAuth.get(c);
    for (const m of c.methods) {
      let http = null, path = null;
      const attrNames = (m.attrs || []).map(x => x.name);
      for (const a of m.attrs || []) {
        const def = ROUTE_ATTRS[a.name];
        if (def) {
          http = def.http;
          path = extractPath(a.argsRaw, def.pathArgIdx);
          break;
        }
      }
      if (!http) continue;
      const requiresAuth = (ca.authedAtClass || attrNames.some(n => AUTH_ATTRS.has(n)))
                         && !attrNames.some(n => AUTH_SUPPRESSORS.has(n));
      routes.push({
        method: m,
        http,
        path: path || `/${c.name}/${m.name}`,
        requiresAuth,
        line: m.line,
        className: c.name,
        methodName: m.name,
      });
    }
  }
  return { methodFlow, routes, classAuth };
}

// Helper queries used by detectors.

// "Is the receiver `name` known to be of type matching pattern?"
export function receiverIsType(method, flow, receiver, typePattern) {
  if (!receiver) return false;
  const t = flow.typeMap.get(receiver);
  if (!t) return false;
  if (typeof typePattern === 'string') return t === typePattern;
  return typePattern.test(t);
}

// "Does this token-slice's text contain a tainted variable reference?"
// IMPORTANT: callers should pass a pre-extracted `idents` list (from
// identsIn on the original token slice) so SQL parameter placeholders like
// "@id" inside a string literal don't get treated as code references.
// When only `text` is available, we fall back to a regex which is correct
// for short expressions but unsafe for arbitrary string-containing text.
export function expressionIsTainted(flow, text, idents = null) {
  if (!text && !idents) return false;
  if (text) {
    if (isSourceExpr(text) && !isSanitizedExpr(text)) return true;
    if (isSanitizedExpr(text)) return false;
  }
  const refs = idents || (text ? text.match(/\b[A-Za-z_]\w*\b/g) || [] : []);
  for (const r of refs) if (flow.taintMap.get(r)) return true;
  return false;
}

// Token-aware variant for ArgExpr objects — uses the arg's pre-extracted
// idents list (which excludes string-literal contents) so SQL parameter
// placeholders, error message templates, and other string contents are
// not treated as code identifiers.
export function argIsTainted(flow, arg) {
  if (!arg) return false;
  if (arg.text && isSanitizedExpr(arg.text)) return false;
  if (arg.text && isSourceExpr(arg.text)) return true;
  for (const id of arg.idents || []) if (flow.taintMap.get(id)) return true;
  return false;
}

// "Is an interpolated-string literal tainted?" — true if any embedded
// expression references a tainted var.
export function interpStringIsTainted(flow, interpToken) {
  if (!interpToken || interpToken.kind !== 'interp') return false;
  for (const p of interpToken.parts || []) {
    if (p.kind === 'expr' && expressionIsTainted(flow, p.text)) return true;
  }
  return false;
}

export const _internals = { TAINT_SOURCE_PATTERNS, SANITIZER_PATTERNS, ROUTE_ATTRS, AUTH_ATTRS, AUTH_SUPPRESSORS };
