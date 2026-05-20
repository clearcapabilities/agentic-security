// Agent Tool-Chain Privilege Escalation (OWASP LLM06 — Sensitive
// Information Disclosure × LLM07 — Insecure Plugin Design, applied to
// agent tool composition).
//
// Pattern: An agent has two tools — a low-privilege READ tool (`list_files`,
// `fetch_url`, `query_db_readonly`) and a high-privilege ACT tool (`exec`,
// `write_file`, `send_email`, `db_admin_query`). The agent's harness lets
// the LLM call them in sequence: the LLM reads the output of the READ tool
// (which can be attacker-controlled — files in a tenant's bucket, content
// from a scraped URL, a row in a DB the attacker can update) and uses
// that output as input to the ACT tool. The READ tool's output is now an
// authority-promoting channel.
//
// We catch the AT-RISK PATTERN at code-shape time:
//   - Two tools registered in the same agent harness
//   - One is READ-class (callee name matches: read, list, get, fetch,
//     search, query, find, scrape, retrieve)
//   - The other is ACT-class (write, exec, run, send, post, delete,
//     create, update, drop, kill)
//   - No explicit `confirm` / `human_approval` / `policy_check` between
//     them (search for these inside the tool's handler body)
//
// Frameworks we recognize:
//   - LangChain Python:  Tool(name="…", func=…) / @tool decorator
//   - LangChain JS:      new Tool({ name, func })
//   - LangGraph:         tools=[…]
//   - OpenAI Assistants: tools=[{ type:"function", function:{ name, …}}]
//   - Anthropic Claude SDK: tools=[{ name, description, input_schema }]
//   - MCP servers: tools.register or capabilities.tools

import { blankComments } from './_comment-strip.js';

const READ_VERBS = ['read', 'list', 'get', 'fetch', 'search', 'query', 'find', 'scrape', 'retrieve', 'lookup', 'show', 'select'];
const ACT_VERBS  = ['write', 'exec', 'run', 'send', 'post', 'delete', 'create', 'update', 'drop', 'kill', 'execute', 'invoke', 'modify', 'patch', 'mutate', 'add_user', 'remove_user'];

// Patterns capturing a tool NAME from a registration line, language-tagged.
const TOOL_NAME_PATTERNS = [
  // LangChain Python: Tool(name="…", …)  or  @tool def name(args):
  ['py', /\bTool\s*\(\s*name\s*=\s*['"]([a-zA-Z_][\w]*)['"]/g],
  ['py', /^\s*@tool\s*[\r\n]+\s*def\s+([a-zA-Z_][\w]*)\s*\(/gm],
  // LangChain JS / LangGraph:  new Tool({ name: "…" })  or  tool({ name })
  ['js', /\bnew\s+Tool\s*\(\s*\{\s*name\s*:\s*['"]([a-zA-Z_][\w]*)['"]/g],
  ['js', /\btool\s*\(\s*\{\s*name\s*:\s*['"]([a-zA-Z_][\w]*)['"]/g],
  // OpenAI Assistants:  { type: "function", function: { name: "…" } }
  ['js', /\btype\s*:\s*['"]function['"]\s*,\s*function\s*:\s*\{\s*name\s*:\s*['"]([a-zA-Z_][\w]*)['"]/g],
  ['py', /['"]type['"]\s*:\s*['"]function['"]\s*,\s*['"]function['"]\s*:\s*\{\s*['"]name['"]\s*:\s*['"]([a-zA-Z_][\w]*)['"]/g],
  // Anthropic tools list: { name: "…", description, input_schema }
  ['js', /\{\s*name\s*:\s*['"]([a-zA-Z_][\w]*)['"]\s*,\s*description/g],
  ['py', /\{\s*['"]name['"]\s*:\s*['"]([a-zA-Z_][\w]*)['"]\s*,\s*['"]description['"]/g],
  // MCP server registerTool / setRequestHandler('tools/call', …)
  ['js', /\bregisterTool\s*\(\s*['"]([a-zA-Z_][\w]*)['"]/g],
  ['py', /\b@server\s*\.\s*tool\s*\(\s*['"]([a-zA-Z_][\w]*)['"]/g],
];

const APPROVAL_HINT_RE =
  /\b(?:requireConfirmation|require_confirmation|human_approval|policy_check|approveAction|approve_action|guardCheck|enforce_policy|capability_check)\b/;

function _classify(name) {
  const low = name.toLowerCase();
  for (const v of ACT_VERBS) {
    if (low.includes(v)) return 'act';
  }
  for (const v of READ_VERBS) {
    if (low.includes(v)) return 'read';
  }
  return null;
}

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  return null;
}

export function scanAgentToolEscalation(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  if (!/\b(?:Tool|tool|tools|registerTool|@tool|@server\.tool|input_schema|function_call|tool_use)\b/.test(code)) return [];
  // Collect all tool names declared in this file with their classification.
  const tools = []; // { name, kind: 'act'|'read', line }
  for (const [plang, pat] of TOOL_NAME_PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      const name = m[1];
      const kind = _classify(name);
      if (!kind) continue;
      tools.push({ name, kind, line: _lineOf(raw, m.index) });
    }
  }
  if (tools.length < 2) return [];
  const hasRead = tools.some(t => t.kind === 'read');
  const hasAct  = tools.some(t => t.kind === 'act');
  if (!hasRead || !hasAct) return [];
  // Approval-mechanism gate — if the file references a known confirm/policy
  // helper, we assume the harness mediates the escalation and suppress.
  if (APPROVAL_HINT_RE.test(code)) return [];
  // Fire one finding per ACT tool, naming the READ counterpart in the trace.
  const findings = [];
  const seen = new Set();
  const readNames = tools.filter(t => t.kind === 'read').map(t => t.name);
  for (const actTool of tools.filter(t => t.kind === 'act')) {
    const id = `agent-tool-escalation:${fp}:${actTool.line}:${actTool.name}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      file: fp, line: actTool.line,
      vuln: `Agent Tool Privilege Escalation (act-tool "${actTool.name}" exposed alongside read-tools)`,
      severity: 'high',
      cwe: 'CWE-269',     // Improper Privilege Management
      family: 'agent-tool-escalation',
      stride: 'Elevation of Privilege',
      snippet: (raw.split('\n')[actTool.line - 1] || '').trim().slice(0, 200),
      remediation:
        `Tool "${actTool.name}" performs an action (write/exec/send/delete). It's registered alongside read tools (${readNames.slice(0, 4).join(', ')}) in the same agent surface — the LLM can pipe the read tool's output (which is attacker-influenceable: scraped pages, DB rows tenants can edit, file contents in shared buckets) directly into the act tool's input. ` +
        'Mitigations: ' +
        '(1) require an explicit confirmation / human approval step for any act tool whose inputs are derived from a read tool\'s output; ' +
        '(2) isolate act tools to a separate agent surface with a stricter system prompt; ' +
        '(3) attach a policy_check / capability_check helper to the act tool that verifies the input was not solely derived from low-trust read sources; ' +
        '(4) tag read-tool outputs with provenance metadata so the act tool can refuse low-trust input.',
      parser: 'AGENT-TOOL-ESCALATION',
      confidence: 0.7,
    });
  }
  return findings;
}
