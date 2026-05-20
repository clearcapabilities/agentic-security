// LLM Stored-Prompt Injection (CWE-1336 / OWASP LLM01 — LLM Top 10).
//
// Pattern: a system/instruction prompt is loaded from a writable location
// (database row, config file in a writable mount, vector-store seed file,
// settings panel) and concatenated into an LLM call. The prompt itself
// becomes the injection vector — much harder to defend than direct user
// input because operators see a "configured prompt" and don't realize
// it's adversary-reachable.
//
// We catch the AT-RISK shape, not the breach itself:
//   - System prompt content read from a non-source location AND used as
//     the system message in an LLM call WITHOUT delimiters / role frames
//     / explicit instruction-priority scaffolding.
//
// Specifically we flag:
//   1. `system_prompt = db.query(...).first().content` or similar
//      read-then-use-as-system-prompt patterns
//   2. `messages: [{ role: 'system', content: <variable> }]` where the
//      variable is sourced from `readFile(<config or DB>)`
//   3. settings.yaml / prompts/*.md loaded at runtime AND piped to
//      LLM call without a known hardening helper

import { blankComments } from './_comment-strip.js';

const WRITABLE_SOURCE_RE =
  /\b(?:db\.|database\.|conn\.|cursor\.|prisma\.|drizzle\.|knex|pg\.query|mysql\.query|mongo|redis|getSetting|loadSetting|adminConfig|tenantSetting|fetchPrompt|getStoredPrompt|loadPromptFromDB)\b/;

const READS_FROM_USER_WRITABLE_FILE_RE =
  /\b(?:fs\.readFile|readFile|fs\.readFileSync|open\s*\(['"]\.?\/?(?:prompts|configs|tenants|admin|settings)\/|configparser|yaml\.safe_load|toml\.load)\b/;

// LLM-call shapes that consume a system prompt variable.
const LLM_CALL_PATTERNS = [
  ['js', /\bmessages\s*:\s*\[\s*\{\s*role\s*:\s*['"]system['"]\s*,\s*content\s*:\s*([a-z_][\w]*|[a-z_][\w]*\.[\w.]+)/gi, 'OpenAI messages[]'],
  ['js', /\bsystem\s*:\s*([a-z_][\w]*|[a-z_][\w]*\.[\w.]+)\s*[,}]/gi, 'Anthropic system='],
  ['py', /\bmessages\s*=\s*\[\s*\{\s*['"]role['"]\s*:\s*['"]system['"]\s*,\s*['"]content['"]\s*:\s*([a-z_][\w]*|[a-z_][\w]*\.[\w.]+)/gi, 'OpenAI messages[]'],
  ['py', /\bsystem\s*=\s*([a-z_][\w]*|[a-z_][\w]*\.[\w.]+)/gi, 'Anthropic system='],
];

// Known hardening helpers — when these wrap the prompt-variable, suppress.
const HARDENING_HINT_RE =
  /\b(?:wrapWithDelimiters|hardenPrompt|sanitizePrompt|deny_instruction_override|with_role_isolation|escapeUntrustedSection)\b/;

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  return null;
}

export function scanStoredPromptInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  // Cheap pre-filter — no LLM call in this file, skip.
  if (!/\b(?:openai|anthropic|messages\s*[:=]\s*\[|system\s*[:=]\s*['"`]|ChatCompletion|chat\.completions|claude|llm\.|LLM)\b/i.test(code)) return [];
  // Pre-filter — no writable-source read, skip.
  const hasWritable = WRITABLE_SOURCE_RE.test(code) || READS_FROM_USER_WRITABLE_FILE_RE.test(code);
  if (!hasWritable) return [];
  if (HARDENING_HINT_RE.test(code)) return [];
  const findings = [];
  const seen = new Set();
  const rawLines = raw.split('\n');
  for (const [plang, pat, label] of LLM_CALL_PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      const varName = (m[1] || '').split('.')[0];
      if (!varName || !/^[a-z_][\w]*$/i.test(varName)) continue;
      const callLine = _lineOf(raw, m.index);
      // Look back ≤30 lines for an assignment to `varName` that pulls
      // from a writable source. If found, fire.
      const lo = Math.max(0, callLine - 31);
      const before = rawLines.slice(lo, callLine - 1).join('\n');
      const assignRe = new RegExp(`\\b${varName}\\s*=\\s*[^;\\n]*?(?:${WRITABLE_SOURCE_RE.source}|${READS_FROM_USER_WRITABLE_FILE_RE.source})`);
      if (!assignRe.test(before)) continue;
      const id = `llm-stored-prompt:${fp}:${callLine}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp, line: callLine,
        vuln: `LLM Stored-Prompt Injection (${label})`,
        severity: 'high',
        cwe: 'CWE-1336',
        family: 'llm-prompt-injection',
        stride: 'Tampering',
        snippet: (rawLines[callLine - 1] || '').trim().slice(0, 200),
        remediation:
          'A system/instruction prompt sourced from a writable location (DB row, config file, admin panel) is the same attack surface as direct user input — operators who can edit that storage can override your model. ' +
          'Mitigations: ' +
          '(1) wrap the loaded text in rare-token delimiters and explicitly tell the model the wrapped content is data, not instructions; ' +
          '(2) require a separate immutable instruction prefix (e.g. compile-time-constant) that asserts model role + refuses to override; ' +
          '(3) enforce a server-side allow-list of approved prompt templates rather than free-form storage; ' +
          '(4) keep the writable surface behind a signing key so unsigned prompts are refused.',
        parser: 'LLM-STORED-PROMPT',
        confidence: 0.8,
      });
    }
  }
  return findings;
}
