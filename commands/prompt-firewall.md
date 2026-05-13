---
description: Audit LLM/AI app security — user input in system prompts, missing max_tokens, LLM output used as SQL/code, and missing output validation.
---

Deep audit of AI feature security. Covers the four most dangerous gaps in LLM-powered apps: prompt injection via system prompt contamination, cost explosion from missing token caps, second-order injection when model output feeds into SQL/shell, and missing output schema validation.

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first, then /prompt-firewall.');
  process.exit(0);
}

const pfFindings = (scan.findings || []).filter(f =>
  (f.id || '').startsWith('prompt-firewall:') ||
  /prompt.*inject|system.*prompt.*user|max.token|llm.*output.*sql|llm.*output.*exec|output.*validat/i.test(f.title || f.vuln || '')
);

// Also surface any llm.js findings (existing module)
const llmFindings = (scan.findings || []).filter(f =>
  !f.id?.startsWith('prompt-firewall:') &&
  /prompt.injection|LLM.*inject|user.*input.*prompt/i.test(f.vuln || f.title || '')
);

console.log('');
console.log(W('Prompt Injection Firewall Audit', '1'));
console.log('');

if (pfFindings.length === 0 && llmFindings.length === 0) {
  console.log(W('  ✓  No prompt injection or LLM security issues detected.', '32'));
  console.log('');
  console.log('  Checked:');
  console.log('  • User input injected into system prompts');
  console.log('  • Missing max_tokens cap (cost explosion risk)');
  console.log('  • LLM output used as SQL/shell/eval input (second-order injection)');
  console.log('  • Missing output schema validation');
  console.log('  • Prompt injection vectors (existing llm.js rules)');
  console.log('');
  process.exit(0);
}

const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36', info: '2' };
const all = [...pfFindings, ...llmFindings].sort((a,b) => (sevOrder[a.severity]??4)-(sevOrder[b.severity]??4));

for (const f of all) {
  const c = sevColor[f.severity] || '0';
  console.log(W('[' + (f.severity||'?').toUpperCase() + ']', c) + '  ' + (f.title || f.vuln));
  console.log('  ' + f.file + (f.line ? ':' + f.line : ''));
  if (f.description) console.log('  ' + W(f.description.slice(0, 200), '2'));
  console.log('');
  if (f.remediation) f.remediation.split('\n').slice(0, 5).forEach(l => console.log('  ' + l));
  console.log('');
}

const crit = all.filter(f=>f.severity==='critical').length;
const high = all.filter(f=>f.severity==='high').length;
console.log(W('Summary', '1'));
console.log('  ' + all.length + ' AI security finding(s) — ' + crit + ' critical, ' + high + ' high');
console.log('');
console.log(W('The most dangerous pattern:', '1'));
console.log('  LLM output → SQL/exec (critical): an attacker controls the prompt,');
console.log('  controls the model output, which then runs as a database query.');
console.log('  This is an indirect SQL injection that bypasses all input sanitization.');
console.log('');
console.log('  Fix all: /fix --all --high');
console.log('');
"
```

LLM security is different from traditional security — the attack surface is the model's output, not just the user's input. Even with input sanitization, if you trust the model's response to drive SQL queries or shell commands, an attacker who can influence the prompt chain (stored prompt injection, indirect injection via RAG retrieval, or direct input) controls your database.
