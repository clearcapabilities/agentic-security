---
description: SentQL prompt — write a custom security check in natural language; the assistant translates it to the project's YAML rule DSL and previews before saving to .agentic-security/rules/.
argument-hint: "<natural-language description, OR raw YAML>"
---

The user describes a custom check in natural language. You translate it into the project's existing YAML rule DSL (the one already consumed by `scanner/src/posture/custom-rules.js`) and write it to `.agentic-security/rules/<slug>.yml` after the user confirms.

The DSL shape:

```yaml
id: <stable-id>
name: <human title>
severity: critical | high | medium | low | info
cwe: CWE-NNN
description: <one paragraph>
remediation: <one paragraph>

# Pattern matchers — at least one of these is required.
match:
  files: ["**/*.js", "**/*.ts"]      # glob; required
  regex: '<javascript-regex>'         # required (matches the line)
  not_in_window: '<regex>'            # optional negative-lookaround over ±5 lines

# Optional: LLM validation hook. The engine emits the candidate finding with
# llm_only:true if the LLM cannot validate; otherwise the LLM confidence
# replaces the rule's static confidence.
llm_validate:
  prompt: 'Is this exploitable as described? Reply with one of: yes | no | maybe.'
  min_confidence: 0.7

# Optional: path constraints (Layer-2 wire-up).
path:
  must_traverse: ['<predicate>']      # e.g. 'is_http_route'
  must_not_traverse: ['<predicate>']  # e.g. 'is_sanitized'

shadow: false                          # if true, emits to shadow-findings only
```

When the user invokes `/query <input>`:

1. If `<input>` already looks like YAML (starts with `id:` or `---`), validate and save directly.
2. Otherwise: read the natural-language description, draft the YAML, show it to the user, and ask "save?". On yes, write to `.agentic-security/rules/<slug>.yml` and run `/scan --quick` so they see whether it fires.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');

const input = (process.argv.slice(1).join(' ') || '').trim();
if (!input) {
  console.error('Usage: /query <natural-language description>');
  console.error('  Example: /query flag any place we log req.body.password');
  process.exit(1);
}

console.log('');
console.log('━━━ SentQL ━━━');
console.log('Input:    ' + input);
console.log('');

// If input already looks like YAML, write straight through.
if (/^(?:---|\\s*id:)/m.test(input)) {
  const slugMatch = input.match(/\\bid:\\s*([a-z0-9_-]+)/i);
  const slug = (slugMatch && slugMatch[1]) || ('rule-' + Date.now().toString(36));
  const target = path.join('.agentic-security', 'rules', slug + '.yml');
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, input.endsWith('\\n') ? input : input + '\\n');
  console.log('Saved:    ' + target);
  console.log('Run:      /scan --quick   (to verify the rule fires)');
  process.exit(0);
}

console.log('Natural-language input received. Draft the YAML, show it,');
console.log('and on user confirmation write to .agentic-security/rules/<slug>.yml.');
console.log('');
console.log('(The drafting step is performed by the assistant, not by this script.)');
" -- "$@"
```

Then *you* (the assistant) draft the YAML based on the user's natural-language input, show it to them, and on confirmation write it to `.agentic-security/rules/<slug>.yml` using the Write tool. The next `/scan` will load it via the existing `custom-rules.js` loader.
