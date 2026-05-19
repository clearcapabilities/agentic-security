---
description: Install pre-commit and pre-push git hooks that run scoped scans on every commit and full diff scans before push. Blocks on new critical findings by default.
argument-hint: "[--threshold critical|high|medium] [--uninstall]"
---

Install client-side git hooks that gate commits and pushes on security findings. The hooks are written to `.git/hooks/pre-commit` and `.git/hooks/pre-push` and are project-local (not shared via `git config core.hooksPath`).

- **pre-commit**: scoped scan of staged files only — fast (<2s typical), runs on every `git commit`. Blocks if any new critical finding is introduced.
- **pre-push**: full diff scan against `@{upstream}` (or `main` if no upstream). Slower but blocks the broader set before code leaves the machine.

Pass `--uninstall` to remove the hooks. Pass `--threshold` to change the blocking severity (default: `critical`).

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\\x1b[\${c}m\${s}\\x1b[0m\` : s;

const args = process.argv.slice(1);
const uninstall = args.includes('--uninstall');
const ti = args.indexOf('--threshold');
const threshold = ti >= 0 ? args[ti+1] : (args.find(a => /^--threshold=/.test(a))||'').split('=')[1] || 'critical';

if (!fs.existsSync('.git')) {
  console.error('Not a git repo (no .git directory found).');
  process.exit(1);
}
const HOOK_DIR = '.git/hooks';
fs.mkdirSync(HOOK_DIR, { recursive: true });

const MARKER = '# agentic-security:managed';

if (uninstall) {
  for (const name of ['pre-commit', 'pre-push']) {
    const p = path.join(HOOK_DIR, name);
    if (!fs.existsSync(p)) continue;
    const c = fs.readFileSync(p, 'utf8');
    if (!c.includes(MARKER)) {
      console.log(W('  ⚠  ' + name + ' was not installed by us — skipping.', '33'));
      continue;
    }
    fs.unlinkSync(p);
    console.log(W('  ✓  Removed ' + p, '32'));
  }
  process.exit(0);
}

const preCommit = \`#!/usr/bin/env bash
\${MARKER}
# Scoped scan of staged files. Blocks on new \${threshold}+ findings.
set -e
STAGED=\\$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\\\.(js|jsx|ts|tsx|mjs|cjs|py|rb|php|java|kt|go|cs|sol|tf|yaml|yml|json)\\$' || true)
if [ -z \\"\\$STAGED\\" ]; then exit 0; fi
echo \\"agentic-security: scanning \\$(echo \\\\\\"\\$STAGED\\\\\\" | wc -l) staged files...\\"
TMP=\\$(mktemp -d)
trap 'rm -rf \\\\\\"\\$TMP\\\\\\"' EXIT
for f in \\$STAGED; do
  mkdir -p \\"\\$TMP/\\$(dirname \\\\\\"\\$f\\\\\\")\\"
  git show :\\\\\\"\\$f\\\\\\" > \\"\\$TMP/\\$f\\" 2>/dev/null || true
done
npx --yes agentic-security scan \\"\\$TMP\\" --threshold \${threshold} --json > /tmp/agentic-security-precommit.json 2>/dev/null || true
node -e \\"
  const f=require('fs'); let r;
  try{r=JSON.parse(f.readFileSync('/tmp/agentic-security-precommit.json','utf8'));}catch{process.exit(0);}
  const SEV={critical:0,high:1,medium:2,low:3};
  const th=SEV['\${threshold}']??0;
  const bad=(r.findings||[]).filter(x=>(SEV[x.severity]??9)<=th);
  if(bad.length){
    console.error('agentic-security pre-commit BLOCKED — '+bad.length+' \${threshold}+ finding(s):');
    bad.slice(0,5).forEach(x=>console.error('  ['+x.severity+'] '+x.vuln+' — '+x.file+':'+x.line));
    console.error('Bypass: git commit --no-verify (use sparingly)');
    process.exit(1);
  }
\\"
\`;

const prePush = \`#!/usr/bin/env bash
\${MARKER}
# Diff scan against upstream. Blocks on new \${threshold}+ findings.
set -e
UPSTREAM=\\$(git rev-parse --abbrev-ref @{u} 2>/dev/null || echo main)
echo \\"agentic-security: diff scan against \\$UPSTREAM ...\\"
npx --yes agentic-security scan . --changed-since \\\\\\"\\$UPSTREAM\\\\\\" --threshold \${threshold} --json > /tmp/agentic-security-prepush.json 2>/dev/null || true
node -e \\"
  const f=require('fs'); let r;
  try{r=JSON.parse(f.readFileSync('/tmp/agentic-security-prepush.json','utf8'));}catch{process.exit(0);}
  const SEV={critical:0,high:1,medium:2,low:3};
  const th=SEV['\${threshold}']??0;
  const bad=(r.findings||[]).filter(x=>(SEV[x.severity]??9)<=th);
  if(bad.length){
    console.error('agentic-security pre-push BLOCKED — '+bad.length+' \${threshold}+ finding(s).');
    bad.slice(0,10).forEach(x=>console.error('  ['+x.severity+'] '+x.vuln+' — '+x.file+':'+x.line));
    console.error('Bypass: git push --no-verify (use sparingly)');
    process.exit(1);
  }
\\"
\`;

for (const [name, body] of [['pre-commit', preCommit], ['pre-push', prePush]]) {
  const p = path.join(HOOK_DIR, name);
  if (fs.existsSync(p) && !fs.readFileSync(p, 'utf8').includes(MARKER)) {
    console.log(W('  ⚠  ' + p + ' already exists and is not managed by us — skipping.', '33'));
    console.log('     To replace, remove it manually first.');
    continue;
  }
  fs.writeFileSync(p, body);
  fs.chmodSync(p, 0o755);
  console.log(W('  ✓  Installed ' + p, '32'));
}
console.log('');
console.log(W('  Threshold: \${threshold} (pass --threshold high to relax).', '2'));
console.log(W('  Uninstall: /install-hooks --uninstall', '2'));
" -- "$@"
```

Tell the user the hooks are now in place and that `--no-verify` bypasses them if they genuinely need to commit through a known finding.
