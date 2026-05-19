---
description: Generate a CI security gate for any of the supported providers (GitHub Actions, GitLab CI, CircleCI, Buildkite, Jenkins). Auto-detects the provider from the repo; pass --provider <name> to override.
argument-hint: "[--provider gitlab|circleci|buildkite|jenkins|github] [--apply]"
---

Multi-provider CI gate generator. The original `/ci-gate` emits GitHub Actions only; this command supports GitLab CI, CircleCI, Buildkite, and Jenkins as well.

Detection rules:
- `.gitlab-ci.yml` → GitLab CI
- `.circleci/config.yml` → CircleCI
- `.buildkite/pipeline.yml` or `BUILDKITE_*` env vars → Buildkite
- `Jenkinsfile` → Jenkins
- `.github/` → GitHub Actions
- pass `--provider` to force a specific output

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');
const W = (s, c) => process.stdout.isTTY ? \`\\x1b[\${c}m\${s}\\x1b[0m\` : s;

const args = process.argv.slice(1);
const apply = args.includes('--apply');
const explicit = (args.find(a => a.startsWith('--provider=')) || '').split('=')[1]
              || (args.indexOf('--provider') >= 0 ? args[args.indexOf('--provider') + 1] : null);

const detected = explicit
  || (fs.existsSync('.gitlab-ci.yml') ? 'gitlab' : null)
  || (fs.existsSync('.circleci/config.yml') ? 'circleci' : null)
  || (fs.existsSync('.buildkite/pipeline.yml') ? 'buildkite' : null)
  || (fs.existsSync('Jenkinsfile') ? 'jenkins' : null)
  || (fs.existsSync('.github') ? 'github' : null);

if (!detected) {
  console.error('Could not detect CI provider. Pass --provider gitlab|circleci|buildkite|jenkins|github');
  process.exit(1);
}

const ROOT = process.env.CLAUDE_PLUGIN_ROOT || path.dirname(path.dirname(__filename));

const TEMPLATES = {
  gitlab:   { src: path.join(ROOT, 'scripts/ci-templates/.gitlab-ci.yml'),
              dest: '.gitlab-ci.yml',
              merge: 'extend existing or include via local:' },
  circleci: { src: path.join(ROOT, 'scripts/ci-templates/.circleci-config.yml'),
              dest: '.circleci/config.yml',
              merge: 'merge into existing workflows section' },
  buildkite:{ src: path.join(ROOT, 'scripts/ci-templates/buildkite.yml'),
              dest: '.buildkite/pipeline.yml',
              merge: 'append to steps:' },
  jenkins:  { src: path.join(ROOT, 'scripts/ci-templates/Jenkinsfile'),
              dest: 'Jenkinsfile',
              merge: 'merge stages: into existing pipeline' },
  github:   { src: null, dest: null,
              merge: 'use /ci-gate (the dedicated GitHub Actions generator)' },
};

const t = TEMPLATES[detected];
if (detected === 'github') {
  console.log(W('Detected provider: GitHub Actions', '1'));
  console.log('For GitHub Actions, use the dedicated command: ' + W('/ci-gate', '36'));
  process.exit(0);
}

const content = fs.readFileSync(t.src, 'utf8');

console.log('');
console.log(W('Detected provider: ' + detected, '1'));
console.log('Target file:  ' + t.dest);
console.log('');

if (apply) {
  if (fs.existsSync(t.dest)) {
    console.log(W('  ⚠  ' + t.dest + ' already exists.', '33'));
    console.log('  ' + t.merge);
    console.log('');
    console.log('  Template content (copy the relevant block):');
  } else {
    fs.mkdirSync(path.dirname(t.dest), { recursive: true });
    fs.writeFileSync(t.dest, content);
    console.log(W('  ✓  Wrote ' + t.dest, '32'));
    process.exit(0);
  }
}

console.log(content.split('\\n').map(l => '  ' + l).join('\\n'));
console.log('');
console.log(W('  Pass --apply to write the file (or its template, when one already exists).', '33'));
" -- "$@"
```

Pass `--apply` to write the template into the right path. If the target file already exists, the template is printed verbatim so you can merge the security stage into your existing pipeline.
