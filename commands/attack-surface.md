---
description: Generate a plain-English narrative of your app's top attack scenarios — written for builders, not security engineers. No CVE IDs, just stories.
---

Synthesise the scan findings into a plain-English threat narrative. Instead of a list of finding IDs, you get 3–5 realistic attack stories: what an attacker does, in what order, and what they walk away with.

```bash
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) {
  console.log(W('No scan found.', '33') + ' Run /scan --all first.');
  process.exit(0);
}

const findings = scan.findings || [];
const routes = scan.routes || [];
const components = scan.components || [];

// Summarise for Claude to build the narrative
const critAndHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 20);
const secretFindings = findings.filter(f => /CWE-798|hardcoded|secret|credential/i.test(f.cwe || f.vuln || ''));
const authFindings = findings.filter(f => /auth|IDOR|session|JWT|csrf|CWE-284|CWE-287|CWE-352/i.test(f.cwe || f.vuln || ''));
const injectionFindings = findings.filter(f => /SQL|injection|XSS|command|SSRF/i.test(f.vuln || ''));
const kevFindings = findings.filter(f => f.kev);
const chains = findings.filter(f => f.vuln && f.vuln.includes('→'));
const unauthRoutes = routes.filter(r => !r.hasAuth && r.method !== 'GET').length;

console.log('');
console.log(W('Attack Surface — Threat Narrative', '1'));
console.log('');
console.log(W('Stats for Claude to synthesise:', '2'));
console.log(JSON.stringify({
  total_findings: findings.length,
  critical: findings.filter(f => f.severity === 'critical').length,
  high: findings.filter(f => f.severity === 'high').length,
  secrets_leaked: secretFindings.length,
  auth_issues: authFindings.length,
  injection_issues: injectionFindings.length,
  kev_deps: kevFindings.length,
  attack_chains: chains.length,
  unauth_state_routes: unauthRoutes,
  top_findings: critAndHigh.slice(0, 10).map(f => ({ vuln: f.vuln, file: f.file, line: f.line, severity: f.severity, cwe: f.cwe })),
  chains: chains.slice(0, 5).map(f => f.vuln),
}, null, 2));
console.log('');
"
```

Using the JSON stats above, write a threat narrative in plain English for a non-security-engineer builder. Format it as:

## Your App's Attack Surface

**Grade: [A/B/C/D/F]** — one sentence verdict.

Then 3–5 attack scenarios, each as:

### Scenario N: [Catchy name]
**What the attacker does:** 2–3 sentences describing the sequence of steps, starting from "An attacker who visits your site..."
**What they get:** one sentence — data exfiltration, account takeover, financial impact, etc.
**Likelihood:** Low / Medium / High (based on how exploitable the finding is)
**The fix in one line:** the single most impactful remediation step.

End with: **Biggest single thing to fix first:** [one action].

Write for someone who codes but doesn't know security. Use real impact language ("they can read every user's messages", "they can charge any card", "they can delete your database"). Skip jargon. No CVE numbers.
