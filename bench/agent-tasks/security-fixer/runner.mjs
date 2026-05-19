#!/usr/bin/env node
// Agent-task runner: security-fixer.
//
// For each task, exercises the deterministic security-fixer toolchain end-to-end
// against a clean copy of the fixture:
//
//   1. Copy the fixture's pre/ tree to a fresh temp directory (clean-slate
//      isolation, per Anthropic eval guidance).
//   2. Write a staged `last-scan.json` carrying ONE finding with a known-good
//      `fix.replacement`. (The scanner doesn't synthesize replacements today;
//      pre-staging lets us test the apply-fix toolchain that the agent would
//      consume once detectors emit replacements.)
//   3. Sign the last-scan.json with the per-install HMAC key (premortem #1).
//   4. Run the MCP tools in order: synthesize_fix → verify_fix → apply_fix.
//   5. Re-scan the patched fixture and check the original stableId is gone.
//   6. Score each grader and emit pass/fail per task.
//
// Aggregate report: pass@1 per task, per-grader breakdown, total runtime.
//
// Usage:
//   node bench/agent-tasks/security-fixer/runner.mjs
//   node bench/agent-tasks/security-fixer/runner.mjs --json
//   node bench/agent-tasks/security-fixer/runner.mjs --task sqli-replace

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import { signLastScan } from '../../../scanner/src/posture/integrity.js';
import { runScan } from '../../../scanner/src/runScan.js';
import * as tools from '../../../scanner/src/mcp/tools.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..', '..');
const TASKS_DIR = path.join(HERE, 'tasks');

function args() {
  const a = process.argv.slice(2);
  const out = { json: false, task: null };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--json') out.json = true;
    else if (a[i] === '--task') out.task = a[++i];
  }
  return out;
}

async function _copyDir(src, dst) {
  await fsp.mkdir(dst, { recursive: true });
  for (const ent of await fsp.readdir(src, { withFileTypes: true })) {
    const s = path.join(src, ent.name);
    const d = path.join(dst, ent.name);
    if (ent.isDirectory()) await _copyDir(s, d);
    else if (ent.isFile()) await fsp.copyFile(s, d);
  }
}

async function _writeStagedScan(workDir, stagedFinding) {
  const stateDir = path.join(workDir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  const scan = {
    findings: [stagedFinding],
    routes: [], components: [], secrets: [], supplyChain: [], logicVulns: [],
    fc: {},
    annotatorErrors: [],
  };
  const body = JSON.stringify(scan, null, 2);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), body);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
}

async function _runTask(task) {
  const workDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agent-task-'));
  const result = {
    id: task.id, description: task.description,
    graders: {}, attempts: 0, durationMs: 0,
  };
  const t0 = Date.now();
  try {
    // Step 1: copy fixture.
    const fixtureAbs = path.resolve(REPO_ROOT, task.fixture_path);
    if (!fs.existsSync(fixtureAbs)) {
      result.error = `fixture not found: ${task.fixture_path}`;
      return result;
    }
    await _copyDir(fixtureAbs, workDir);
    // Step 2: stage the finding. Path is relative to workDir.
    const finding = JSON.parse(JSON.stringify(task.staged_finding));
    // Read the actual file content into the staged finding's snippet line so
    // verify_fix's re-scan and re-checks have a real target.
    const targetAbs = path.join(workDir, finding.file);
    if (!fs.existsSync(targetAbs)) {
      result.error = `staged file missing: ${finding.file}`;
      return result;
    }
    const targetBefore = await fsp.readFile(targetAbs, 'utf8');
    await _writeStagedScan(workDir, finding);

    const ctx = { sessionRoot: workDir };

    // Step 3: synthesize_fix.
    const synth = await tools.synthesize_fix.handler({ finding_id: finding.id }, ctx);
    result.graders.synthesize_returned_replacement = synth.hasReplacement === true;

    // Step 4: verify_fix in-memory.
    const proposed = { [finding.file]: finding.fix.replacement };
    const verify = await tools.verify_fix.handler({ stable_id: finding.stableId, files: proposed }, ctx);
    result.graders.verify_passed = verify.ok === true;

    // Step 5: apply_fix (real disk write).
    const apply = await tools.apply_fix.handler({ finding_id: finding.id, confirm: true }, ctx);
    result.graders.fix_applied = apply.applied === true;
    result.attempts = apply.attemptOrdinal || 1;
    result.graders.single_attempt = result.attempts === 1;
    result.graders.no_budget_exceeded = !apply.budgetExceeded;

    // Step 6: re-scan and check the finding is gone (by stableId) AND no new
    // ≥high finding appeared.
    if (apply.applied) {
      const { scan } = await runScan(workDir, { network: false });
      const findings = scan.findings || [];
      const stillThere = findings.some(f => f.stableId === finding.stableId);
      result.graders.stableId_closed = !stillThere;
      // Count new ≥high (high or critical) findings, excluding ones that
      // already existed in `targetBefore`. We approximate "new" as findings
      // whose stableId differs from the staged finding's; since the staged
      // scan only had ONE finding, anything ≥high in the post-scan that
      // isn't our target is a new regression.
      const newHigh = findings.filter(f =>
        f.stableId !== finding.stableId &&
        (f.severity === 'high' || f.severity === 'critical'));
      result.graders.no_new_high = newHigh.length === 0;
      result.newHighCount = newHigh.length;
    } else {
      result.graders.stableId_closed = false;
      result.graders.no_new_high = false;
    }
    // Final diff sanity (used for human review only, not graded).
    const targetAfter = await fsp.readFile(targetAbs, 'utf8');
    result.diffApplied = targetAfter !== targetBefore;
  } catch (e) {
    result.error = String((e && e.message) || e).slice(0, 400);
  } finally {
    result.durationMs = Date.now() - t0;
    // Clean up temp dir.
    try { await fsp.rm(workDir, { recursive: true, force: true }); } catch {}
  }
  return result;
}

function _summary(results) {
  const total = results.length;
  const graderNames = ['synthesize_returned_replacement', 'verify_passed', 'fix_applied', 'single_attempt', 'no_budget_exceeded', 'stableId_closed', 'no_new_high'];
  const perGrader = {};
  for (const g of graderNames) perGrader[g] = { pass: 0, fail: 0, na: 0 };
  let allGradersPassed = 0;
  for (const r of results) {
    let allPass = true;
    for (const g of graderNames) {
      if (!(g in r.graders)) { perGrader[g].na++; allPass = false; continue; }
      if (r.graders[g]) perGrader[g].pass++;
      else { perGrader[g].fail++; allPass = false; }
    }
    if (allPass) allGradersPassed++;
  }
  return {
    total,
    pass1: total > 0 ? allGradersPassed / total : 0,
    perGrader,
  };
}

async function main() {
  const opts = args();
  if (!fs.existsSync(TASKS_DIR)) {
    console.error(`no tasks directory at ${TASKS_DIR}`);
    process.exit(2);
  }
  const taskFiles = fs.readdirSync(TASKS_DIR).filter(f => f.endsWith('.json'));
  const results = [];
  for (const tf of taskFiles) {
    const task = JSON.parse(fs.readFileSync(path.join(TASKS_DIR, tf), 'utf8'));
    if (opts.task && opts.task !== task.id) continue;
    results.push(await _runTask(task));
  }
  const summary = _summary(results);
  if (opts.json) {
    console.log(JSON.stringify({ when: new Date().toISOString(), summary, results }, null, 2));
    return;
  }
  console.log('');
  console.log(`security-fixer agent-task corpus — ${results.length} task(s)`);
  console.log(`  pass@1 (all graders pass): ${(summary.pass1 * 100).toFixed(1)}%`);
  console.log('');
  for (const g of Object.keys(summary.perGrader)) {
    const v = summary.perGrader[g];
    console.log(`  ${g.padEnd(35)} pass=${v.pass}  fail=${v.fail}  n/a=${v.na}`);
  }
  console.log('');
  for (const r of results) {
    const verdict = r.error ? `ERR (${r.error})` :
                    Object.values(r.graders).every(Boolean) ? 'PASS' : 'FAIL';
    console.log(`  · ${r.id.padEnd(30)} ${verdict.padEnd(8)} attempts=${r.attempts} ${r.durationMs}ms`);
    if (r.error) continue;
    for (const [g, v] of Object.entries(r.graders)) {
      if (!v) console.log(`      ✗ ${g}`);
    }
  }
}

main().catch(e => { console.error(e); process.exit(1); });
