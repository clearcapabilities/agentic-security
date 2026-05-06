#!/usr/bin/env node
// SessionStart hook: print a one-line tip if no baseline exists yet.
import * as fs from 'node:fs';
import * as path from 'node:path';

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const blPath = path.join(cwd, '.agentic-security', 'baseline.json');
if (!fs.existsSync(blPath)) {
  console.log('agentic-security: no baseline. Run /security-scan then /security-baseline save to enable commit gating.');
}
process.exit(0);
