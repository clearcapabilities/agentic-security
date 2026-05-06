// Filesystem driver: reads a directory, builds the fileContents/depFileContents
// maps the engine expects, and invokes runFullScan.
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import fg from 'fast-glob';
import { runFullScan, shouldScan } from './engine.js';

const DEP_FILE_NAMES = new Set([
  'package.json','package-lock.json','yarn.lock','pnpm-lock.yaml',
  'requirements.txt','pyproject.toml','poetry.lock','Pipfile.lock',
  'composer.json','composer.lock','Gemfile','Gemfile.lock',
  'go.mod','Cargo.toml','Cargo.lock',
  'pom.xml','build.gradle','build.gradle.kts',
  'pubspec.yaml','pubspec.lock',
]);

const DEFAULT_IGNORE = [
  '**/node_modules/**','**/.git/**','**/__pycache__/**','**/vendor/**',
  '**/dist/**','**/build/**','**/.next/**','**/venv/**','**/env/**','**/.venv/**',
  '**/target/**','**/bin/**','**/obj/**','**/.cache/**','**/coverage/**',
  '**/bower_components/**','**/tests/**','**/test/**','**/__tests__/**','**/spec/**','**/mocks/**',
];

export async function readTree(root, { ignore = [] } = {}) {
  const entries = await fg('**/*', {
    cwd: root, dot: false, onlyFiles: true,
    ignore: [...DEFAULT_IGNORE, ...ignore], followSymbolicLinks: false,
    suppressErrors: true,
  });
  const fileContents = {};
  const depFileContents = {};
  for (const rel of entries) {
    const abs = path.join(root, rel);
    let stat;
    try { stat = await fs.stat(abs); } catch { continue; }
    if (stat.size > 500_000) continue;
    let content;
    try { content = await fs.readFile(abs, 'utf8'); } catch { continue; }
    const base = path.basename(rel);
    if (DEP_FILE_NAMES.has(base)) depFileContents[rel] = content;
    if (shouldScan(rel)) fileContents[rel] = content;
  }
  return { fileContents, depFileContents };
}

export async function runScan(rootDir, opts = {}) {
  const root = path.resolve(rootDir);
  const startedAt = new Date().toISOString();
  const t0 = Date.now();
  const { fileContents, depFileContents } = await readTree(root, opts);
  const scan = await runFullScan({ fileContents, depFileContents }, opts.onProgress || (()=>{}));
  return {
    scan,
    meta: { scanId: cryptoUUID(), startedAt, durationMs: Date.now() - t0, root },
  };
}

export const scanPath = runScan;

function cryptoUUID(){
  // Node 20+ has globalThis.crypto.randomUUID
  return globalThis.crypto?.randomUUID?.() || `scan-${Date.now().toString(36)}`;
}
