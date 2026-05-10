// Model serialization & loading defenses — F1 over labelled fixtures.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

const LABELS = [
  { file: 'vuln-torch-load.py',           positive: true,  matcher: /torch\.load\(\) without weights_only/i },
  { file: 'vuln-trust-remote-code.py',    positive: true,  matcher: /trust_remote_code=True/i },
  { file: 'vuln-no-revision.py',          positive: true,  matcher: /from_pretrained without pinned revision/i },
  { file: 'vuln-pickle-load.py',          positive: true,  matcher: /pickle\.load\(\)/i },
  { file: 'vuln-yaml-load.py',            positive: true,  matcher: /yaml\.load\(\)|yaml\.unsafe_load/i },
  { file: 'vuln-joblib-load.py',          positive: true,  matcher: /joblib\.load/i },
  { file: 'vuln-numpy-allow-pickle.py',   positive: true,  matcher: /np\.load\(allow_pickle/i },
  { file: 'vuln-http-model-url.py',       positive: true,  matcher: /weights fetched from http/i },
  { file: 'safe-torch-weights-only.py',   positive: false, matcher: /^Model Load:/i },
  { file: 'safe-pinned-revision.py',      positive: false, matcher: /^Model Load:/i },
  { file: 'safe-yaml-safe-load.py',       positive: false, matcher: /^Model Load:/i },
];

test('Model load defenses — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Model-load',
    fixtureDir: 'model-load',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});
