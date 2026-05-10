// Prompt template security audit — F1 over labelled fixtures.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

const LABELS = [
  { file: 'vuln-fstring-prompt.py',     positive: true,  matcher: /Prompt Template:.*interpolated/i },
  { file: 'vuln-template-literal.js',   positive: true,  matcher: /Prompt Template:.*interpolated/i },
  { file: 'prompts/vuln-prompt.j2',     positive: true,  matcher: /Prompt Template:.*isolation markers/i },
  { file: 'safe-messages-array.py',     positive: false, matcher: /^Prompt Template:/i },
  { file: 'safe-messages-array.js',     positive: false, matcher: /^Prompt Template:/i },
  { file: 'prompts/safe-isolated.j2',   positive: false, matcher: /^Prompt Template:/i },
];

test('Prompt template — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Prompt-template',
    fixtureDir: 'prompt-template',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});
