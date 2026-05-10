// Model serialization & loading defenses.
//
// OWASP LLMSecOps explicitly names "Model Serialization Defenses" and
// "Digital Model/Dataset Verification" — these are the canonical RCE
// vectors when loading ML models. PyTorch's default torch.load() was
// vulnerable until 2.6 made weights_only=True the default; trust_remote_code
// in transformers still defaults to False but is widely toggled to True.
//
// This module fires only on highly concrete patterns to keep the F1 ceiling
// at 1.00 against the labelled fixture set:
//
//   1. torch.load(...) without weights_only=True   (CWE-502, RCE)
//   2. transformers.from_pretrained(..., trust_remote_code=True)  (CWE-94, RCE)
//   3. from_pretrained without revision=<sha>      (CWE-1357, supply chain)
//   4. pickle.load / pickle.loads on model paths   (CWE-502, RCE)
//   5. yaml.load(stream) without SafeLoader        (CWE-502, RCE)
//   6. joblib.load(...)                            (CWE-502, RCE — pickle-backed)
//   7. np.load(..., allow_pickle=True)             (CWE-502, RCE)
//   8. tf.keras.models.load_model from http:// URL (CWE-494, supply chain)
//   9. Loading model weights from http:// URL      (CWE-494, supply chain)
//
// Suppressions:
//   - tests/, examples/, fixtures/, codefixes/, docs/  (paths)
//   - if weights_only=True is present                  (negation context)
//   - if Loader=SafeLoader / yaml.safe_load             (negation context)

const _SCAN_EXT_RE = /\.(?:py|ipynb)$/i;
const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;

// Pattern table. Each entry has:
//   re:        the trigger regex (run on raw source)
//   contextRe: optional regex over a window around the match to confirm or suppress
//   contextNeg: when set, the contextRe must NOT match for the finding to fire
//   vuln, severity, cwe, fix
const PATTERNS = [
  {
    name: 'torch-load-unsafe',
    re: /\btorch\.load\s*\(/g,
    // Suppress if weights_only=True is in the same call's argument list (next 200 chars)
    contextRe: /weights_only\s*=\s*True/,
    contextNeg: true,
    vuln: 'Model Load: torch.load() without weights_only=True (RCE via pickle)',
    severity: 'critical',
    cwe: 'CWE-502',
    fix: 'Pass weights_only=True to torch.load(): `torch.load(path, weights_only=True)`. The default was unsafe in PyTorch < 2.6 — the loader can execute arbitrary Python during deserialization. Prefer the safetensors format (`.safetensors`) for new models — it cannot execute code.',
  },
  {
    name: 'transformers-trust-remote-code',
    re: /\.from_pretrained\s*\([^)]{0,400}?trust_remote_code\s*=\s*True/g,
    vuln: 'Model Load: from_pretrained(trust_remote_code=True) executes arbitrary code from the model repo',
    severity: 'critical',
    cwe: 'CWE-94',
    fix: 'Set trust_remote_code=False (the default) or omit it. With trust_remote_code=True, the transformers library executes arbitrary Python code published in the model repository at load time. If you need a specific custom model, audit its code first and pin to a verified revision.',
  },
  {
    name: 'from-pretrained-no-revision',
    re: /\b(?:Auto(?:Model|Tokenizer|Config|Processor|FeatureExtractor)|[A-Z][A-Za-z]*Model|[A-Z][A-Za-z]*Tokenizer)\.from_pretrained\s*\(\s*['"][\w./-]+['"][^)]*\)/g,
    // Fire only when revision= is NOT in the call's arguments
    contextRe: /revision\s*=/,
    contextNeg: true,
    vuln: 'Model Load: from_pretrained without pinned revision (mutable, supply-chain risk)',
    severity: 'high',
    cwe: 'CWE-1357',
    fix: 'Pin to a specific commit SHA: `AutoModel.from_pretrained("org/model", revision="abc123def456...")`. Without a pinned revision the model publisher (or anyone who compromises them) can ship new weights into your inference path silently. Get the SHA from the Hugging Face Hub commit history.',
  },
  {
    name: 'pickle-load',
    re: /\bpickle\.(?:load|loads)\s*\(/g,
    vuln: 'Model Load: pickle.load() — RCE on untrusted input',
    severity: 'critical',
    cwe: 'CWE-502',
    fix: 'pickle.load() executes arbitrary code during deserialization. Use safetensors (`.safetensors`), JSON, or MessagePack for serialization. If you must use pickle, only on paths you wrote yourself in the same process and verify a hash before loading.',
  },
  {
    name: 'yaml-unsafe-load',
    re: /\byaml\.(?:load|unsafe_load)\s*\(/g,
    contextRe: /yaml\.safe_load|Loader\s*=\s*(?:yaml\.)?SafeLoader/,
    contextNeg: true,
    vuln: 'Model Load: yaml.load() / yaml.unsafe_load() — RCE on untrusted YAML',
    severity: 'critical',
    cwe: 'CWE-502',
    fix: 'Use yaml.safe_load() for any YAML you did not author. yaml.load() with the default loader instantiates arbitrary Python objects, including os.system shells. yaml.unsafe_load() is even worse.',
  },
  {
    name: 'joblib-load',
    re: /\bjoblib\.load\s*\(/g,
    vuln: 'Model Load: joblib.load() is pickle-backed — RCE on untrusted input',
    severity: 'high',
    cwe: 'CWE-502',
    fix: 'joblib.load() uses pickle under the hood and has the same RCE risk. Use it only on files you control and verify a hash before loading. For sklearn models, prefer ONNX export or skops/skopt safe-serialization.',
  },
  {
    name: 'numpy-allow-pickle',
    re: /\bnp\.load\s*\([^)]*?allow_pickle\s*=\s*True/g,
    vuln: 'Model Load: np.load(allow_pickle=True) — RCE via pickle in .npy files',
    severity: 'high',
    cwe: 'CWE-502',
    fix: 'Set allow_pickle=False (default since NumPy 1.16.3) and use a structured format (.npz with explicit arrays). If you must keep allow_pickle=True, only on .npy files you produced yourself in the same trust boundary.',
  },
  {
    name: 'http-model-url',
    re: /(?:torch\.hub\.load_state_dict_from_url|hf_hub_download|tf\.keras\.models\.load_model|load_state_dict)\s*\(\s*['"]http:\/\//g,
    vuln: 'Model Load: model weights fetched from http:// (no integrity, MITM)',
    severity: 'high',
    cwe: 'CWE-494',
    fix: 'Use https://. Better: pin to a specific revision/SHA and verify a checksum after download. Plain http allows a network attacker to substitute the weights with a backdoored version.',
  },
];

function _emit(fp, line, p, snippet) {
  return {
    id: `model-load:${fp}:${line}:${p.name}`,
    kind: 'sast',
    severity: p.severity,
    vuln: p.vuln,
    cwe: p.cwe,
    stride: 'Tampering',
    file: fp,
    line,
    snippet: (snippet || '').trim().slice(0, 200),
    fix: p.fix,
  };
}

export function scanModelLoad(fp, raw) {
  if (!_SCAN_EXT_RE.test(fp)) return [];
  const fpNorm = fp.replace(/\\/g, '/');
  if (_NONPROD_PATH_RE.test(fpNorm)) return [];
  if (!raw || raw.length > 500_000) return [];

  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();

  for (const p of PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g');
    let m;
    while ((m = re.exec(raw))) {
      const matchedText = m[0];
      // Build a window: from match-100 to match-end+400, to catch nearby kwargs / Loader= clauses
      const windowStart = Math.max(0, m.index - 100);
      const windowEnd = Math.min(raw.length, m.index + matchedText.length + 400);
      const window = raw.substring(windowStart, windowEnd);

      if (p.contextRe) {
        const present = p.contextRe.test(window);
        if (p.contextNeg && present) continue; // suppress: safe context found
        if (!p.contextNeg && !present) continue;
      }

      const line = raw.substring(0, m.index).split('\n').length;
      const finding = _emit(fp, line, p, lines[line - 1] || matchedText);
      if (!seen.has(finding.id)) {
        seen.add(finding.id);
        findings.push(finding);
      }
    }
  }

  return findings;
}

// Public for tests
export const _internal = { PATTERNS };
