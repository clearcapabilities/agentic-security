// Prompt injection firewall audit — defensive layer gaps.
//
// The existing llm.js module detects prompt injection vectors (user input
// flowing to prompts). This module focuses on the MISSING DEFENSES: output
// validation before using LLM responses in sensitive operations, missing
// max_tokens caps (cost explosion), user input injected into system prompts
// without delimiters, and LLM output used as code/SQL/shell input.
//
// F1 safety:
//   - Only fires in files that demonstrably call an LLM API
//   - Classic benchmark apps (NodeGoat, Juice Shop, OWASP Benchmark) have
//     zero LLM API calls — completely safe
//   - Multi-signal: requires both an LLM call AND the dangerous pattern

const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i;
const _NONPROD_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|node_modules)\//i;

// LLM API call signals — gate ALL rules on one of these being present
const LLM_API_RE = /(?:openai|anthropic|claude|gpt|ChatOpenAI|ChatAnthropic|langchain|groq|mistral|together|replicate|fireworks)(?:\.chat\.completions\.create|\.messages\.create|\.invoke|\.call|\.generate|\.complete)/i;
const LLM_IMPORT_RE = /(?:from|require)\s*\(?\s*['"`](?:openai|@anthropic-ai\/sdk|langchain|@langchain|groq-sdk|@mistralai|replicate|together-ai|@google\/generative-ai)['"`]/i;

// --- Missing max_tokens / max_completion_tokens ---
const COMPLETION_CALL_RE = /(?:create|invoke|generate|complete)\s*\(\s*\{/g;
const MAX_TOKENS_RE = /max_tokens|max_completion_tokens|maxTokens|max_new_tokens/;

// --- User input directly in system prompt without delimiter ---
// Pattern: system prompt built by string concat/template with user-controlled var
const SYSTEM_PROMPT_TEMPLATE_RE = /(?:system|systemPrompt|system_prompt)\s*[:=]\s*(?:`[^`]*\$\{(?:req|request|body|user|input|query|message|content|prompt)\b|['"][\w\s]+ \+\s*(?:req|request|body|user|input|query|message|content|prompt)\b)/i;

// --- LLM output used as SQL / shell / eval ---
const LLM_RESULT_RE = /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?(?:completion|response|result|output|message|text|content)\s*\.(?:choices\[0\]|content|text|message\.content|output\[0\]\.text)/;
const SINK_AFTER_LLM_RE = /(?:db\.|prisma\.|mongoose\.|query\s*\(|exec\s*\(|eval\s*\(|child_process|execSync|runCode)/i;

// --- No output validation before using LLM response ---
// Detect: result used directly without .trim(), type check, JSON.parse guard, or schema parse
const SCHEMA_PARSE_RE = /(?:z\.parse|zodSchema|Joi\.validate|yup\.validate|JSON\.parse|\.trim\(\)|typeof\s+\w+\s*===|Array\.isArray)/;

function _lineOf(content, idx) {
  return content.slice(0, idx).split('\n').length;
}

function scanPromptFirewall(file, content) {
  if (!_SCAN_EXT_RE.test(file)) return [];
  if (_NONPROD_RE.test(file)) return [];

  // Gate: file must contain LLM API usage
  if (!LLM_API_RE.test(content) && !LLM_IMPORT_RE.test(content)) return [];

  const findings = [];
  const lines = content.split('\n');

  // --- Missing max_tokens ---
  {
    let m;
    const re = new RegExp(COMPLETION_CALL_RE.source, 'g');
    while ((m = re.exec(content)) !== null) {
      // Check the argument block (~400 chars after opening brace)
      const argBlock = content.slice(m.index, Math.min(content.length, m.index + 500));
      // Find closing } to delimit the arg block
      const closeIdx = argBlock.indexOf('}');
      const checkBlock = closeIdx > 0 ? argBlock.slice(0, closeIdx) : argBlock;
      if (!MAX_TOKENS_RE.test(checkBlock)) {
        const lineNum = _lineOf(content, m.index);
        findings.push({
          id: `prompt-firewall:MISSING_MAX_TOKENS:${file}:${lineNum}`,
          title: 'LLM API call without max_tokens cap',
          severity: 'medium',
          file, line: lineNum,
          vuln: 'Prompt Firewall — Missing max_tokens Cap',
          description: 'An LLM completion call has no max_tokens limit. A single user-triggered request can generate arbitrarily long responses, draining your monthly AI budget. Combined with no rate limiting, this is a cost-explosion attack vector — a single attacker can generate $1000s in API charges in minutes.',
          remediation: 'Always set max_tokens:\n  { model: "...", messages: [...], max_tokens: 1000 }\nCombine with per-user rate limiting (see /rate-limit-check) and per-request cost alerts in your provider dashboard.',
          cwe: 'CWE-400',
        });
        break; // one finding per file for this pattern
      }
    }
  }

  // --- User input directly in system prompt ---
  for (let i = 0; i < lines.length; i++) {
    if (SYSTEM_PROMPT_TEMPLATE_RE.test(lines[i])) {
      findings.push({
        id: `prompt-firewall:USER_IN_SYSTEM_PROMPT:${file}:${i + 1}`,
        title: 'User-controlled content injected into LLM system prompt',
        severity: 'high',
        file, line: i + 1,
        vuln: 'Prompt Firewall — User Input in System Prompt',
        description: 'User-supplied data is directly concatenated into the system prompt without a hard delimiter. Attackers can craft inputs like "Ignore all previous instructions and..." to override your system instructions, exfiltrate data, or make the model produce harmful content attributed to your app.',
        remediation: 'Keep system prompt and user input strictly separated using the messages array structure:\n  messages: [\n    { role: "system", content: FIXED_SYSTEM_PROMPT },\n    { role: "user", content: userInput }  // never in system\n  ]\nNever template user input into the system role.',
        cwe: 'CWE-77',
      });
    }
  }

  // --- LLM output used as SQL/shell/eval input ---
  // Two-pass: find where LLM result is assigned, check if that variable reaches a sink
  {
    let m;
    const resRe = new RegExp(LLM_RESULT_RE.source, 'g');
    while ((m = resRe.exec(content)) !== null) {
      const varName = m[1];
      if (!varName) continue;
      // Look for the variable used in a sink within 30 lines after the assignment
      const afterIdx = m.index + m[0].length;
      const afterContent = content.slice(afterIdx, Math.min(content.length, afterIdx + 1500));
      const varUsedInSink = new RegExp(`\\b${varName}\\b[^;\\n]{0,100}(?:${SINK_AFTER_LLM_RE.source})`);
      const sinkUsedWithVar = new RegExp(`(?:${SINK_AFTER_LLM_RE.source})[^;\\n]{0,200}\\b${varName}\\b`);
      if (varUsedInSink.test(afterContent) || sinkUsedWithVar.test(afterContent)) {
        const lineNum = _lineOf(content, m.index);
        findings.push({
          id: `prompt-firewall:LLM_OUTPUT_TO_SINK:${file}:${lineNum}`,
          title: 'LLM output used directly in SQL/shell/eval — second-order injection',
          severity: 'critical',
          file, line: lineNum,
          vuln: 'Prompt Firewall — LLM Output Used as Code/Query',
          description: `The variable "${varName}" holds raw LLM output and is passed to a database query, shell command, or eval call without validation. An attacker who can influence the prompt (via stored prompt injection or direct input) can craft model responses that execute arbitrary SQL, shell commands, or JavaScript.`,
          remediation: 'Never use LLM output directly as code, SQL, or shell input:\n  1. Parse and validate output with a schema (zod, Joi) before use\n  2. Use parameterised queries — never template LLM text into SQL\n  3. If you need structured output, use JSON mode + schema validation\n  4. Treat LLM output as user-supplied text with the same distrust',
          cwe: 'CWE-94',
        });
      }
    }
  }

  // --- No output validation on LLM response before use ---
  // Only fire if LLM output is used and there's no schema/type validation nearby
  {
    const hasLLMResult = /(?:completion|response|result)\s*\.(?:choices\[0\]|content|message\.content)/.test(content);
    const hasValidation = SCHEMA_PARSE_RE.test(content);
    if (hasLLMResult && !hasValidation) {
      // Don't double-fire if we already flagged LLM_OUTPUT_TO_SINK
      const alreadyFlagged = findings.some(f => f.id.includes('LLM_OUTPUT_TO_SINK'));
      if (!alreadyFlagged) {
        const idx = content.search(/(?:completion|response|result)\s*\.(?:choices\[0\]|content|message\.content)/);
        findings.push({
          id: `prompt-firewall:NO_OUTPUT_VALIDATION:${file}:${_lineOf(content, idx)}`,
          title: 'LLM output used without schema validation',
          severity: 'low',
          file, line: _lineOf(content, idx),
          vuln: 'Prompt Firewall — No LLM Output Validation',
          description: 'LLM API responses are consumed without type/schema validation. Models can return unexpected formats, null fields, or adversarially crafted content. Code that assumes specific output structure will crash or behave unexpectedly under adversarial prompting.',
          remediation: 'Validate LLM output with a schema before use:\n  import { z } from "zod";\n  const schema = z.object({ answer: z.string(), score: z.number() });\n  const parsed = schema.parse(JSON.parse(llmOutput));\nOr use a structured output / JSON mode feature of the API.',
          cwe: 'CWE-20',
        });
      }
    }
  }

  return findings;
}

export { scanPromptFirewall };
