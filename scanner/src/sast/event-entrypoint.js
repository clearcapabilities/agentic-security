// R6 (PRD §5) — non-HTTP entrypoint taint. Route-rooted analysis goes blind to
// message-queue consumers, scheduled tasks, and serverless handlers — exactly
// where high-severity backend bugs live. This recognizes those entrypoints,
// treats their payload parameter as an untrusted source, and flags when it
// reaches a code/command/SQL sink without sanitization.
//
// Precision-first: gated to files that register such an entrypoint; tracks the
// handler's payload parameter (+ common member accesses) into a dangerous sink.

import { blankComments } from './_comment-strip.js';

// Entrypoint registrations → the untrusted payload parameter name they bind.
const ENTRYPOINTS = [
  // JS: queue/stream consumers — .on('message', (msg)=>…) / .subscribe((msg)=>…)
  { re: /\.(?:on|subscribe|consume|process)\s*\(\s*(?:['"][^'"]*['"]\s*,\s*)?(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)/g, lang: 'js' },
  // JS serverless: exports.handler = async (event) => … / module.exports.handler = (event)
  { re: /(?:exports\.\w+|module\.exports(?:\.\w+)?)\s*=\s*(?:async\s*)?\(?\s*([A-Za-z_$][\w$]*)/g, lang: 'js' },
  // Python Celery / serverless: @app.task / @shared_task / def handler(event, context)
  { re: /@(?:app|celery|shared)\w*\.task[^\n]*\n\s*def\s+\w+\s*\(\s*([A-Za-z_]\w*)/g, lang: 'py' },
  { re: /\bdef\s+(?:handler|lambda_handler|handle|consume|on_message|process)\s*\(\s*([A-Za-z_]\w*)/g, lang: 'py' },
];

// Context markers that indicate an event/queue/serverless file.
const CONTEXT = /(kafka|rabbit|amqp|sqs|sns|pubsub|kinesis|@app\.task|shared_task|lambda_handler|exports\.handler|celery|bull|bullmq|@SqsListener|@KafkaListener|@RabbitListener|@Scheduled|consumer|EventBridge|cloudevent)/i;

const SINKS = [
  { re: /\b(?:exec|execSync|spawn|spawnSync)\s*\(/, label: 'command exec', cwe: '78', fam: 'command-injection' },
  { re: /\beval\s*\(|\bnew\s+Function\s*\(/, label: 'eval', cwe: '94', fam: 'code-injection' },
  { re: /\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen|check_output)\s*\(/, label: 'command exec', cwe: '78', fam: 'command-injection' },
  { re: /\.(?:query|execute|raw)\s*\(\s*[`'"][^`'"]*\$?\{?\s*\+?/, label: 'SQL query (concatenated)', cwe: '89', fam: 'sql-injection' },
];

const SANITIZER = /\b(sanitiz|validate|escape|allowlist|allow_list|whitelist|schema\.(?:parse|validate)|zod|joi|pydantic|is_safe|verify)/i;

const PAYLOAD_MEMBER = /\.(?:body|value|data|message|payload|Records|detail|content|text)\b/;

export function scanEventEntrypoints(fp, raw) {
  if (typeof raw !== 'string' || !raw) return [];
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i.test(fp)) return [];
  const code = blankComments(raw);
  if (!CONTEXT.test(code)) return [];
  const isPy = /\.py$/i.test(fp);
  const lines = code.split('\n');

  // Collect payload variable names from entrypoint registrations.
  const payloads = new Set();
  for (const ep of ENTRYPOINTS) {
    if (ep.lang === 'py' !== isPy) continue;
    const re = new RegExp(ep.re.source, ep.re.flags);
    let m;
    while ((m = re.exec(code))) {
      const name = m[1];
      if (name && !['async', 'function', 'context', 'self', 'cls'].includes(name)) payloads.add(name);
    }
  }
  if (!payloads.size) return [];

  const findings = [];
  const seen = new Set();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const sink of SINKS) {
      if (!sink.re.test(line)) continue;
      const arg = line.slice(line.search(sink.re));
      const hit = [...payloads].some((p) => new RegExp(`\\b${p}\\b`).test(arg));
      if (!hit) continue;
      // Sanitizer anywhere in a small window above suppresses.
      const near = lines.slice(Math.max(0, i - 6), i + 1).join('\n');
      if (SANITIZER.test(near)) continue;
      const key = `${i + 1}:${sink.fam}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push({
        id: `event-entrypoint:${fp}:${i + 1}`,
        severity: 'high',
        file: fp,
        line: i + 1,
        vuln: `Untrusted event/message payload reaches ${sink.label}`,
        cwe: `CWE-${sink.cwe}`,
        family: sink.fam,
        parser: 'EVENT-FLOW',
        description: `A non-HTTP entrypoint (queue consumer / scheduled task / serverless handler) passes its untrusted payload into ${sink.label} without validation. Message/event bodies are attacker-influenceable just like HTTP input.`,
        remediation: 'Validate/parse the event payload against a schema before use, and avoid passing it to a command/code/SQL sink (parameterize, use argv-form exec).',
      });
    }
  }
  return findings;
}

export const _internals = { PAYLOAD_MEMBER };
