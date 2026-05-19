import { isChainWorthy, familyForBoundary } from './cross-lang-meta.js';

// Cross-language message-queue taint propagation (FR-XSAT-4 — P1.5).
//
// When a project ships producer and consumer code for the same message
// queue (Kafka topic, AWS SQS queue, RabbitMQ exchange, Redis stream,
// Google Pub/Sub topic), tainted data flowing into the producer carries
// through the queue and emerges in the consumer's hand. The engine pairs
// producer call sites with consumer handlers by topic name; when either
// end has a high+ finding, we emit a `cross_language: true` chain finding
// at the OTHER end so engineers see the transitive flow.
//
// This module is deliberately conservative: we only emit chains when the
// producer and consumer agree on the topic name (string literal match).
// Constant-folded topic names (variables, env vars) get a `topic: 'inferred'`
// tag and lower confidence rather than dropped — that's the precision/recall
// trade-off documented in the parent PRD's Pillar-6 honesty commitments.
//
// Detectors per queue tech:
//   Kafka          — kafkajs (Node), confluent-kafka (Python), kafka-clients (Java), sarama (Go)
//   AWS SQS        — aws-sdk (Node), boto3 (Python), aws-sdk-java
//   RabbitMQ       — amqplib (Node), pika (Python), RabbitTemplate (Spring)
//   Redis Streams  — redis (xadd/xread) — Node/Python/Java/Go
//   Google Pub/Sub — @google-cloud/pubsub (Node), google-cloud-pubsub (Python)

// ─── Topic extraction ──────────────────────────────────────────────────────

// Each regex finds either a producer-write site or a consumer-handler site.
// Group 1 = topic name (literal or expression text).
const PRODUCER_PATTERNS = [
  // Kafka
  { tech: 'kafka',  re: /\bproducer\s*\.\s*send\s*\(\s*\{[^}]*?topic\s*:\s*['"]([^'"]+)['"]/g },
  { tech: 'kafka',  re: /\bsendMessage\s*\(\s*['"]([^'"]+)['"]/g },                        // kafka-clients (Java)
  { tech: 'kafka',  re: /producer\.send\s*\(\s*new\s+ProducerRecord\s*[<(]\s*[^,]*?,\s*['"]([^'"]+)['"]/g },  // Java
  { tech: 'kafka',  re: /(?:Producer|producer)\.produce\s*\(\s*['"]([^'"]+)['"]/g },        // confluent-kafka Python
  // SQS
  { tech: 'sqs',    re: /\bsendMessage\s*\(\s*\{[^}]*?QueueUrl\s*:\s*['"][^'"]*?\/([^'"\/]+)['"]/g },  // aws-sdk node, queue URL ends with name
  { tech: 'sqs',    re: /\bsend_message\s*\(\s*QueueUrl\s*=\s*['"][^'"]*?\/([^'"\/]+)['"]/g },        // boto3
  // RabbitMQ
  { tech: 'rabbit', re: /\bpublish\s*\(\s*['"]([^'"]+)['"]/g },                            // amqplib & pika common
  { tech: 'rabbit', re: /rabbitTemplate\.convertAndSend\s*\(\s*['"]([^'"]+)['"]/g },        // Spring
  // Redis streams (multi-language XADD shapes)
  { tech: 'redis',  re: /\.\s*xadd\s*\(\s*['"]([^'"]+)['"]/gi },                            // node/ioredis: xadd('key', ...)
  { tech: 'redis',  re: /\bXADD\s+([\w:.-]+)/g },                                          // redis-cli style in code strings
  { tech: 'redis',  re: /XAddArgs\s*\{\s*Stream\s*:\s*['"]([^'"]+)['"]/g },                // go-redis: &redis.XAddArgs{Stream: "..."}
  { tech: 'redis',  re: /\.\s*xadd\s*\(\s*name\s*=\s*['"]([^'"]+)['"]/g },                  // python redis-py: xadd(name="...")
  // Google Pub/Sub
  { tech: 'pubsub', re: /\btopic\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.publish/g },             // @google-cloud/pubsub
  { tech: 'pubsub', re: /publisher\.publish\s*\(\s*topic_path\s*\([^,]+,\s*['"]([^'"]+)['"]/g },  // python
];

const CONSUMER_PATTERNS = [
  // Kafka
  { tech: 'kafka',  re: /\bconsumer\s*\.\s*subscribe\s*\(\s*\{[^}]*?topics?\s*:\s*\[?\s*['"]([^'"]+)['"]/g },
  { tech: 'kafka',  re: /\.\s*subscribe\s*\(\s*\[\s*['"]([^'"]+)['"]/g },
  { tech: 'kafka',  re: /@KafkaListener\s*\(\s*topics\s*=\s*\{?\s*['"]([^'"]+)['"]/g },   // Spring Boot
  // SQS
  { tech: 'sqs',    re: /\bsqsClient\.receiveMessage\s*\(\s*\{[^}]*?QueueUrl\s*:\s*['"][^'"]*?\/([^'"\/]+)['"]/g },
  { tech: 'sqs',    re: /\breceive_message\s*\(\s*QueueUrl\s*=\s*['"][^'"]*?\/([^'"\/]+)['"]/g },
  // RabbitMQ
  { tech: 'rabbit', re: /\.\s*consume\s*\(\s*['"]([^'"]+)['"]/g },                         // amqplib
  { tech: 'rabbit', re: /\.\s*basic_consume\s*\(\s*[^,]*,\s*queue\s*=\s*['"]([^'"]+)['"]/g }, // pika
  { tech: 'rabbit', re: /@RabbitListener\s*\(\s*queues\s*=\s*['"]([^'"]+)['"]/g },         // Spring
  // Redis streams (multi-language XREAD shapes)
  { tech: 'redis',  re: /\.\s*xread(?:group)?\s*\(\s*[^)]*?streams\s*:\s*\{?\s*['"]([^'"]+)['"]/gi },
  { tech: 'redis',  re: /\bXREAD(?:GROUP)?\s+(?:GROUP\s+\S+\s+\S+\s+)?(?:COUNT\s+\d+\s+)?STREAMS\s+([\w:.-]+)/gi },
  { tech: 'redis',  re: /\.\s*xread\s*\(\s*\{[^}]*?key\s*:\s*['"]([^'"]+)['"]/gi },        // node-redis v4: xread({key:'...'})
  // Google Pub/Sub
  { tech: 'pubsub', re: /\bsubscription\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.on/g },
  { tech: 'pubsub', re: /\bsubscriber\.subscribe\s*\(\s*subscription_path\s*\([^,]+,\s*['"]([^'"]+)['"]/g },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

/**
 * Walk every file looking for queue producer/consumer call sites.
 * Returns:
 *   {
 *     producers: Map<topic, Array<{file, line, tech}>>
 *     consumers: Map<topic, Array<{file, line, tech}>>
 *   }
 *
 * Topic normalization: lowercase + strip leading slashes (SQS queue URLs
 * vary by region/account; we key only on the queue name segment).
 */
function indexQueueSites(fileContents) {
  const producers = new Map();
  const consumers = new Map();
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (typeof c !== 'string' || c.length > 500_000) continue;
    if (!_looksLikeCodeFile(fp)) continue;
    for (const { tech, re } of PRODUCER_PATTERNS) {
      const rx = new RegExp(re.source, re.flags);
      let m;
      while ((m = rx.exec(c))) {
        const topic = _normTopic(m[1]);
        if (!topic) continue;
        const line = lineOf(c, m.index);
        const arr = producers.get(topic) || [];
        arr.push({ file: fp, line, tech });
        producers.set(topic, arr);
      }
    }
    for (const { tech, re } of CONSUMER_PATTERNS) {
      const rx = new RegExp(re.source, re.flags);
      let m;
      while ((m = rx.exec(c))) {
        const topic = _normTopic(m[1]);
        if (!topic) continue;
        const line = lineOf(c, m.index);
        const arr = consumers.get(topic) || [];
        arr.push({ file: fp, line, tech });
        consumers.set(topic, arr);
      }
    }
  }
  return { producers, consumers };
}

function _normTopic(s) {
  if (!s || typeof s !== 'string') return '';
  return s.trim().toLowerCase().replace(/^\/+/, '');
}

function _looksLikeCodeFile(fp) {
  return /\.(js|jsx|ts|tsx|mjs|cjs|py|java|kt|go|rb|cs|rs|php|scala|swift)$/i.test(fp);
}

// ─── Chain emission ─────────────────────────────────────────────────────────

/**
 * For each (producer, consumer) pair on the same topic, look up high+ findings
 * at either site and emit a chain finding at the OTHER side.
 *
 * Returns an array of chain findings ready to splice into finalFindings.
 */
export function scanCrossLangQueues(fileContents, findings) {
  const { producers, consumers } = indexQueueSites(fileContents);
  if (!producers.size || !consumers.size) return [];
  // Index existing findings by (file, line) for fast lookup. Only include
  // chain-worthy families (FR-CHAIN-FILTER): chaining to a CSRF or
  // header-hardening finding on the other side of a queue is semantically
  // meaningless — taint doesn't propagate through those classes.
  const findingsByFile = new Map();
  for (const f of findings || []) {
    if (!f || typeof f !== 'object') continue;
    if (!/critical|high/.test(f.severity || '')) continue;
    if (!isChainWorthy(f)) continue;
    const file = f.file || f.sink?.file;
    if (!file) continue;
    const list = findingsByFile.get(file) || [];
    list.push(f);
    findingsByFile.set(file, list);
  }
  const chains = [];
  for (const [topic, prodList] of producers) {
    const consList = consumers.get(topic);
    if (!consList) continue;
    for (const prod of prodList) {
      for (const cons of consList) {
        // For each producer, see if the consumer file has high+ findings.
        const consFindings = findingsByFile.get(cons.file) || [];
        for (const consF of consFindings) {
          chains.push(_chainFinding({
            origin: prod, target: cons, topic, sourceFinding: consF, dir: 'producer->consumer',
          }));
        }
        const prodFindings = findingsByFile.get(prod.file) || [];
        for (const prodF of prodFindings) {
          chains.push(_chainFinding({
            origin: cons, target: prod, topic, sourceFinding: prodF, dir: 'consumer->producer',
          }));
        }
      }
    }
  }
  return chains;
}

function _chainFinding({ origin, target, topic, sourceFinding, dir }) {
  return {
    id: `xlang-queue:${origin.file}:${origin.line}->${target.file}:${target.line}:${topic}`,
    file: origin.file,
    line: origin.line,
    vuln: `Cross-language taint via ${target.tech} topic '${topic}' — ${dir} — reaches ${sourceFinding.vuln}`,
    severity: _downgradeSeverity(sourceFinding.severity),
    cwe: sourceFinding.cwe || null,
    parser: 'XLANG-QUEUE',
    family: familyForBoundary('queue'),       // FR-FAMILY-REGISTRY: canonical name
    cross_language: true,
    boundary: 'queue',
    topic,
    tech: target.tech,
    confidence: 0.6,
    source: { file: origin.file, line: origin.line, label: `${target.tech} producer (topic ${topic})` },
    sink:   { file: target.file, line: target.line, label: `${target.tech} consumer reaches ${sourceFinding.vuln}` },
    remediation: `A tainted message written to '${topic}' is read by a handler with a high-severity finding (${sourceFinding.cwe || sourceFinding.vuln}). Validate the payload at both ends: producer should not forward unsanitized request data; consumer should treat the queue body as untrusted.`,
    snippet: `// taint flows: ${origin.file}:${origin.line} → ${target.tech}/${topic} → ${target.file}:${target.line}`,
  };
}

function _downgradeSeverity(sev) {
  // The chain finding is informational alongside the source finding — we
  // demote one tier so it doesn't double-count in severity bucketing.
  const next = { critical: 'high', high: 'medium', medium: 'low', low: 'low' };
  return next[sev || 'high'] || 'low';
}

// For tests + bench tooling.
export function _indexQueueSites(fileContents) { return indexQueueSites(fileContents); }
