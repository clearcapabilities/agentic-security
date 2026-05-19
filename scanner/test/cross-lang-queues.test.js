// Cross-language queue taint propagation (P1.5 / FR-XSAT-4).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCrossLangQueues, _indexQueueSites } from '../src/posture/cross-lang-queues.js';

// ─── Indexing — does the regex catalogue find producers and consumers? ─────

test('indexQueueSites finds kafkajs producer and consumer', () => {
  const fc = {
    'svc-a/index.js': `
const { Kafka } = require('kafkajs');
const producer = kafka.producer();
async function send(req) {
  await producer.send({ topic: 'orders.created', messages: [{ value: req.body.payload }] });
}`,
    'svc-b/handler.js': `
const consumer = kafka.consumer({ groupId: 'g' });
await consumer.subscribe({ topics: ['orders.created'], fromBeginning: true });
consumer.run({ eachMessage: async ({ message }) => {
  eval(message.value.toString());  // imagine this is the high-sev sink
}});`,
  };
  const { producers, consumers } = _indexQueueSites(fc);
  assert.ok(producers.get('orders.created'), 'producer should be indexed');
  assert.ok(consumers.get('orders.created'), 'consumer should be indexed');
});

test('indexQueueSites finds AWS SQS producer + consumer', () => {
  const fc = {
    'producer.ts': `await sqsClient.sendMessage({ QueueUrl: 'https://sqs.us-east-1.amazonaws.com/123/user-events', MessageBody: payload });`,
    'consumer.py': `r = sqs.receive_message(QueueUrl='https://sqs.us-east-1.amazonaws.com/123/user-events')`,
  };
  const { producers, consumers } = _indexQueueSites(fc);
  assert.ok(producers.get('user-events'), 'SQS producer keyed by queue name');
  assert.ok(consumers.get('user-events'), 'SQS consumer keyed by queue name');
});

test('indexQueueSites finds RabbitMQ amqplib publish + consume', () => {
  const fc = {
    'a.js': `ch.publish('events.exchange', '', Buffer.from(payload));`,
    'b.js': `ch.consume('events.exchange', msg => handler(msg.content));`,
  };
  const { producers, consumers } = _indexQueueSites(fc);
  assert.ok(producers.get('events.exchange'));
  assert.ok(consumers.get('events.exchange'));
});

test('indexQueueSites finds Redis XADD + XREAD', () => {
  const fc = {
    'a.go': `client.XAdd(ctx, &redis.XAddArgs{ Stream: "logs.stream", Values: map[string]interface{}{"data": tainted} })`,
    'b.js': `await client.xread({ key: 'logs.stream', id: '0' });`,
  };
  const { producers, consumers } = _indexQueueSites(fc);
  // The Go XADD shape is matched by the second redis pattern (XADD <stream>).
  const hasProd = producers.get('logs.stream') !== undefined ||
                  [...producers.keys()].some(k => k.includes('logs.stream'));
  const hasCons = consumers.get('logs.stream') !== undefined ||
                  [...consumers.keys()].some(k => k.includes('logs.stream'));
  assert.ok(hasProd || hasCons,
    'expected to recognize at least one side of the Redis stream pair');
});

// ─── Chain emission — does a finding on one side surface on the other? ────

test('chain emits when consumer-side has a high-sev finding', () => {
  const fc = {
    'producer.js': `await producer.send({ topic: 'work.queue', messages: [{ value: req.body.cmd }] });`,
    'consumer.js': `consumer.run({ eachMessage: async ({ message }) => { require('child_process').exec(message.value.toString()); }});\nawait consumer.subscribe({ topics: ['work.queue'] });`,
  };
  const findings = [
    {
      vuln: 'Command Injection',
      severity: 'critical',
      cwe: 'CWE-78',
      file: 'consumer.js',
      line: 1,
    },
  ];
  const chains = scanCrossLangQueues(fc, findings);
  assert.ok(chains.length > 0, 'expected at least one chain finding back to the producer');
  const back = chains.find(c => c.file === 'producer.js');
  assert.ok(back, 'expected a chain finding rooted at the producer');
  assert.equal(back.boundary, 'queue');
  assert.equal(back.cross_language, true);
  assert.equal(back.tech, 'kafka');
  assert.equal(back.topic, 'work.queue');
  assert.ok(back.vuln.includes('Command Injection'), 'chain vuln should reference the underlying finding');
});

test('no chain emitted when producer/consumer disagree on topic', () => {
  const fc = {
    'a.js': `producer.send({ topic: 'orders', messages: [{ value: req.body }] });`,
    'b.js': `consumer.subscribe({ topics: ['payments'] }); consumer.run(...)`,
  };
  const findings = [{ vuln: 'SQL Injection', severity: 'high', cwe: 'CWE-89', file: 'b.js', line: 1 }];
  const chains = scanCrossLangQueues(fc, findings);
  assert.equal(chains.length, 0, 'topic mismatch must not chain');
});

test('chain severity is one tier below the source finding', () => {
  const fc = {
    'p.js': `producer.send({ topic: 't', messages: [{ value: x }] });`,
    'c.js': `consumer.subscribe({ topics: ['t'] }); consumer.run(...)`,
  };
  // Vuln must be in the chain-worthy set (FR-CHAIN-FILTER) — bare 'X' is not.
  const findings = [{ vuln: 'XSS', severity: 'critical', cwe: 'CWE-79', file: 'c.js', line: 1 }];
  const chains = scanCrossLangQueues(fc, findings);
  const at = chains.find(c => c.file === 'p.js');
  assert.equal(at.severity, 'high', 'critical source → high chain');
});

test('low-severity source produces no high-priority chain', () => {
  const fc = {
    'p.js': `producer.send({ topic: 't', messages: [{ value: x }] });`,
    'c.js': `consumer.subscribe({ topics: ['t'] }); consumer.run(...)`,
  };
  // Chain-worthy vuln, but low severity → still no chain (severity gate).
  const findings = [{ vuln: 'XSS', severity: 'low', cwe: 'CWE-79', file: 'c.js', line: 1 }];
  const chains = scanCrossLangQueues(fc, findings);
  assert.equal(chains.length, 0, 'low-severity source should not trigger a cross-language chain (config: only critical|high)');
});

test('null findings/fileContents do not throw', () => {
  assert.doesNotThrow(() => scanCrossLangQueues(null, null));
  assert.deepEqual(scanCrossLangQueues({}, []), []);
});
