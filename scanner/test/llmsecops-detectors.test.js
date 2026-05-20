// v0.68 — LLMSecOps detector tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanStoredPromptInjection } from '../src/sast/llm-stored-prompt.js';
import { scanRAGPoisoning } from '../src/sast/rag-poisoning.js';
import { scanAgentToolEscalation } from '../src/sast/agent-tool-escalation.js';

// ─── Stored-prompt injection ───────────────────────────────────────────────

test('stored-prompt — DB-loaded system prompt fed to OpenAI fires', () => {
  const out = scanStoredPromptInjection('chat.js', `
const OpenAI = require('openai');
const openai = new OpenAI();
async function chat(userMessage) {
  const sysPrompt = await db.query('SELECT content FROM prompts WHERE id=1');
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'system', content: sysPrompt }, { role: 'user', content: userMessage }]
  });
}
`);
  assert.ok(out.length >= 1, 'expected stored-prompt finding');
  assert.equal(out[0].cwe, 'CWE-1336');
});

test('stored-prompt — hardcoded constant system prompt does NOT fire', () => {
  const out = scanStoredPromptInjection('chat.js', `
const OpenAI = require('openai');
const openai = new OpenAI();
const SYSTEM_PROMPT = "You are a helpful assistant.";
async function chat(userMessage) {
  return openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: userMessage }]
  });
}
`);
  assert.equal(out.length, 0, 'constant prompts are safe');
});

test('stored-prompt — wrapWithDelimiters helper suppresses', () => {
  const out = scanStoredPromptInjection('chat.js', `
const sysPrompt = wrapWithDelimiters(await db.query('SELECT content FROM prompts'));
openai.chat.completions.create({ messages: [{ role: 'system', content: sysPrompt }] });
`);
  assert.equal(out.length, 0, 'hardening helper should suppress');
});

// ─── RAG poisoning ─────────────────────────────────────────────────────────

test('rag-poisoning — Chroma add with req.body and no metadata fires', () => {
  const out = scanRAGPoisoning('ingest.py', `
import chromadb
client = chromadb.Client()
collection = client.create_collection('docs')
def ingest(request):
    collection.add(documents=[request.body['text']])
`);
  assert.ok(out.length >= 1, 'expected RAG poisoning finding');
  assert.equal(out[0].cwe, 'CWE-1336');
  assert.equal(out[0].family, 'rag-poisoning');
});

test('rag-poisoning — Chroma add WITH metadata.source/trust_level suppresses', () => {
  const out = scanRAGPoisoning('ingest.py', `
import chromadb
client = chromadb.Client()
collection = client.create_collection('docs')
def ingest(request):
    collection.add(documents=[request.body['text']],
                   metadatas=[{'source': 'user-tier', 'trust_level': 'low', 'tenant_id': request.user.id}])
`);
  assert.equal(out.length, 0, 'metadata with trust_level should suppress');
});

test('rag-poisoning — Pinecone upsert with user-controlled vectors fires', () => {
  const out = scanRAGPoisoning('ingest.py', `
import pinecone
index = pinecone.Index('docs')
def ingest(request):
    index.upsert(vectors=[(request.body['id'], request.body['vec'])])
`);
  assert.ok(out.length >= 1);
});

// ─── Agent tool escalation ─────────────────────────────────────────────────

test('agent-tool-escalation — read tool + act tool with no approval gate fires', () => {
  const out = scanAgentToolEscalation('agent.py', `
from langchain.tools import Tool
def list_files(path): return os.listdir(path)
def exec_command(cmd): return subprocess.run(cmd, shell=True)
tools = [
  Tool(name="list_files", func=list_files, description="list files in a directory"),
  Tool(name="exec_command", func=exec_command, description="run a shell command"),
]
`);
  assert.ok(out.length >= 1, 'expected an agent-tool-escalation finding');
  assert.equal(out[0].cwe, 'CWE-269');
  assert.equal(out[0].family, 'agent-tool-escalation');
});

test('agent-tool-escalation — with explicit approval helper, suppresses', () => {
  const out = scanAgentToolEscalation('agent.js', `
const list_files = new Tool({ name: "list_files", func: lf });
const exec_command = new Tool({ name: "exec_command", func: async (cmd, opts) => {
  await requireConfirmation(opts.user, cmd);
  return exec(cmd);
}});
`);
  assert.equal(out.length, 0, 'requireConfirmation helper should suppress');
});

test('agent-tool-escalation — only read tools, no escalation', () => {
  const out = scanAgentToolEscalation('agent.py', `
from langchain.tools import Tool
tools = [
  Tool(name="search_docs", func=sd),
  Tool(name="get_user", func=gu),
  Tool(name="list_orders", func=lo),
]
`);
  assert.equal(out.length, 0, 'read-only tool surface is fine');
});
