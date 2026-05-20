// RAG Context-Poisoning Path (OWASP LLM02 — Training-Data Poisoning,
// applied at retrieval-time rather than fine-tune time).
//
// Pattern: untrusted text from a user (req.body, file upload, web scrape,
// external API) is written into a vector store / retrieval index without
// (a) source attribution, (b) trust-level tagging, or (c) downstream
// retrieval-side filtering. At LLM query time, the poisoned chunk is
// retrieved with no signal that it shouldn't be trusted, and its
// embedded instructions ride along into the model's context.
//
// We catch the WRITE side, not the READ — the retrieval side is too
// generic to flag without taint context. The write-side signature is
// strong: `<vector_store>.add(text=<user_input>)` with no metadata
// indicating provenance / trust level.
//
// Vector-store libraries covered (v1):
//   - chromadb (Python):  collection.add(documents=[...])
//   - pinecone (Python/JS): index.upsert(vectors=[{values, metadata}])
//   - weaviate:           client.collections.<n>.data.insert(...)
//   - qdrant:             client.upsert(collection_name, points=[...])
//   - langchain:          vectorstore.add_documents(...)
//   - pgvector:           INSERT INTO embeddings (vec, content) VALUES (...)
//
// Suppress when:
//   - the call includes `metadata: { source, trust_level, … }` and the
//     trust_level is a non-trivial argument (not just '"trusted"')
//   - a known sanitizer or denylist filter is referenced in the preceding
//     30 lines

import { blankComments } from './_comment-strip.js';

const TAINT_HINT_RE =
  /\b(?:req\.|request\.|params\.|query\.|body\.|ctx\.query|ctx\.request|reply\.query|c\.Query|r\.URL\.Query|_GET|_POST|_REQUEST|getParameter|getHeader|webhook|scrape|fetch\s*\()/;

const PATTERNS = [
  // chromadb collection.add
  ['py', /\b(?:collection|chroma_collection)\s*\.\s*add\s*\(\s*documents\s*=\s*([^)]+?)\s*[,)]/g, 'ChromaDB'],
  // langchain add_documents / add_texts
  ['py', /\bvectorstore\s*\.\s*add_(?:documents|texts)\s*\(\s*([^)]+?)\s*[,)]/g, 'LangChain'],
  ['js', /\bvectorStore\s*\.\s*add(?:Documents|Texts)\s*\(\s*([^)]+?)\s*[,)]/g, 'LangChain.js'],
  // pinecone upsert
  ['py', /\bindex\s*\.\s*upsert\s*\(\s*vectors\s*=\s*([^)]+?)\s*[,)]/g, 'Pinecone'],
  ['js', /\bindex\s*\.\s*upsert\s*\(\s*([^)]+?)\s*\)/g, 'Pinecone'],
  // weaviate insert
  ['py', /\.\s*data\s*\.\s*insert\s*\(\s*([^)]+?)\s*[,)]/g, 'Weaviate'],
  // qdrant upsert
  ['py', /\bclient\s*\.\s*upsert\s*\(\s*collection_name[^,]+,\s*points\s*=\s*([^)]+?)\s*[,)]/g, 'Qdrant'],
  // pgvector via raw INSERT
  ['py', /\bINSERT\s+INTO\s+\w*embedding[^;]*VALUES\s*\(\s*([^)]+?)\)/gi, 'pgvector raw INSERT'],
];

const PROVENANCE_HINT_RE =
  /\bmetadatas?\s*[=:]\s*\[?\s*\{[^}]*(?:source|trust_level|provenance|tenant_id|user_id|origin)/i;

const SANITIZER_HINT_RE =
  /\b(?:bleach\s*\.\s*clean|DOMPurify\.sanitize|stripUntrustedInstructions|detect_prompt_injection|denylist[A-Za-z0-9_]*|trustLevelOf)\b/;

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }
function _lang(fp) {
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) return 'js';
  if (/\.py$/i.test(fp)) return 'py';
  return null;
}
function _hasSanitizerAbove(raw, line) {
  const lines = raw.split('\n');
  const lo = Math.max(0, line - 30);
  return SANITIZER_HINT_RE.test(lines.slice(lo, line).join('\n'));
}

export function scanRAGPoisoning(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const lang = _lang(fp);
  if (!lang) return [];
  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  if (!/\b(?:chromadb|chroma|pinecone|weaviate|qdrant|pgvector|langchain|vectorstore|vectorStore|embedding)\b/i.test(code)) return [];
  const findings = [];
  const seen = new Set();
  for (const [plang, pat, label] of PATTERNS) {
    if (plang !== lang) continue;
    const re = new RegExp(pat.source, pat.flags);
    let m;
    while ((m = re.exec(code))) {
      const callArgs = (m[1] || '');
      if (!TAINT_HINT_RE.test(callArgs)) continue;
      // The full call may extend beyond the captured fragment; look at the
      // rest of the line block to check for provenance metadata.
      const lineNo = _lineOf(raw, m.index);
      const lines = raw.split('\n');
      const blockEnd = Math.min(lines.length, lineNo + 5);
      const block = lines.slice(lineNo - 1, blockEnd).join('\n');
      if (PROVENANCE_HINT_RE.test(block)) continue;
      if (_hasSanitizerAbove(raw, lineNo)) continue;
      const id = `rag-poisoning:${fp}:${lineNo}:${label}`;
      if (seen.has(id)) continue;
      seen.add(id);
      findings.push({
        id,
        file: fp, line: lineNo,
        vuln: `RAG Context-Poisoning Path (${label})`,
        severity: 'high',
        cwe: 'CWE-1336',
        family: 'rag-poisoning',
        stride: 'Tampering',
        snippet: (lines[lineNo - 1] || '').trim().slice(0, 200),
        remediation:
          'Untrusted user content is being written to a retrieval index without a provenance/trust-level tag. At retrieval time the chunk will appear in LLM context with no signal it shouldn\'t be trusted, and any embedded instructions ride along. ' +
          'Mitigations: ' +
          '(1) tag every write with `metadata: { source, trust_level, tenant_id }` and FILTER on `trust_level` at retrieval time; ' +
          '(2) keep user-generated content in a separate index from curated/admin content and never mix them in the same retrieval; ' +
          '(3) at retrieval time, wrap user-tier chunks in rare-token delimiters and instruct the model to treat them as data, not instructions; ' +
          '(4) reject content that contains known prompt-injection sentinels ("ignore previous instructions", role-frame strings, etc.) before insertion.',
        parser: 'RAG-POISONING',
        confidence: 0.75,
      });
    }
  }
  return findings;
}
