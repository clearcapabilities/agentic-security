---
description: Generate an AI/ML Bill of Materials (AI-BOM) — every model, prompt template, inference framework, and vector store your project uses. Mirrors SBOM/PBOM but for the AI surface.
argument-hint: "[--format aibom|aibom-md] [--output <file>]"
---

Emit an AI-BOM for the current project. Compatible with the CycloneDX 1.7 ML-BOM extension.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format ${FORMAT:-aibom-md} --output ${OUTPUT:-aibom.md}
```

The AI-BOM captures:

| Category | What's included |
|---|---|
| **Models** | Hugging Face model IDs (with `revision` SHA when pinned), OpenAI / Anthropic / Google / Mistral / Cohere / Groq / Bedrock / Replicate model names called via SDK |
| **Prompt templates** | Files under `prompts/` or `templates/prompts/`, plus `.prompt`, `.j2`, `.jinja`, `.tmpl`, `.mustache`, `.hbs` files (with sha256 hash + line count) |
| **Inference frameworks** | `transformers`, `torch`, `openai`, `anthropic`, `langchain`, `llamaindex`, etc. extracted from your manifests |
| **Vector stores** | `pinecone`, `weaviate`, `chromadb`, `qdrant`, `pgvector`, `milvus`, `faiss` |
| **Embedding providers** | `sentence-transformers` and SDK-provided embedding endpoints |

Output formats:

- `--format aibom` — JSON (machine-readable, CycloneDX 1.7 ML-BOM compatible)
- `--format aibom-md` — Markdown table (human-readable, for README / compliance docs)

## Why this exists

Customers and security reviewers increasingly ask "what AI components does your app use?" An AI-BOM is the AI counterpart to an SBOM — required by emerging regulation (EU AI Act, NIST AI RMF) and by enterprise customer security questionnaires. Generating it from already-scanned source means it's always current and never has to be hand-maintained.
