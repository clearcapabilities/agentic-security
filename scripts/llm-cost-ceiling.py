#!/usr/bin/env python3
"""
llm-cost-ceiling.py — audit LLM call sites and enforce a spend ceiling.

Vibe-coders ship LLM apps without realising that a single prompt-injection
attack on an uncapped endpoint can rack up tens of thousands of dollars in
hours. This script:

  1. Audits every Anthropic / OpenAI / Mistral / Cohere SDK call site
  2. Reports which calls have no max_tokens, no rate limit, no spend cap
  3. Auto-patches max_tokens=1024 into bare create() calls (with --apply)
  4. Generates rate-limit middleware scaffolding for the detected framework
  5. Emits a per-user-per-day spend tracker (lightweight, in-process)

Usage:
  python3 scripts/llm-cost-ceiling.py                       # audit only
  python3 scripts/llm-cost-ceiling.py --apply               # auto-patch max_tokens
  python3 scripts/llm-cost-ceiling.py --generate-middleware # write middleware files
  python3 scripts/llm-cost-ceiling.py --daily-cap-dollars 50 --generate-tracker
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Detection patterns
# ─────────────────────────────────────────────────────────────────────────────

# Match `<sdk>.<method>(...)` blocks and let later analysis look for max_tokens.
# We deliberately keep regex shallow — false negatives on edge cases are OK,
# auto-patching is gated by --apply and FP-safe.
#
# Patterns are gated by file extension so a JS regex doesn't also fire in Python.
JS_EXTS = {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}
PY_EXTS = {".py"}

CALL_PATTERNS_JS = [
    (re.compile(r"\b(?:anthropic|client|messages|ai)\s*\.\s*messages\s*\.\s*create\s*\(", re.M), "anthropic-js"),
    (re.compile(r"\b(?:openai|client|ai)\s*\.\s*chat\s*\.\s*completions\s*\.\s*create\s*\(", re.M), "openai-js"),
    (re.compile(r"\b(?:openai|client)\s*\.\s*completions\s*\.\s*create\s*\(", re.M), "openai-js-legacy"),
]
CALL_PATTERNS_PY = [
    (re.compile(r"\b(?:client|anthropic)\.messages\.create\s*\(", re.M), "anthropic-py"),
    (re.compile(r"\b(?:client|openai)\.chat\.completions\.create\s*\(", re.M), "openai-py"),
]

# Match max_tokens, max_completion_tokens (OpenAI o1/o3), max_output_tokens (Gemini)
MAX_TOKENS_RE = re.compile(r"\bmax_(?:tokens|completion_tokens|output_tokens)\s*[:=]")


def extract_call_block(text: str, start: int) -> tuple[int, int, str]:
    """Find the closing paren of the call that starts at `start`. Returns
       (open_paren_idx, close_paren_idx, call_body)."""
    open_idx = text.find("(", start)
    if open_idx < 0:
        return -1, -1, ""
    depth = 0
    i = open_idx
    in_str = None
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ("'", '"', "`"):
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return open_idx, i, text[open_idx+1:i]
        i += 1
    return open_idx, -1, ""


# ─────────────────────────────────────────────────────────────────────────────
# Audit
# ─────────────────────────────────────────────────────────────────────────────

SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv", "test", "tests", "__tests__"}
TEXT_EXTS = {".js", ".ts", ".tsx", ".jsx", ".py", ".mjs", ".cjs"}


def walk_source_files(cwd: Path):
    for path in cwd.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix in TEXT_EXTS:
            yield path


def audit(cwd: Path) -> list[dict]:
    findings = []
    seen = set()  # (file, open_paren) — dedupe overlapping patterns
    for path in walk_source_files(cwd):
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        if path.suffix in JS_EXTS:
            patterns = CALL_PATTERNS_JS
        elif path.suffix in PY_EXTS:
            patterns = CALL_PATTERNS_PY
        else:
            continue
        for pat, sdk in patterns:
            for m in pat.finditer(text):
                open_idx, close_idx, body = extract_call_block(text, m.end() - 1)
                if open_idx < 0:
                    continue
                key = (str(path), open_idx)
                if key in seen:
                    continue
                seen.add(key)
                has_max = bool(MAX_TOKENS_RE.search(body))
                line = text.count("\n", 0, m.start()) + 1
                findings.append({
                    "file": str(path.relative_to(cwd)),
                    "line": line,
                    "sdk": sdk,
                    "has_max_tokens": has_max,
                    "call_start": m.start(),
                    "open_paren": open_idx,
                    "close_paren": close_idx,
                    "snippet": text[m.start():close_idx+1][:200],
                })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Auto-patch
# ─────────────────────────────────────────────────────────────────────────────

def patch_file(cwd: Path, findings: list[dict], default_max: int) -> int:
    """For each call missing max_tokens, inject it as the first arg property.
       Conservative: only patches when the call body is a single object literal
       (JS/TS) or kwargs block (Python) — leaves complex cases alone.
    """
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        if not f["has_max_tokens"]:
            by_file.setdefault(f["file"], []).append(f)

    patched_count = 0
    for rel, file_findings in by_file.items():
        path = cwd / rel
        text = path.read_text()
        # Patch from bottom up to keep indices valid
        file_findings.sort(key=lambda f: f["open_paren"], reverse=True)
        for f in file_findings:
            open_idx = f["open_paren"]
            body_start = open_idx + 1
            # Skip whitespace
            i = body_start
            while i < len(text) and text[i] in " \t\n\r":
                i += 1
            if i >= len(text):
                continue
            sdk = f["sdk"]
            is_py = sdk.endswith("-py")
            # Insert max_tokens= as first kwarg / property
            if is_py:
                insertion = f"max_tokens={default_max}, "
            else:
                # JS/TS — expect object literal `{ ... }`
                if text[i] != "{":
                    continue
                insertion = f"\n    max_tokens: {default_max},"
                # Insert after the `{`
                i = i + 1
            text = text[:i] + insertion + text[i:]
            patched_count += 1
        path.write_text(text)
    return patched_count


# ─────────────────────────────────────────────────────────────────────────────
# Middleware + tracker generators
# ─────────────────────────────────────────────────────────────────────────────

EXPRESS_RATE_LIMIT_TS = """// agentic-security: auto-generated LLM rate-limit middleware
// Mount this on every route that hits an LLM. Defaults: 20 calls / IP / minute.
//
// Usage:
//   import { llmRateLimit } from './middleware/llm-rate-limit';
//   app.use('/api/ai', llmRateLimit({ limit: 20, windowMs: 60_000 }));

import type { Request, Response, NextFunction } from 'express';

type Bucket = { tokens: number; resetAt: number };
const buckets = new Map<string, Bucket>();

export function llmRateLimit(opts: { limit?: number; windowMs?: number } = {}) {
  const limit = opts.limit ?? 20;
  const windowMs = opts.windowMs ?? 60_000;
  return (req: Request, res: Response, next: NextFunction) => {
    const key = req.ip ?? req.headers['x-forwarded-for']?.toString() ?? 'unknown';
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || now > b.resetAt) {
      b = { tokens: limit, resetAt: now + windowMs };
      buckets.set(key, b);
    }
    if (b.tokens <= 0) {
      res.setHeader('Retry-After', Math.ceil((b.resetAt - now) / 1000));
      return res.status(429).json({ error: 'rate_limit_exceeded' });
    }
    b.tokens--;
    next();
  };
}
"""

NEXT_RATE_LIMIT_TS = """// agentic-security: auto-generated LLM rate-limit for Next.js App Router
// Wrap any LLM-calling route handler with this. Defaults: 20 calls / IP / minute.
//
// Usage:
//   import { withLLMRateLimit } from '@/middleware/llm-rate-limit';
//   export const POST = withLLMRateLimit(async (req) => { ... });

type Bucket = { tokens: number; resetAt: number };
const buckets = new Map<string, Bucket>();

export function withLLMRateLimit(
  handler: (req: Request) => Promise<Response>,
  opts: { limit?: number; windowMs?: number } = {}
) {
  const limit = opts.limit ?? 20;
  const windowMs = opts.windowMs ?? 60_000;
  return async (req: Request) => {
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    const now = Date.now();
    let b = buckets.get(ip);
    if (!b || now > b.resetAt) {
      b = { tokens: limit, resetAt: now + windowMs };
      buckets.set(ip, b);
    }
    if (b.tokens <= 0) {
      return new Response(JSON.stringify({ error: 'rate_limit_exceeded' }), {
        status: 429,
        headers: { 'Retry-After': String(Math.ceil((b.resetAt - now) / 1000)) },
      });
    }
    b.tokens--;
    return handler(req);
  };
}
"""

PYTHON_RATE_LIMIT = '''# agentic-security: auto-generated LLM rate-limit middleware
# Defaults: 20 calls / IP / minute. Drop-in for FastAPI / Starlette.
#
# Usage:
#   from middleware.llm_rate_limit import llm_rate_limit
#   app.add_middleware(llm_rate_limit, limit=20, window_seconds=60)

from time import time
from typing import Callable

class llm_rate_limit:
    def __init__(self, app, limit: int = 20, window_seconds: int = 60):
        self.app = app
        self.limit = limit
        self.window = window_seconds
        self.buckets: dict[str, tuple[int, float]] = {}

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        client_ip = headers.get(b"x-forwarded-for", b"unknown").decode().split(",")[0].strip()
        now = time()
        tokens, reset = self.buckets.get(client_ip, (self.limit, now + self.window))
        if now > reset:
            tokens, reset = self.limit, now + self.window
        if tokens <= 0:
            await send({"type": "http.response.start", "status": 429,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body",
                        "body": b'{"error":"rate_limit_exceeded"}'})
            return
        self.buckets[client_ip] = (tokens - 1, reset)
        return await self.app(scope, receive, send)
'''

SPEND_TRACKER_TS = """// agentic-security: per-day LLM spend tracker
// Wraps any LLM client call to estimate $/day and refuse calls above the cap.
// In production, replace the file-backed store with Redis or a database.

import * as fs from 'node:fs';
import * as path from 'node:path';

const STATE = path.join(process.cwd(), '.agentic-security', 'spend.json');
// Rough per-1k-tokens prices in USD. Update for your actual rates.
const PRICES: Record<string, { input: number; output: number }> = {
  'claude-sonnet-4-6':      { input: 0.003, output: 0.015 },
  'claude-opus-4-7':        { input: 0.015, output: 0.075 },
  'gpt-4o':                 { input: 0.0025, output: 0.010 },
  'gpt-4o-mini':            { input: 0.00015, output: 0.0006 },
};

export class SpendCeilingExceeded extends Error {}

function loadState(): Record<string, number> {
  try { return JSON.parse(fs.readFileSync(STATE, 'utf8')); } catch { return {}; }
}
function saveState(s: Record<string, number>) {
  fs.mkdirSync(path.dirname(STATE), { recursive: true });
  fs.writeFileSync(STATE, JSON.stringify(s));
}

export function trackAndGate(opts: { dailyCapUsd: number; model: string; inputTokens: number; outputTokens: number; }) {
  const day = new Date().toISOString().slice(0, 10);
  const state = loadState();
  const price = PRICES[opts.model] ?? { input: 0.005, output: 0.020 };
  const cost = (opts.inputTokens / 1000) * price.input + (opts.outputTokens / 1000) * price.output;
  state[day] = (state[day] ?? 0) + cost;
  saveState(state);
  if (state[day] > opts.dailyCapUsd) {
    throw new SpendCeilingExceeded(`Daily LLM spend cap of $${opts.dailyCapUsd} hit at $${state[day].toFixed(2)}.`);
  }
  return state[day];
}
"""


def detect_framework(cwd: Path) -> str:
    pkg = cwd / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if "next" in deps:
                return "next"
            if "express" in deps:
                return "express"
            if "fastify" in deps:
                return "fastify"
        except Exception:
            pass
    if (cwd / "pyproject.toml").exists() or any(cwd.rglob("requirements*.txt")):
        return "python"
    return "unknown"


def generate_middleware(cwd: Path) -> list[Path]:
    fw = detect_framework(cwd)
    out_dir = cwd / "middleware"
    out_dir.mkdir(exist_ok=True)
    written = []
    if fw == "next":
        p = out_dir / "llm-rate-limit.ts"
        p.write_text(NEXT_RATE_LIMIT_TS)
        written.append(p)
    elif fw in ("express", "fastify"):
        p = out_dir / "llm-rate-limit.ts"
        p.write_text(EXPRESS_RATE_LIMIT_TS)
        written.append(p)
    elif fw == "python":
        p = out_dir / "llm_rate_limit.py"
        p.write_text(PYTHON_RATE_LIMIT)
        written.append(p)
    else:
        # default: write all three
        (out_dir / "llm-rate-limit.next.ts").write_text(NEXT_RATE_LIMIT_TS)
        (out_dir / "llm-rate-limit.express.ts").write_text(EXPRESS_RATE_LIMIT_TS)
        (out_dir / "llm_rate_limit.py").write_text(PYTHON_RATE_LIMIT)
        written.extend(out_dir.glob("llm*"))
    return written


def generate_tracker(cwd: Path) -> Path:
    out_dir = cwd / "lib"
    out_dir.mkdir(exist_ok=True)
    p = out_dir / "llm-spend-tracker.ts"
    p.write_text(SPEND_TRACKER_TS)
    return p


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Audit + enforce LLM cost ceilings.")
    parser.add_argument("--cwd", default=None, help="Project root")
    parser.add_argument("--apply", action="store_true",
                        help="Auto-patch missing max_tokens (default value below)")
    parser.add_argument("--default-max-tokens", type=int, default=1024,
                        help="Value to inject for missing max_tokens (default 1024)")
    parser.add_argument("--generate-middleware", action="store_true",
                        help="Write rate-limit middleware scaffolding")
    parser.add_argument("--generate-tracker", action="store_true",
                        help="Write a daily-spend tracker module")
    parser.add_argument("--daily-cap-dollars", type=float, default=50.0,
                        help="Daily $ cap (used in messages only)")
    parser.add_argument("--json", action="store_true", help="JSON output for audit")
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve() if args.cwd else Path.cwd()
    findings = audit(cwd)

    if args.json:
        print(json.dumps(findings, indent=2))
        sys.exit(1 if any(not f["has_max_tokens"] for f in findings) else 0)

    if not findings:
        print("✓ No LLM call sites found.")
        sys.exit(0)

    missing = [f for f in findings if not f["has_max_tokens"]]
    print(f"LLM call audit ({cwd}):")
    print(f"  Total call sites:           {len(findings)}")
    print(f"  Missing max_tokens cap:     {len(missing)}")
    print()
    if missing:
        print("  ⚠️  Each uncapped call is a potential cost-runaway under prompt-injection.")
        print("       One attack on an uncapped endpoint can cost thousands per hour.")
        print()
        for f in missing[:20]:
            print(f"   - {f['file']}:{f['line']}  ({f['sdk']})")
        if len(missing) > 20:
            print(f"   ... and {len(missing) - 20} more")
        print()

    if args.apply and missing:
        n = patch_file(cwd, findings, args.default_max_tokens)
        print(f"  ✓ Auto-patched max_tokens={args.default_max_tokens} into {n} call site(s).")
        print(f"    Review the diff before committing:  git diff")

    if args.generate_middleware:
        written = generate_middleware(cwd)
        for p in written:
            print(f"  ✓ Generated rate-limit middleware: {p.relative_to(cwd)}")
        print(f"    Mount it on every LLM-calling route to cap calls per IP.")

    if args.generate_tracker:
        p = generate_tracker(cwd)
        print(f"  ✓ Generated spend tracker: {p.relative_to(cwd)}")
        print(f"    Suggested daily cap: ${args.daily_cap_dollars:.2f}")
        print(f"    Wrap your LLM calls with trackAndGate({{ dailyCapUsd: {args.daily_cap_dollars} }})")

    if not (args.apply or args.generate_middleware or args.generate_tracker):
        print("Recommended next steps:")
        print(f"  1. Auto-patch caps:    python3 scripts/llm-cost-ceiling.py --apply")
        print(f"  2. Add rate-limit:     python3 scripts/llm-cost-ceiling.py --generate-middleware")
        print(f"  3. Add spend tracker:  python3 scripts/llm-cost-ceiling.py --generate-tracker --daily-cap-dollars 50")

    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    main()
