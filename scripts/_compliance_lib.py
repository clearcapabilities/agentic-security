#!/usr/bin/env python3
"""Shared compliance-scanner library used by owasp-asvs/.

Mirrors the multi-signal evidence model from scripts/nist-compliance/ but pared
down for the smaller compliance overlays. Each overlay ships its own
evidence-rules.json with control IDs and per-signal vocabulary; this library
runs the scan and emits markdown / csv / json.
"""
import argparse
import csv
import fnmatch
import json
import os
import re
import sys
from collections import defaultdict


WEIGHTS = {
    "manifest":   5.0,
    "import":     4.0,
    "test_path":  3.0,
    "named_path": 2.5,
    "code_term":  2.0,
    "config_term":1.5,
    "doc_term":   1.0,
    "comment":    0.5,
}

DEFAULT_IGNORE = {
    "node_modules", ".git", "__pycache__", "vendor", "dist", "build",
    ".next", "venv", "env", ".venv", "target", "bin", "obj", ".cache",
    "coverage", "bower_components",
}

CODE_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".rb", ".php", ".java", ".go", ".rs", ".cs"}
CONFIG_EXTS = {".yml", ".yaml", ".json", ".toml", ".ini", ".env", ".cfg", ".properties"}
DOC_EXTS = {".md", ".rst", ".txt", ".adoc"}

NEGATION_RE = re.compile(
    r"(?:^|\s)(?:we\s+don't|do\s+not\s+(?:yet|currently)|future\s+work|missing|planned|not\s+yet|todo:?\s*implement)\b",
    re.I,
)


def list_files(root):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE and not d.startswith(".cache")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.getsize(p) > 500_000:
                continue
            out.append(p)
    return out


def kind_of(path):
    base = os.path.basename(path)
    if base in ("package.json", "requirements.txt", "pyproject.toml", "Pipfile",
                "go.mod", "Cargo.toml", "Gemfile", "composer.json"):
        return "manifest"
    ext = os.path.splitext(path)[1].lower()
    if ext in CODE_EXTS: return "code"
    if ext in CONFIG_EXTS: return "config"
    if ext in DOC_EXTS: return "doc"
    return "other"


def evaluate(root, controls):
    """Evaluate a list of control rules against the codebase. Returns per-control evidence."""
    files = list_files(root)
    rel = lambda p: os.path.relpath(p, root)
    contents = {}
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                contents[rel(f)] = fh.read()
        except Exception:
            continue
    results = {}
    for ctrl in controls:
        cid = ctrl["id"]
        evidence = []
        weight = 0.0
        signals = set()
        # Manifest deps
        for dep in ctrl.get("manifest_deps", []):
            for path, body in contents.items():
                if kind_of(path) != "manifest": continue
                if re.search(r"[\"']" + re.escape(dep) + r"[\"']", body) or re.search(r"^\s*" + re.escape(dep) + r"\s*[<>=~]", body, re.M):
                    evidence.append({"signal": "manifest", "term": dep, "file": path})
                    weight += WEIGHTS["manifest"]; signals.add("manifest"); break
        # Imports
        for imp in ctrl.get("imports", []):
            re_imp = re.compile(r"\b(?:from\s+|import\s+|require\s*\(\s*[\"'])" + re.escape(imp) + r"\b")
            for path, body in contents.items():
                if kind_of(path) != "code": continue
                if re_imp.search(body):
                    evidence.append({"signal": "import", "term": imp, "file": path})
                    weight += WEIGHTS["import"]; signals.add("import"); break
        # Path globs
        for pat in ctrl.get("paths", []):
            for path in contents:
                if fnmatch.fnmatch(path, pat):
                    sig = "test_path" if "/test" in path or "test" in os.path.basename(path).lower() else "named_path"
                    evidence.append({"signal": sig, "term": pat, "file": path})
                    weight += WEIGHTS[sig]; signals.add(sig); break
        # Terms (word-boundary case-insensitive)
        for term in ctrl.get("terms", []):
            re_t = re.compile(r"\b" + re.escape(term) + r"\b", re.I)
            for path, body in contents.items():
                k = kind_of(path)
                if k == "manifest": continue
                # Skip if surrounding context shows negation
                m = re_t.search(body)
                if not m: continue
                start = max(0, m.start() - 60)
                end = min(len(body), m.end() + 60)
                if NEGATION_RE.search(body[start:end]): continue
                sig = "code_term" if k == "code" else "config_term" if k == "config" else "doc_term"
                evidence.append({"signal": sig, "term": term, "file": path})
                weight += WEIGHTS[sig]; signals.add(sig); break
        # Status
        if weight == 0:
            status = "Not Compliant"
        elif weight >= 8 or len(signals) >= 3:
            status = "Compliant"
        else:
            status = "Partial"
        results[cid] = {
            "id": cid,
            "title": ctrl["title"],
            "status": status,
            "weight": round(weight, 2),
            "signals": sorted(signals),
            "evidence": evidence[:10],
        }
    return results


def emit(results, controls, framework, fmt, out_path):
    rows = []
    for ctrl in controls:
        r = results[ctrl["id"]]
        rows.append({
            "id": r["id"],
            "title": r["title"],
            "status": r["status"],
            "weight": r["weight"],
            "signals": "+".join(r["signals"]),
            "evidence_count": len(r["evidence"]),
        })
    if fmt == "json":
        body = json.dumps({"framework": framework, "controls": list(results.values())}, indent=2)
    elif fmt == "csv":
        from io import StringIO
        s = StringIO()
        w = csv.DictWriter(s, fieldnames=["id", "title", "status", "weight", "signals", "evidence_count"])
        w.writeheader()
        for r in rows: w.writerow(r)
        body = s.getvalue()
    else:
        # markdown
        total = len(rows)
        compliant = sum(1 for r in rows if r["status"] == "Compliant")
        partial = sum(1 for r in rows if r["status"] == "Partial")
        none = total - compliant - partial
        lines = [
            f"# {framework} compliance attestation",
            "",
            f"**Total controls:** {total}    **Compliant:** {compliant}    **Partial:** {partial}    **Not Compliant:** {none}",
            "",
            "| ID | Title | Status | Weight | Signals |",
            "|---|---|---|---:|---|",
        ]
        for r in rows:
            icon = "✅" if r["status"] == "Compliant" else "🟡" if r["status"] == "Partial" else "❌"
            lines.append(f"| `{r['id']}` | {r['title']} | {icon} {r['status']} | {r['weight']} | {r['signals']} |")
        body = "\n".join(lines)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh: fh.write(body)
    else:
        sys.stdout.write(body)


def run(framework, rules_path):
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=".", help="Project root to scan")
    ap.add_argument("--format", choices=["md", "csv", "json"], default="md")
    ap.add_argument("--output", default=None)
    args = ap.parse_args()
    with open(rules_path, "r", encoding="utf-8") as fh:
        rules = json.load(fh)
    controls = [c for c in rules.get("controls", []) if not c.get("id", "").startswith("_")]
    results = evaluate(os.path.abspath(args.path), controls)
    emit(results, controls, framework, args.format, args.output)
