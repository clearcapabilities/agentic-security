#!/usr/bin/env python3
"""
risk-in-dollars.py — translate each scanner finding into $ exposure.

CVSS scores don't move non-technical builders. Dollar figures do.
This maps each finding's CWE to a best-/likely-/worst-case exposure
estimate (sourced from public incident data) and shows them sorted by
worst-case $.

Usage:
  python3 scripts/risk-in-dollars.py
  python3 scripts/risk-in-dollars.py --json
  python3 scripts/risk-in-dollars.py --top 10
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BANDS_PATH = SCRIPT_DIR / "data" / "dollar-risk-bands.json"


def load_bands() -> dict:
    return json.loads(BANDS_PATH.read_text())


def load_findings(cwd: Path) -> list[dict]:
    scan_path = cwd / ".agentic-security" / "last-scan.json"
    if not scan_path.exists():
        print(f"ERROR: {scan_path} not found — run /scan --all first.", file=sys.stderr)
        sys.exit(1)
    data = json.loads(scan_path.read_text())
    findings = []
    for key in ("findings", "logicVulns", "supplyChain"):
        findings.extend(data.get(key, []))
    return findings


def vuln_family(finding: dict) -> str:
    cwe = (finding.get("cwe") or "").upper().strip()
    if cwe:
        return cwe
    v = (finding.get("vuln") or "").lower()
    if "sql" in v and "inj" in v:        return "CWE-89"
    if "command inj" in v:                return "CWE-78"
    if "path trav" in v or "lfi" in v:    return "CWE-22"
    if "ssrf" in v:                        return "CWE-918"
    if "xss" in v:                         return "CWE-79"
    if "idor" in v:                        return "CWE-639"
    if "csrf" in v:                        return "CWE-352"
    if "mass assign" in v:                 return "CWE-915"
    if "auth bypass" in v:                 return "CWE-287"
    if "signature" in v:                   return "CWE-345"
    if "deserial" in v:                    return "CWE-502"
    if "prototype pollut" in v:            return "CWE-1321"
    if "hardcoded" in v or "secret" in v:  return "CWE-798"
    if "open redirect" in v:               return "CWE-601"
    if "xxe" in v:                         return "CWE-611"
    if "missing auth" in v or "broken auth" in v: return "CWE-862"
    if "prompt inj" in v:                  return "LLM01"
    if "max_tokens" in v or "rate limit" in v: return "LLM10"
    return "DEFAULT"


def usd(n: int) -> str:
    if n >= 1_000_000:
        return f"${n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"${n / 1_000:.0f}k"
    return f"${n}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Translate scanner findings into $ exposure.")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--top", type=int, default=0, help="Show only the top N findings by worst-case")
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve() if args.cwd else Path.cwd()
    findings = load_findings(cwd)
    bands = load_bands()

    rows = []
    total_worst = 0
    total_likely = 0
    for f in findings:
        family = vuln_family(f)
        band = bands.get(family) or bands.get("DEFAULT")
        rows.append({
            "id": f.get("id"),
            "vuln": f.get("vuln"),
            "cwe": f.get("cwe"),
            "family": family,
            "severity": f.get("severity"),
            "file": f.get("file"),
            "line": f.get("line"),
            "best_case_usd": band["best_case_usd"],
            "likely_case_usd": band["likely_case_usd"],
            "worst_case_usd": band["worst_case_usd"],
            "scenario": band["scenario"],
            "regulatory": band.get("regulatory", ""),
            "name": band["name"],
        })
        total_worst += band["worst_case_usd"]
        total_likely += band["likely_case_usd"]

    rows.sort(key=lambda r: r["worst_case_usd"], reverse=True)
    if args.top > 0:
        rows = rows[:args.top]

    if args.json:
        print(json.dumps({"total_likely_usd": total_likely, "total_worst_usd": total_worst,
                          "findings": rows}, indent=2))
        return

    print("┌─────────────────────────────────────────────────────────────────────────────┐")
    print("│  Security findings translated to $ exposure                                 │")
    print("└─────────────────────────────────────────────────────────────────────────────┘")
    print()
    print(f"  Total findings:       {len(findings)}")
    print(f"  Likely-case total:    {usd(total_likely)}")
    print(f"  Worst-case total:     {usd(total_worst)}")
    print()
    print("  ⚠️  These are conservative public-data estimates, NOT legal advice. Use")
    print("      for prioritisation. Sort: worst-case descending.")
    print()
    print(f"  {'#':<3} {'$ WORST':<10} {'$ LIKELY':<10} {'CLASS':<28} FILE:LINE")
    print(f"  {'-'*3} {'-'*10} {'-'*10} {'-'*28} {'-'*40}")
    for i, r in enumerate(rows, 1):
        loc = f"{(r.get('file') or '?')[:35]}:{r.get('line') or '?'}"
        print(f"  {i:<3} {usd(r['worst_case_usd']):<10} {usd(r['likely_case_usd']):<10} {r['name'][:28]:<28} {loc}")
    print()
    if rows:
        top = rows[0]
        print(f"Top-exposure finding:")
        print(f"  {top['name']}  ({top['file']}:{top['line']})")
        print(f"  Scenario:    {top['scenario']}")
        if top.get("regulatory"):
            print(f"  Regulatory:  {top['regulatory']}")


if __name__ == "__main__":
    main()
