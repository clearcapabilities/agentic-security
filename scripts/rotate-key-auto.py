#!/usr/bin/env python3
"""
rotate-key-auto.py — actively rotate a leaked credential, end-to-end.

Detects the provider from the key's format, generates the EXACT revocation
and re-issuance commands, scrubs the value from every tracked file +
local .env files, and pushes the replacement to known deployment platforms
when their CLI is installed.

This goes beyond /rotate-secret (which guides) — it does the work.

Usage:
  python3 scripts/rotate-key-auto.py <leaked-value-or-prefix>
  python3 scripts/rotate-key-auto.py --scan          # auto-discover all leaked keys in repo
  python3 scripts/rotate-key-auto.py --provider openai --new-value sk-...

Safety:
  - Default mode is INTERACTIVE: prints every action and waits for confirmation.
  - Use --yes to skip prompts (for CI / non-interactive flows).
  - All file edits are reversible via the .agentic-security/rotation-backups/ dir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Provider registry
# ─────────────────────────────────────────────────────────────────────────────

PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "patterns": [r"sk-[A-Za-z0-9_-]{20,}", r"sk-proj-[A-Za-z0-9_-]{20,}"],
        "env_names": ["OPENAI_API_KEY"],
        "console_url": "https://platform.openai.com/api-keys",
        "revoke_steps": [
            "1. Visit https://platform.openai.com/api-keys",
            "2. Find the key whose prefix is shown below and click the trash icon",
            "3. Create a new key (button: 'Create new secret key')",
            "4. Set a usage limit at https://platform.openai.com/account/billing/limits",
        ],
        "cost_warning": (
            "OpenAI keys are billed without a default limit. A leaked key with "
            "no usage cap can be drained to thousands of dollars in hours. "
            "Set a HARD CAP at the URL above as soon as you create the replacement."
        ),
    },
    "anthropic": {
        "name": "Anthropic",
        "patterns": [r"sk-ant-[A-Za-z0-9_-]{20,}"],
        "env_names": ["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        "console_url": "https://console.anthropic.com/settings/keys",
        "revoke_steps": [
            "1. Visit https://console.anthropic.com/settings/keys",
            "2. Click the three-dot menu next to the leaked key → Delete",
            "3. Click 'Create Key' to generate the replacement",
            "4. Set a spend limit at https://console.anthropic.com/settings/limits",
        ],
        "cost_warning": "Anthropic keys are billed at request-time with no default cap.",
    },
    "stripe": {
        "name": "Stripe",
        "patterns": [r"sk_live_[A-Za-z0-9]{24,}", r"rk_live_[A-Za-z0-9]{24,}"],
        "env_names": ["STRIPE_SECRET_KEY", "STRIPE_API_KEY"],
        "console_url": "https://dashboard.stripe.com/apikeys",
        "cli": "stripe",
        "revoke_steps": [
            "1. Visit https://dashboard.stripe.com/apikeys",
            "2. Click 'Roll key' next to the leaked Secret/Restricted key",
            "3. Copy the new value displayed (you'll only see it once)",
            "OR via CLI (requires `stripe login` first):",
            "   stripe keys create --type restricted_key --name 'rotated-$(date +%Y%m%d)'",
        ],
        "cost_warning": (
            "Live Stripe keys = real money. A leaked sk_live can charge cards, "
            "refund to attacker accounts, and pull payout balances. Rotate FIRST, "
            "then audit the payments dashboard for anomalies in the last 24h."
        ),
    },
    "aws": {
        "name": "AWS",
        "patterns": [r"AKIA[0-9A-Z]{16}"],
        "env_names": ["AWS_ACCESS_KEY_ID"],
        "secret_env_names": ["AWS_SECRET_ACCESS_KEY"],
        "console_url": "https://console.aws.amazon.com/iam/home#/security_credentials",
        "cli": "aws",
        "revoke_steps": [
            "1. Mark old key inactive:  aws iam update-access-key --access-key-id <KEY> --status Inactive --user-name <USER>",
            "2. Create replacement:      aws iam create-access-key --user-name <USER>",
            "3. Delete old key:          aws iam delete-access-key --access-key-id <KEY> --user-name <USER>",
            "OR via console: IAM → Users → <username> → Security credentials → Make inactive → Delete → Create access key",
        ],
        "cost_warning": (
            "AWS keys are the worst leak — attackers spin up GPU instances for crypto-mining "
            "and rack up tens of thousands of dollars in hours. The instant you suspect "
            "exposure: set the key Inactive (above) before you do anything else."
        ),
    },
    "github": {
        "name": "GitHub",
        "patterns": [r"ghp_[A-Za-z0-9]{36}", r"github_pat_[A-Za-z0-9_]{82}"],
        "env_names": ["GITHUB_TOKEN", "GH_TOKEN"],
        "console_url": "https://github.com/settings/tokens",
        "cli": "gh",
        "revoke_steps": [
            "1. Visit https://github.com/settings/tokens",
            "2. Click the leaked token name → 'Delete' (top-right)",
            "3. Generate replacement: 'Generate new token (classic)' or 'Fine-grained tokens → Generate'",
            "OR via CLI:  gh auth refresh   (rotates the gh-managed token)",
        ],
        "cost_warning": "GitHub tokens with `repo` scope can push to any repo you own — including supply-chain attack vectors.",
    },
    "supabase-service-role": {
        "name": "Supabase service-role key",
        "patterns": [r"eyJ[A-Za-z0-9_-]{60,}\.eyJ[^.]+\.[A-Za-z0-9_-]+"],  # JWT — refined by header check below
        "env_names": ["SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_SERVICE_KEY"],
        "console_url": "https://supabase.com/dashboard/project/_/settings/api",
        "revoke_steps": [
            "1. Visit https://supabase.com/dashboard/project/_/settings/api",
            "2. Click 'Generate new JWT secret' (this invalidates ALL JWTs — anon AND service-role)",
            "3. Copy the new service_role key from the same page",
            "4. Update every server-side env: SUPABASE_SERVICE_ROLE_KEY=<new>",
            "5. Update SUPABASE_ANON_KEY too — JWT secret rotation invalidates it as well",
        ],
        "cost_warning": "The service_role key BYPASSES RLS. A leak = full DB read/write/delete for any attacker.",
    },
    "slack": {
        "name": "Slack",
        "patterns": [r"xox[abp]-[A-Za-z0-9-]{20,}"],
        "env_names": ["SLACK_BOT_TOKEN", "SLACK_TOKEN", "SLACK_WEBHOOK_URL"],
        "console_url": "https://api.slack.com/apps",
        "revoke_steps": [
            "1. Visit https://api.slack.com/apps and select your app",
            "2. 'OAuth & Permissions' → 'Revoke tokens' button",
            "3. Reinstall the app to mint fresh tokens",
        ],
        "cost_warning": "Slack tokens can read DMs, post as your bot, and exfil channel histories.",
    },
    "google-api": {
        "name": "Google API key",
        "patterns": [r"AIza[A-Za-z0-9_-]{30,}"],
        "env_names": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
        "console_url": "https://console.cloud.google.com/apis/credentials",
        "revoke_steps": [
            "1. Visit https://console.cloud.google.com/apis/credentials",
            "2. Click the leaked key → 'Delete'",
            "3. 'Create credentials' → 'API key' to mint replacement",
            "4. **Critical**: click 'Restrict key' → restrict by API + HTTP referrer",
        ],
        "cost_warning": "Unrestricted Google API keys (Maps, Gemini, etc.) are aggressively scraped — set restrictions immediately.",
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Detection
# ─────────────────────────────────────────────────────────────────────────────

def detect_provider(value: str) -> Optional[str]:
    """Return the provider key whose pattern matches `value`, or None."""
    for key, prov in PROVIDERS.items():
        for pat in prov["patterns"]:
            if re.fullmatch(pat, value.strip()):
                return key
    # JWT-ish: extra check for Supabase service-role vs anon
    if re.fullmatch(r"eyJ[A-Za-z0-9_-]{60,}\.eyJ[^.]+\.[A-Za-z0-9_-]+", value.strip()):
        try:
            import base64
            payload_b64 = value.strip().split(".")[1]
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", "replace"))
            if payload.get("role") == "service_role":
                return "supabase-service-role"
        except Exception:
            pass
    return None


def scan_repo(cwd: Path) -> list[dict]:
    """Walk tracked + .env files, return [{provider, value_prefix, file, line, env_name}]."""
    findings = []
    skip_dirs = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv", "venv"}
    text_exts = {".js", ".ts", ".tsx", ".jsx", ".py", ".go", ".rb", ".php", ".java",
                 ".env", ".local", ".example", ".yml", ".yaml", ".json", ".sh", ".rs"}

    for path in cwd.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix not in text_exts and not path.name.startswith(".env"):
            continue
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            continue
        for lineno, line in enumerate(content.splitlines(), 1):
            for key, prov in PROVIDERS.items():
                for pat in prov["patterns"]:
                    for m in re.finditer(pat, line):
                        val = m.group(0)
                        # Skip example/placeholder values
                        if "REPLACE_ME" in val or "your-key-here" in val.lower():
                            continue
                        findings.append({
                            "provider": key,
                            "value_prefix": val[:12] + "..." + val[-4:],
                            "value": val,
                            "file": str(path.relative_to(cwd)),
                            "line": lineno,
                        })
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Scrubbing
# ─────────────────────────────────────────────────────────────────────────────

def backup_file(path: Path, backup_dir: Path) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    rel = path.name + "." + hashlib.sha1(str(path).encode()).hexdigest()[:8] + ".bak"
    shutil.copy2(path, backup_dir / rel)


def scrub_value(cwd: Path, value: str, replacement: str, backup_dir: Path) -> int:
    """Replace `value` with `replacement` across every text file. Returns count."""
    count = 0
    skip_dirs = {"node_modules", ".git", "dist", "build", ".next", "__pycache__", ".venv"}
    text_exts = {".js", ".ts", ".tsx", ".jsx", ".py", ".go", ".rb", ".php", ".java",
                 ".env", ".local", ".example", ".yml", ".yaml", ".json", ".sh", ".rs", ".md"}
    for path in cwd.rglob("*"):
        if any(part in skip_dirs for part in path.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix not in text_exts and not path.name.startswith(".env"):
            continue
        try:
            content = path.read_text(errors="ignore")
        except Exception:
            continue
        if value in content:
            backup_file(path, backup_dir)
            new_content = content.replace(value, replacement)
            path.write_text(new_content)
            count += 1
    return count


# ─────────────────────────────────────────────────────────────────────────────
# Deploy-platform push
# ─────────────────────────────────────────────────────────────────────────────

def detect_deploy_platforms(cwd: Path) -> list[str]:
    out = []
    if (cwd / "vercel.json").exists() or (cwd / ".vercel").exists():
        out.append("vercel")
    if (cwd / "fly.toml").exists():
        out.append("fly")
    if (cwd / "railway.json").exists() or (cwd / "railway.toml").exists():
        out.append("railway")
    if (cwd / "wrangler.toml").exists() or (cwd / "wrangler.jsonc").exists():
        out.append("cloudflare")
    if (cwd / "netlify.toml").exists():
        out.append("netlify")
    return out


def push_to_platform(platform: str, env_name: str, new_value: str) -> tuple[bool, str]:
    """Push the new env var to a deployment platform via its CLI.
       Returns (success, message)."""
    cli_cmds = {
        "vercel":     ["vercel", "env", "add", env_name, "production"],
        "fly":        ["fly", "secrets", "set", f"{env_name}={new_value}"],
        "railway":    ["railway", "variables", "set", f"{env_name}={new_value}"],
        "cloudflare": ["wrangler", "secret", "put", env_name],
        "netlify":    ["netlify", "env:set", env_name, new_value],
    }
    cmd = cli_cmds.get(platform)
    if not cmd:
        return False, f"no CLI mapping for {platform}"
    if not shutil.which(cmd[0]):
        return False, f"{cmd[0]} CLI not installed — install or set env var manually"
    # Some CLIs read value from stdin
    if platform in ("vercel", "cloudflare"):
        try:
            proc = subprocess.run(cmd, input=new_value, capture_output=True, text=True, timeout=30)
            ok = proc.returncode == 0
            return ok, (proc.stdout + proc.stderr)[:600]
        except Exception as e:
            return False, str(e)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        ok = proc.returncode == 0
        return ok, (proc.stdout + proc.stderr)[:600]
    except Exception as e:
        return False, str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Interactive rotation flow
# ─────────────────────────────────────────────────────────────────────────────

def confirm(prompt: str, auto_yes: bool) -> bool:
    if auto_yes:
        print(f"  {prompt}  [auto-yes]")
        return True
    try:
        a = input(f"  {prompt} [y/N]: ").strip().lower()
        return a in ("y", "yes")
    except EOFError:
        return False


def rotate_one(cwd: Path, finding: dict, new_value: Optional[str], auto_yes: bool) -> None:
    prov = PROVIDERS[finding["provider"]]
    print()
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"Provider:       {prov['name']}")
    print(f"Leaked at:      {finding['file']}:{finding['line']}")
    print(f"Value prefix:   {finding['value_prefix']}")
    print()
    print(f"WHY THIS IS URGENT:")
    print(f"  {prov.get('cost_warning', 'Rotate this credential.')}")
    print()
    print(f"STEP 1 — Revoke the old key (do this in another tab NOW):")
    for step in prov["revoke_steps"]:
        print(f"  {step}")
    print(f"  Console: {prov.get('console_url', '(see provider dashboard)')}")
    print()

    if not new_value:
        if not auto_yes:
            print("STEP 2 — Paste the NEW value here (or press Enter to skip auto-scrub):")
            try:
                new_value = input("  new value: ").strip()
            except EOFError:
                new_value = ""
        if not new_value:
            print("  (Skipping auto-scrub — rotate manually then re-run.)")
            return

    # Sanity: new value should match the same provider pattern
    if detect_provider(new_value) != finding["provider"]:
        print(f"  ⚠️  WARNING: new value doesn't match {prov['name']} key format.")
        if not confirm("Continue anyway?", auto_yes):
            return

    backup_dir = cwd / ".agentic-security" / "rotation-backups" / time.strftime("%Y%m%d-%H%M%S")
    if not confirm(f"STEP 3 — Replace all occurrences of the leaked value across the repo (backups → {backup_dir})?", auto_yes):
        return
    count = scrub_value(cwd, finding["value"], new_value, backup_dir)
    print(f"  ✓ Replaced in {count} file(s). Backups at {backup_dir}")

    # Push to deploy platforms
    platforms = detect_deploy_platforms(cwd)
    if not platforms:
        print("  (No deployment platform detected — set env vars manually in your hosting dashboard.)")
        return
    env_names = prov.get("env_names", [])
    print(f"\nSTEP 4 — Push to deployment platform(s): {', '.join(platforms)}")
    for pf in platforms:
        for env_name in env_names:
            if not confirm(f"Push {env_name} to {pf}?", auto_yes):
                continue
            ok, msg = push_to_platform(pf, env_name, new_value)
            mark = "✓" if ok else "✗"
            print(f"  {mark} {pf}:{env_name}  {msg[:200]}")

    print()
    print(f"STEP 5 — Final audit:")
    print(f"  - Check your billing dashboard for unexpected usage in the last 24h.")
    print(f"  - Search git history for other leaks of this exact value:")
    print(f"      git log -p -S '{finding['value'][:8]}' --all")
    print(f"  - If you committed the key, the git history still has it. Either:")
    print(f"      (a) rewrite history with `git filter-repo`, or")
    print(f"      (b) accept that the key is dead and rely on revocation only.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Actively rotate a leaked credential.")
    parser.add_argument("value", nargs="?", help="The leaked key value (or just its prefix)")
    parser.add_argument("--scan", action="store_true", help="Scan the repo for ALL leaked keys")
    parser.add_argument("--provider", choices=list(PROVIDERS.keys()),
                        help="Force a specific provider (skip auto-detection)")
    parser.add_argument("--new-value", help="New replacement value (for non-interactive use)")
    parser.add_argument("--yes", action="store_true", help="Skip confirmations (CI mode)")
    parser.add_argument("--cwd", default=None, help="Project root (default: current dir)")
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve() if args.cwd else Path.cwd()

    if args.scan:
        print(f"Scanning {cwd} for leaked credentials...\n")
        findings = scan_repo(cwd)
        if not findings:
            print("✓ No leaked credentials found.")
            sys.exit(0)
        print(f"Found {len(findings)} leaked credential(s):\n")
        for i, f in enumerate(findings, 1):
            print(f"  [{i}] {PROVIDERS[f['provider']]['name']}: {f['value_prefix']}  ({f['file']}:{f['line']})")
        print()
        if not confirm("Rotate all of them now?", args.yes):
            sys.exit(0)
        for f in findings:
            rotate_one(cwd, f, args.new_value, args.yes)
        return

    if not args.value:
        parser.print_help()
        sys.exit(2)

    provider = args.provider or detect_provider(args.value)
    if not provider:
        print(f"Could not detect provider from value '{args.value[:24]}...'")
        print(f"Use --provider to force one of: {', '.join(PROVIDERS.keys())}")
        sys.exit(2)

    finding = {"provider": provider, "value": args.value,
               "value_prefix": args.value[:12] + "..." + args.value[-4:],
               "file": "(supplied via CLI)", "line": 0}
    rotate_one(cwd, finding, args.new_value, args.yes)


if __name__ == "__main__":
    main()
