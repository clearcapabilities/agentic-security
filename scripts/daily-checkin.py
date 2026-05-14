#!/usr/bin/env python3
"""
daily-checkin.py — run a scan, compute the delta since the last check-in,
and post a digest to Slack / Discord / a generic webhook.

Designed to be invoked from cron / GitHub Actions / a scheduled task.

Usage:
  python3 scripts/daily-checkin.py                       # local stdout digest
  python3 scripts/daily-checkin.py --slack <webhook>     # post to Slack
  python3 scripts/daily-checkin.py --discord <webhook>   # post to Discord
  python3 scripts/daily-checkin.py --webhook <url>       # generic POST JSON
  python3 scripts/daily-checkin.py --setup               # interactive setup
  python3 scripts/daily-checkin.py --crontab             # print crontab line

Config is read from .agentic-security/daily-checkin.json:
  {
    "slack_webhook":   "https://hooks.slack.com/...",
    "discord_webhook": "https://discord.com/api/webhooks/...",
    "generic_webhook": "https://your-server/security-hook",
    "min_severity":    "high",
    "include_kev":     true,
    "include_chains":  true
  }
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path


def load_cfg(cwd: Path) -> dict:
    p = cwd / ".agentic-security" / "daily-checkin.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def save_cfg(cwd: Path, cfg: dict) -> None:
    p = cwd / ".agentic-security" / "daily-checkin.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2))


def load_scan(cwd: Path) -> dict | None:
    p = cwd / ".agentic-security" / "last-scan.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def load_last_digest(cwd: Path) -> dict:
    p = cwd / ".agentic-security" / "daily-checkin-last.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def save_last_digest(cwd: Path, digest: dict) -> None:
    p = cwd / ".agentic-security" / "daily-checkin-last.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(digest, indent=2))


def severity_rank(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get((s or "info").lower(), 4)


def fingerprint(f: dict) -> str:
    return f"{f.get('id') or ''}:{f.get('file') or ''}:{f.get('line') or ''}"


def build_digest(cwd: Path, cfg: dict, scan: dict) -> dict:
    findings = []
    for key in ("findings", "logicVulns", "supplyChain"):
        findings.extend(scan.get(key, []))
    min_rank = severity_rank(cfg.get("min_severity", "high"))
    findings = [f for f in findings if severity_rank(f.get("severity")) <= min_rank]

    # Counts
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[(f.get("severity") or "info").lower()] = counts.get((f.get("severity") or "info").lower(), 0) + 1

    # Delta vs last digest
    prev = load_last_digest(cwd)
    prev_fps = set(prev.get("fingerprints", []))
    cur_fps = {fingerprint(f) for f in findings}
    new_findings = [f for f in findings if fingerprint(f) not in prev_fps]
    resolved_count = len(prev_fps - cur_fps)

    # Pull KEV exposure if available
    kev = scan.get("kev", []) or scan.get("kevExposure", [])

    return {
        "ts": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "total": len(findings),
        "counts": counts,
        "new": new_findings,
        "resolved_count": resolved_count,
        "kev_count": len(kev),
        "fingerprints": list(cur_fps),
    }


def render_text(digest: dict, project_name: str) -> str:
    lines = []
    lines.append(f"🛡  *{project_name}* — daily security digest  ({digest['ts']})")
    lines.append("")
    c = digest["counts"]
    lines.append(f"  Open:   {c.get('critical', 0)} critical · {c.get('high', 0)} high · {c.get('medium', 0)} medium")
    if digest["new"]:
        lines.append(f"  ⚠️  {len(digest['new'])} new finding(s) since last digest:")
        for f in digest["new"][:5]:
            sev = (f.get("severity") or "?").upper()
            lines.append(f"     • [{sev}] {f.get('vuln', '?')} — {f.get('file', '?')}:{f.get('line', '?')}")
        if len(digest["new"]) > 5:
            lines.append(f"     ... and {len(digest['new']) - 5} more")
    else:
        lines.append(f"  ✓ No new findings since last digest")
    if digest["resolved_count"]:
        lines.append(f"  ✓ {digest['resolved_count']} finding(s) resolved 🎉")
    if digest["kev_count"]:
        lines.append(f"  🚨 KEV (known-exploited) packages in tree: {digest['kev_count']}")
    lines.append("")
    lines.append("  Run /scan --all for full details, or /find-and-fix-everything to auto-remediate.")
    return "\n".join(lines)


def render_slack_blocks(digest: dict, project_name: str) -> dict:
    """Slack Block Kit formatted message."""
    c = digest["counts"]
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🛡  {project_name} — daily security digest"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": digest["ts"]}]},
        {"type": "section", "text": {"type": "mrkdwn",
            "text": f"*Open*  ·  {c.get('critical', 0)} critical  ·  {c.get('high', 0)} high  ·  {c.get('medium', 0)} medium"}},
    ]
    if digest["new"]:
        lines = [f"⚠️  *{len(digest['new'])} new finding(s)* since last digest:"]
        for f in digest["new"][:5]:
            sev = (f.get("severity") or "?").upper()
            lines.append(f"  • [{sev}] {f.get('vuln', '?')} — `{f.get('file', '?')}:{f.get('line', '?')}`")
        if len(digest["new"]) > 5:
            lines.append(f"  ... and {len(digest['new']) - 5} more")
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}})
    if digest["resolved_count"]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"✓ *{digest['resolved_count']} resolved* since last digest 🎉"}})
    if digest["kev_count"]:
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"🚨 *{digest['kev_count']} KEV packages* in your dependency tree (known-exploited CVEs)"}})
    return {"blocks": blocks, "text": f"agentic-security daily digest for {project_name}"}


def render_discord(digest: dict, project_name: str) -> dict:
    c = digest["counts"]
    embed = {
        "title": f"🛡  {project_name} — daily security digest",
        "description": f"{digest['ts']}",
        "color": 0xE74C3C if (c.get("critical", 0) + c.get("high", 0)) > 0 else 0x2ECC71,
        "fields": [
            {"name": "Open", "value": f"{c.get('critical', 0)} critical · {c.get('high', 0)} high · {c.get('medium', 0)} medium", "inline": False},
        ],
    }
    if digest["new"]:
        new_text = "\n".join(
            f"• [{(f.get('severity') or '?').upper()}] {f.get('vuln', '?')} — `{f.get('file', '?')}:{f.get('line', '?')}`"
            for f in digest["new"][:5])
        if len(digest["new"]) > 5:
            new_text += f"\n... and {len(digest['new']) - 5} more"
        embed["fields"].append({"name": f"⚠️ {len(digest['new'])} new finding(s)", "value": new_text, "inline": False})
    if digest["resolved_count"]:
        embed["fields"].append({"name": "✓ Resolved", "value": str(digest["resolved_count"]) + " 🎉", "inline": True})
    if digest["kev_count"]:
        embed["fields"].append({"name": "🚨 KEV", "value": f"{digest['kev_count']} known-exploited packages", "inline": True})
    return {"embeds": [embed]}


def post(url: str, payload: dict) -> tuple[bool, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status < 300, str(resp.status)
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"
    except Exception as e:
        return False, str(e)


def setup_interactive(cwd: Path) -> None:
    cfg = load_cfg(cwd)
    print("Daily check-in setup — leave any field blank to keep its current value.\n")
    for key, label in [
        ("slack_webhook", "Slack incoming-webhook URL"),
        ("discord_webhook", "Discord webhook URL"),
        ("generic_webhook", "Generic JSON webhook URL"),
        ("min_severity", "Minimum severity (critical/high/medium/low) [default: high]"),
    ]:
        cur = cfg.get(key) or ""
        prompt = f"  {label}"
        if cur:
            prompt += f" [current: {cur[:30]}...]"
        prompt += ": "
        try:
            ans = input(prompt).strip()
        except EOFError:
            ans = ""
        if ans:
            cfg[key] = ans
        elif key == "min_severity" and not cur:
            cfg[key] = "high"
    save_cfg(cwd, cfg)
    print(f"\n✓ Saved to {cwd / '.agentic-security' / 'daily-checkin.json'}")
    print(f"\nTo schedule a daily run at 9am, add to your crontab:")
    print(f"  0 9 * * *  cd {cwd} && python3 scripts/daily-checkin.py")
    print(f"\nOr in GitHub Actions, add a daily workflow that runs this script.")


def print_crontab(cwd: Path) -> None:
    print(f"# agentic-security daily check-in")
    print(f"0 9 * * *  cd {cwd} && python3 scripts/daily-checkin.py >> .agentic-security/daily-checkin.log 2>&1")


def main() -> None:
    parser = argparse.ArgumentParser(description="Daily security digest posted to your messaging tool of choice.")
    parser.add_argument("--cwd", default=None)
    parser.add_argument("--slack", default=None, help="Override Slack webhook URL")
    parser.add_argument("--discord", default=None, help="Override Discord webhook URL")
    parser.add_argument("--webhook", default=None, help="Override generic JSON webhook URL")
    parser.add_argument("--setup", action="store_true", help="Interactive setup")
    parser.add_argument("--crontab", action="store_true", help="Print suggested crontab line")
    parser.add_argument("--rescan", action="store_true",
                        help="Run a fresh scan before building the digest (default: use last-scan.json)")
    parser.add_argument("--project-name", default=None)
    args = parser.parse_args()

    cwd = Path(args.cwd).resolve() if args.cwd else Path.cwd()

    if args.setup:
        setup_interactive(cwd)
        return
    if args.crontab:
        print_crontab(cwd)
        return

    cfg = load_cfg(cwd)
    project_name = args.project_name or cwd.name

    # Optional rescan
    if args.rescan:
        bundle = cwd / "scanner" / "dist" / "agentic-security.mjs"
        if not bundle.exists():
            # Try the plugin location
            bundle = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", str(cwd))) / "scanner" / "dist" / "agentic-security.mjs"
        if bundle.exists():
            subprocess.run(["node", str(bundle), "scan", str(cwd), "--all", "--no-network"], cwd=str(cwd), timeout=120)

    scan = load_scan(cwd)
    if not scan:
        print("ERROR: No .agentic-security/last-scan.json — run /scan --all first or pass --rescan.", file=sys.stderr)
        sys.exit(1)

    digest = build_digest(cwd, cfg, scan)
    text = render_text(digest, project_name)
    print(text)

    posted_anywhere = False
    slack = args.slack or cfg.get("slack_webhook")
    if slack:
        ok, msg = post(slack, render_slack_blocks(digest, project_name))
        print(f"\n  Slack:   {'✓ posted' if ok else '✗ ' + msg}")
        posted_anywhere = posted_anywhere or ok
    discord = args.discord or cfg.get("discord_webhook")
    if discord:
        ok, msg = post(discord, render_discord(digest, project_name))
        print(f"  Discord: {'✓ posted' if ok else '✗ ' + msg}")
        posted_anywhere = posted_anywhere or ok
    generic = args.webhook or cfg.get("generic_webhook")
    if generic:
        ok, msg = post(generic, {"project": project_name, "digest": digest})
        print(f"  Webhook: {'✓ posted' if ok else '✗ ' + msg}")
        posted_anywhere = posted_anywhere or ok

    if not (slack or discord or generic):
        print("\n  (No webhook configured — run with --setup to configure Slack/Discord/webhook destinations.)")

    save_last_digest(cwd, digest)


if __name__ == "__main__":
    main()
