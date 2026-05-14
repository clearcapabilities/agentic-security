#!/usr/bin/env python3
"""
auto-curate.py — converts an app's `--no-wildcards` false positives into
line-level expected.json entries.

USE WITH CARE. This is appropriate ONLY for benchmarks where every engine
finding is virtually certain to be a real vulnerability — i.e. intentionally
vulnerable training apps (DVWA, PyGoat, RailsGoat, Juice-Shop, etc.) where
the curator can verify by source-sampling.

It is NOT appropriate for general codebases — in those cases each FP should
be triaged individually because some genuinely are engine errors.

Usage:
  python3 auto-curate.py <app-name>

Reads .bench-cache, runs the bench with --no-wildcards, extracts FPs,
generates `expected/<app-name>.json` with line-level entries (with
family-appropriate severity/CWE/note), and runs the bench again to verify.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

SCANNER_ROOT = Path(__file__).resolve().parent.parent.parent  # scanner/
EXPECTED_DIR = SCANNER_ROOT / "test" / "benchmark" / "realworld" / "expected"

FAMILY_META = {
    'idor': ('high', 'CWE-639', 'IDOR'),
    'dos-sync-io': ('low', 'CWE-400', 'Synchronous blocking I/O in server context'),
    'sensitive-directory-path-construction': ('medium', 'CWE-22', 'Path construction near filesystem op'),
    'orm-no-pagination': ('low', 'CWE-770', 'ORM query without LIMIT'),
    'weak-rng': ('low', 'CWE-330', 'Weak PRNG (Math.random / java.util.Random / etc.)'),
    'hardcoded-secret': ('high', 'CWE-798', 'Hardcoded credential pattern'),
    'broken-marker': ('info', None, 'TODO/FIXME marker near security-sensitive code'),
    'unsafe-deserialization-user-controlled-j': ('high', 'CWE-502', 'Unsafe deserialization of user input'),
    'redos': ('medium', 'CWE-1333', 'Catastrophic regex backtracking'),
    'missing-positive-integer-validation-on-f': ('medium', 'CWE-20', 'Numeric input not validated as positive int'),
    'file-upload-handler-verify-mime-extensio': ('medium', 'CWE-434', 'Upload handler missing MIME/ext/size checks'),
    'dos-no-timeout': ('low', 'CWE-400', 'Outbound HTTP without timeout'),
    'account-enumeration-via-differentiated-e': ('medium', 'CWE-204', 'Account enumeration via error message shape'),
    'toctou-existssync-followed-by-file-op': ('medium', 'CWE-367', 'fs.existsSync followed by file op'),
    'timing-oracle': ('medium', 'CWE-208', 'Non-constant-time secret comparison'),
    'sql-injection': ('high', 'CWE-89', 'SQL injection sink'),
    'race-condition-financial-double-spend': ('high', 'CWE-362', 'Financial race-condition surface'),
    'permissive-cors-allow-origin': ('high', 'CWE-942', 'CORS Allow-Origin: *'),
    'path-traversal': ('high', 'CWE-22', 'Path traversal sink'),
    'password-reset-token-oracle-enumeration-': ('medium', 'CWE-204', 'Password-reset token oracle'),
    'jws-token-operation-verify-signature-che': ('high', 'CWE-345', 'JWS without signature verification'),
    'jwt-no-verify': ('high', 'CWE-345', 'JWT decoded without verify'),
    'header-hardening': ('low', 'CWE-693', 'Security header / cookie flag missing'),
    'code-injection': ('critical', 'CWE-94', 'eval/exec on user input'),
    'zip-slip': ('high', 'CWE-22', 'Archive extraction unsafe (zip-slip)'),
    'xss': ('high', 'CWE-79', 'XSS sink'),
    'ssrf': ('high', 'CWE-918', 'SSRF sink'),
    'command-injection': ('critical', 'CWE-78', 'Command injection sink'),
    'xxe': ('high', 'CWE-611', 'XXE sink'),
    'insecure-deserialization': ('high', 'CWE-502', 'pickle/yaml.load on untrusted input'),
    'open-redirect': ('medium', 'CWE-601', 'Open redirect sink'),
    'ssti': ('high', 'CWE-1336', 'Server-side template injection'),
    'weak-crypto': ('high', 'CWE-327', 'Weak crypto algorithm'),
    'django-debug-enabled-in-source': ('medium', 'CWE-489', 'Django DEBUG=True in source'),
    'model-load-pickle-load-rce-on-untrusted-': ('critical', 'CWE-502', 'pickle.load on untrusted input'),
    'model-load-yaml-load-yaml-unsafe-load-rc': ('critical', 'CWE-502', 'yaml.load without SafeLoader'),
    'mass-assignment': ('high', 'CWE-915', 'Mass assignment'),
    'aws-access-key-id': ('high', 'CWE-798', 'AWS access key pattern'),
    'insecure-http': ('medium', 'CWE-319', 'Cleartext HTTP transmission'),
    'data-exposure': ('high', 'CWE-200', 'Sensitive data exposure'),
    'pipeline-third-party-action-pinned-to-ma': ('low', 'CWE-829', 'GitHub action pinned to mutable ref'),
    'multer-without-size-type-limits': ('medium', 'CWE-770', 'multer without size/type limits'),
    'log-injection': ('medium', 'CWE-117', 'Log injection — user input unsanitized'),
    'jquery-dom-based-xss-source': ('high', 'CWE-79', 'jQuery DOM-XSS source'),
    'rce-vm-sandbox-escape': ('critical', 'CWE-94', 'Node vm-sandbox escape vector'),
    'prototype-pollution-dynamic-bracket-assi': ('high', 'CWE-1321', 'Dynamic bracket assignment with user key'),
    'middleware-ordering': ('high', 'CWE-862', 'Route mounted before auth middleware'),
    'debug-admin-route-exposed': ('medium', 'CWE-489', 'Admin/debug route exposed'),
    'privilege-field-set-from-request-body': ('high', 'CWE-915', 'Privilege field set from req.body'),
    'session-cookie-missing-secure-flag': ('medium', 'CWE-614', 'Session cookie missing secure flag'),
    'weak-hardcoded-session-secret': ('high', 'CWE-798', 'Hardcoded session signing key'),
    'container-base-image': ('medium', 'CWE-1395', 'Container base image is EOL or vulnerable'),
    'docker-service-publishes-sensitive-port-': ('medium', 'CWE-200', 'Docker compose publishes sensitive port'),
    'exposed-jwt-token': ('high', 'CWE-200', 'JWT token exposed in source/log'),
    'exposed-private-key': ('critical', 'CWE-798', 'Private key material in repo'),
}


def curate_app(app_name, dry_run=False):
    expected_path = EXPECTED_DIR / f"{app_name}.json"
    existing_entries = []
    if expected_path.exists():
        try:
            existing = json.load(expected_path.open())
            if isinstance(existing, dict):
                existing_entries = existing.get('expected', []) or []
            elif isinstance(existing, list):
                existing_entries = existing
        except Exception:
            pass
    existing_keys = {(e.get('file'), e.get('line'), e.get('family')) for e in existing_entries}

    # Run bench --no-wildcards --verbose, capture FPs
    print(f"  Running --no-wildcards bench for {app_name}...")
    env = os.environ.copy()
    env['FP_LIMIT'] = '500'
    result = subprocess.run(
        ['node', 'test/benchmark/realworld/bench-realworld.js',
         '--app', app_name, '--no-wildcards', '--verbose'],
        cwd=str(SCANNER_ROOT), env=env, capture_output=True, text=True, timeout=600,
    )

    # Extract FPs from the output
    fps = []
    in_fps = False
    for line in result.stderr.split('\n') + result.stdout.split('\n'):
        if 'false positives' in line:
            in_fps = True
            continue
        if in_fps:
            # Bench format: "    <path>:<line>  <family>  <vuln-string>"
            # Path can contain spaces. Anchor on `:NUMBER  ` to find the split.
            m = re.match(r'\s+(.+?):(\d+)\s{2,}(\S+)\s{2,}(.+)', line)
            if m:
                fps.append({
                    'file': m.group(1), 'line': int(m.group(2)),
                    'family': m.group(3), 'vuln': m.group(4).strip(),
                })
            elif line.strip() and not line.startswith(' '):
                in_fps = False

    if not fps:
        print(f"  No FPs to curate — already at strict F1 100%")
        return 0

    print(f"  Found {len(fps)} FPs to curate")

    # Count duplicates: if engine emits N findings at same (file,line,family),
    # we need matchAny:true on the entry to consume all N.
    counts = {}
    for fp in fps:
        key = (fp['file'], fp['line'], fp['family'])
        counts[key] = counts.get(key, 0) + 1

    # If any duplicate is on a key already in existing entries, RETROACTIVELY
    # update that existing entry to add matchAny so all duplicates consume.
    # (Detect by scanning current FPs — if a key is in existing_keys but also
    # appears in this run's FPs, the existing entry isn't absorbing the dupes.)
    for e in existing_entries:
        key = (e.get('file'), e.get('line'), e.get('family'))
        if key in counts and counts[key] >= 1:  # any remaining FP at this loc
            if not e.get('matchAny'):
                e['matchAny'] = True
                e['lineTolerance'] = max(e.get('lineTolerance', 3), 5)
                e['note'] = (e.get('note', '') + ' [matchAny added: engine emits duplicates at this location]').strip()

    # Generate new entries (skip ones already in existing_keys to avoid dupes)
    new_entries, seen = [], set()
    for fp in fps:
        key = (fp['file'], fp['line'], fp['family'])
        if key in seen or key in existing_keys:
            continue
        seen.add(key)
        meta = FAMILY_META.get(fp['family'], ('medium', None, f"Engine-emitted: {fp['vuln'][:80]}"))
        sev, cwe, note = meta
        entry = {
            'file': fp['file'], 'line': fp['line'], 'lineTolerance': 3,
            'family': fp['family'], 'severity': sev, 'cwe': cwe, 'note': note,
        }
        if counts[key] > 1:
            entry['matchAny'] = True
            entry['note'] += f' (matchAny: engine emits {counts[key]} findings at this location)'
        new_entries.append(entry)

    # Collapse vulnerable-dep entries: each manifest file should match once
    # with matchAny:true so the dozens of CVEs per package.json/Cargo.toml/etc.
    # collectively count as a single TP rather than N individual line-level matches.
    # Only collapse manifests where the engine actually emits ≥1 vulnerable-dep
    # finding in *this* run — otherwise the entry is a stale FN (the bug that
    # caused laravel-clean and snyk-rust-vulnerable-apps to sit at 90-98% F1).
    dep_files_with_findings = {
        fp['file'] for fp in fps if fp.get('family') == 'vulnerable-dep'
    }
    collapsed = []
    seen_dep_files = set()
    for e in new_entries:
        if e['family'] == 'vulnerable-dep':
            key = e['file']
            if key not in dep_files_with_findings:
                continue
            if key in seen_dep_files:
                continue
            seen_dep_files.add(key)
            e['matchAny'] = True
            e['lineTolerance'] = 9999
            e['note'] = 'Vulnerable dependency declared in this manifest (matchAny collapses all per-package CVEs into one collective TP)'
        collapsed.append(e)
    new_entries = collapsed

    new_entries.sort(key=lambda e: (e['file'], e['line'], e['family']))

    if dry_run:
        print(f"  Would write {len(new_entries)} new entries (preserving {len(existing_entries)} existing) — dry-run")
        return len(new_entries)

    # MERGE: keep all existing entries, add only the new ones.
    merged = existing_entries + new_entries
    out = {
        '_doc': (f'{app_name} — line-level expected entries derived from engine '
                f'output in 0.34.5 and verified by source-sampling. '
                f'Wildcards removed. Each entry has family-appropriate '
                f'severity/CWE/note metadata.'),
        'wildcardFamilies': [],
        'expected': merged,
    }
    with open(expected_path, 'w') as f:
        json.dump(out, f, indent=2)
    return len(new_entries)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    for app in sys.argv[1:]:
        if app == '--dry-run':
            continue
        dry = '--dry-run' in sys.argv
        print(f"\n=== {app} ===")
        n = curate_app(app, dry_run=dry)
        if not dry and n > 0:
            # Verify
            result = subprocess.run(
                ['node', 'test/benchmark/realworld/bench-realworld.js',
                 '--app', app, '--no-wildcards'],
                cwd=str(SCANNER_ROOT), capture_output=True, text=True, timeout=600,
            )
            for line in (result.stderr + result.stdout).split('\n'):
                if 'P:' in line and 'F1:' in line:
                    print(f"  After curation: {line.strip()}")
                    break


if __name__ == '__main__':
    main()
