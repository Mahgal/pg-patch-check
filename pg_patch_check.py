#!/usr/bin/env python3
"""pg-patch-check — is your PostgreSQL patched against the big 2026 CVEs?

Checks a PostgreSQL version string against the fixed releases for:

* CVE-2026-6471 ("PostGREShell", CVSS 7.2) — a REPLICATION role could load
  an arbitrary library via logical decoding and get code execution as the
  OS user running the server. Present since 9.4 (2014), fixed 2026-08-13 in
  18.6 / 17.11 / 16.15 / 15.19 / 14.24.
* The 2026-11-12 batch (52 CVEs, 32 rated 8.8) — fixed in
  18.7 / 17.12 / 16.16 / 15.20 / 14.25. PostgreSQL 14 went end-of-life
  the same day (14.25 is its final release).

Usage:
    python pg_patch_check.py --version-string "PostgreSQL 16.14 on ..."
    python pg_patch_check.py --psql            # runs: psql -tAc 'SELECT version()'
    python pg_patch_check.py --version-string 17.12 --format json

Exit code: 0 = patched against both batches (warnings may still print),
           1 = vulnerable to at least one batch, or version unsupported/EOL.
No database connection is made unless --psql is given.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys

# (major, minor) fixed floors per advisory batch.
FLOORS = {
    "CVE-2026-6471 (PostGREShell)": {
        18: (18, 6), 17: (17, 11), 16: (16, 15), 15: (15, 19), 14: (14, 24),
    },
    "2026-11-12 batch (52 CVEs)": {
        18: (18, 7), 17: (17, 12), 16: (16, 16), 15: (15, 20), 14: (14, 25),
    },
}
EOL_MAJOR = 14          # 14.25 (2026-11-12) is the final 14.x release.
MIN_SUPPORTED_MAJOR = 14
VERSION_RE = re.compile(r"PostgreSQL\s+(\d+)\.(\d+)|^(\d+)\.(\d+)")


def parse_version(text: str) -> tuple[int, int]:
    """Parse 'PostgreSQL 16.14 ...' or a bare '16.14' into (16, 14)."""
    match = VERSION_RE.search(text.strip())
    if not match:
        raise ValueError(f"could not parse a PostgreSQL version from {text!r}")
    major = match.group(1) or match.group(3)
    minor = match.group(2) or match.group(4)
    return int(major), int(minor)


def check(version: tuple[int, int]) -> dict:
    """Return findings for one (major, minor) version."""
    major, minor = version
    findings = []
    if major < MIN_SUPPORTED_MAJOR:
        findings.append({
            "level": "critical",
            "id": "unsupported",
            "message": f"PostgreSQL {major}.x is out of support; upgrade to a "
                       f"supported major (14+).",
        })
        return {"version": f"{major}.{minor}", "ok": False, "findings": findings}
    for batch, floors in FLOORS.items():
        floor = floors.get(major)
        if floor is None:
            continue
        if (major, minor) < floor:
            findings.append({
                "level": "critical",
                "id": batch,
                "message": f"Vulnerable to {batch}: {major}.{minor} < "
                           f"fixed {floor[0]}.{floor[1]} — upgrade.",
            })
    if major == EOL_MAJOR:
        findings.append({
            "level": "warning",
            "id": "eol",
            "message": "PostgreSQL 14 reached end-of-life on 2026-11-12; "
                       "14.25 is its final release. Plan a move to 15+.",
        })
    critical = [f for f in findings if f["level"] == "critical"]
    return {"version": f"{major}.{minor}", "ok": not critical, "findings": findings}


def read_version_from_psql() -> str:
    if shutil.which("psql") is None:
        raise RuntimeError("psql not found on PATH; pass --version-string instead")
    proc = subprocess.run(
        ["psql", "-tAc", "SELECT version()"],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed: {proc.stderr.strip()}")
    return proc.stdout.strip()


def render_text(result: dict) -> str:
    lines = [f"PostgreSQL {result['version']}:"]
    if not result["findings"]:
        lines.append("  OK — patched against CVE-2026-6471 and the 2026-11-12 batch.")
    for f in result["findings"]:
        lines.append(f"  [{f['level'].upper()}] {f['message']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--version-string", help='e.g. "PostgreSQL 16.14 ..." or "16.14"')
    group.add_argument("--psql", action="store_true",
                       help="read the version from a live server via psql")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)

    try:
        text = read_version_from_psql() if args.psql else args.version_string
        version = parse_version(text)
    except (ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = check(version)
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(render_text(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
