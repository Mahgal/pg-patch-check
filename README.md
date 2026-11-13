# pg-patch-check

Is your PostgreSQL patched against the big 2026 CVEs? One command tells you.

## The problem

Two heavy PostgreSQL security batches landed in 2026:

- **CVE-2026-6471 ("PostGREShell", CVSS 7.2)** — a role with the
  `REPLICATION` attribute could load an arbitrary library through logical
  decoding and execute code as the OS user running the server. The flaw sat
  in every release since 9.4 (2014) and was fixed on 2026-08-13 in
  **18.6 / 17.11 / 16.15 / 15.19 / 14.24**.
- **The 2026-11-12 batch (52 CVEs, 32 rated 8.8)** — fixed in
  **18.7 / 17.12 / 16.16 / 15.20 / 14.25**. PostgreSQL 14 went
  end-of-life the same day; 14.25 is its final release.

## Quick start

```bash
# From a version string (e.g. from SELECT version()):
python pg_patch_check.py --version-string "PostgreSQL 16.14 on x86_64-pc-linux-gnu"

# Or straight from a live server (needs psql on PATH):
python pg_patch_check.py --psql
```

## Example output

```
$ python pg_patch_check.py --version-string "PostgreSQL 16.14 on Debian"
PostgreSQL 16.14:
  [CRITICAL] Vulnerable to CVE-2026-6471 (PostGREShell): 16.14 < fixed 16.15 — upgrade.
  [CRITICAL] Vulnerable to 2026-11-12 batch (52 CVEs): 16.14 < fixed 16.16 — upgrade.

$ python pg_patch_check.py --version-string 17.12
PostgreSQL 17.12:
  OK — patched against CVE-2026-6471 and the 2026-11-12 batch.

$ python pg_patch_check.py --version-string 14.25
PostgreSQL 14.25:
  [WARNING] PostgreSQL 14 reached end-of-life on 2026-11-12; 14.25 is its
  final release. Plan a move to 15+.
```

Exit code is `0` when patched against both batches, `1` when vulnerable or
unsupported, `2` on bad input. `--format json` gives machine-readable output
for CI.

## Notes

- No database connection is made unless you pass `--psql`.
- Version floors are taken from the PostgreSQL security announcements and
  the Cyera PostGREShell write-up; re-check them against the official
  advisories before a production upgrade decision.
