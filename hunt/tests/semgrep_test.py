#!/usr/bin/env python3
"""Run a pack's Semgrep rules in the real engine against annotated fixtures, and require an
EXACT match between what fired and what was expected.

Every fixture line that should match carries `EXPECT:<rule-id>` in a comment. The test fails on
a missed expectation (the rule is too narrow) AND on any unexpected match (the rule is too broad,
for example firing on a public-key or padded operation in the negative cases). A green result
therefore means both halves were exercised, not only that the rules parsed.

Needs Docker. Uses the official semgrep/semgrep image, so nothing is installed on the host.

  python hunt/tests/semgrep_test.py
  python hunt/tests/semgrep_test.py --rules campaigns/2026-09-rsa-raw-oracle/detections/semgrep/raw-rsa.yml

Defensive tooling. Reads files, runs a linter, writes nothing.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_RULES = "campaigns/2026-09-rsa-raw-oracle/detections/semgrep/raw-rsa.yml"
FIXTURES = "hunt/tests/fixtures/semgrep"
IMAGE = "semgrep/semgrep:1.177.0"
EXPECT = re.compile(r"EXPECT:([a-z0-9\-]+)")


def expected() -> set[tuple[str, int, str]]:
    out = set()
    base = os.path.join(ROOT, FIXTURES)
    for name in sorted(os.listdir(base)):
        with open(os.path.join(base, name), encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                for rid in EXPECT.findall(line):
                    out.add((name, i, rid))
    return out


def actual(rules: str) -> set[tuple[str, int, str]]:
    # MSYS (Git Bash) rewrites /src style arguments into Windows paths; stop it for this call.
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    # Semgrep's built-in ignore list skips any path containing tests/ or fixtures/, which would
    # scan ZERO files and report success. Mount the fixtures and the rules at neutral paths so
    # nothing is silently excluded, and check the scanned-file count below as well.
    fixtures = os.path.join(ROOT, FIXTURES)
    rules_abs = os.path.join(ROOT, rules)
    cmd = ["docker", "run", "--rm",
           "-v", "%s:/scan:ro" % fixtures,
           "-v", "%s:/rules/rules.yml:ro" % rules_abs,
           "-w", "/scan", IMAGE,
           "semgrep", "scan", "--config", "/rules/rules.yml", "--json", "--metrics=off",
           "--disable-version-check", "--no-git-ignore", "."]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    if proc.returncode not in (0, 1):
        sys.stderr.write(proc.stderr[-4000:])
        raise SystemExit("semgrep failed to run (exit %d)" % proc.returncode)
    data = json.loads(proc.stdout)
    if data.get("errors"):
        for e in data["errors"]:
            sys.stderr.write("semgrep error: %s\n" % (e.get("message") or e))
        raise SystemExit("semgrep reported rule or parse errors; a rule that does not load "
                         "cannot be judged by its match count")
    scanned = data.get("paths", {}).get("scanned", [])
    fixture_count = len(os.listdir(fixtures))
    if len(scanned) != fixture_count:
        raise SystemExit("semgrep scanned %d of %d fixture files; refusing to judge a partial scan"
                         % (len(scanned), fixture_count))
    out = set()
    for r in data["results"]:
        rid = r["check_id"].split(".")[-1]
        out.add((os.path.basename(r["path"]), r["start"]["line"], rid))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=DEFAULT_RULES)
    args = ap.parse_args()

    want = expected()
    if not want:
        raise SystemExit("no EXPECT annotations found; refusing to report a pass on nothing")
    got = actual(args.rules)

    missed = sorted(want - got)
    extra = sorted(got - want)
    for f, ln, rid in missed:
        print("MISSED      %s:%d  %s" % (f, ln, rid))
    for f, ln, rid in extra:
        print("UNEXPECTED  %s:%d  %s" % (f, ln, rid))

    rules_hit = {rid for _, _, rid in got & want}
    print("expected %d, matched %d, missed %d, unexpected %d, rules exercised %d"
          % (len(want), len(got & want), len(missed), len(extra), len(rules_hit)))
    return 1 if (missed or extra) else 0


if __name__ == "__main__":
    sys.exit(main())
