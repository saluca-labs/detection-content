#!/usr/bin/env python3
"""Mutation harness for hunt/transitive_egress_audit.py. Stdlib only.

  python hunt/tests/transitive_egress_audit_mutants.py

Runs hunt/tests/test_transitive_egress_audit.py once against the tool as written (must pass), then
once per MUTANT: a copy of the tool with one guarantee deliberately broken (must fail). A suite
that still passes against a mutant is not testing that guarantee, and this script exits non-zero
if that happens. Same pattern as hunt/tests/public_scan_search_mutants.py in the laundered-vantage
pack.

Every mutation target is asserted present, exactly once, before it is applied, so a refactor that
moves the code makes this harness fail loudly instead of "catching" a mutant that was never
applied.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "transitive_egress_audit.py")
SUITE = os.path.join(HERE, "test_transitive_egress_audit.py")

MUTANTS = {
    # ---- gem ----
    ".yardopts --load no longer treated as loading code":
        ('YARD_CODE_OPTS = ("--load", "-e", "--plugin", "--query")',
         'YARD_CODE_OPTS = ("-e", "--plugin", "--query")'),
    "member names lstrip'ed, so .yardopts loses its dot inside a .gem":
        ('m.name[2:] if m.name.startswith("./") else m.name',
         'm.name.lstrip("./")'),
    "timestamp range check removed (any 10 digits is a timestamp)":
        ("    if not (TS_MIN <= ts < TS_MAX):\n        return None",
         "    if False:\n        return None"),
    "marker regex loses comment context (matches '#exfil' inside a string)":
        ('r"(?:^|\\s)#\\s*(?:malicious',
         'r"#\\s*(?:malicious'),
    "marker regex loosened to any comment starting 'hack'":
        (r"hack\s*$|", r"hack\b|"),
    "metadata markup check disabled":
        ("        if block and METADATA_MARKUP_RX.search(block.group(1)):",
         "        if False:"),
    "inner data.tar.gz truncated at the per-file cap (large gems crash)":
        ("_read_member(outer, data_member, MAX_ARCHIVE_BYTES)", "_read_member(outer, data_member)"),
    "corrupt inner archive escapes as a crash instead of cannot-tell":
        ("except (tarfile.TarError, OSError, EOFError, zlib.error) as exc:",
         "except (tarfile.TarError, OSError) as exc:"),
    "doc-build loop reported on either half alone":
        ('if "doc-build-loads-code" in got and got & {', 'if "doc-build-loads-code" in got or got & {'),
    "doc-config write check reverted to any mention of .yardopts":
        ("if DOC_CONFIG_WRITE_RX.search(text):", 'if ".yardopts" in text:'),
    "code checks applied to documentation files too":
        ("if base.endswith(CODE_SUFFIXES):", 'if base != ".yardopts":'),
    # ---- dns ----
    "high-cardinality boundary off by one (> instead of >=)":
        ("if len(subs) >= min_unique:", "if len(subs) > min_unique:"),
    "allowlist ignored":
        ('if any(q == a or q.endswith("." + a) for a in allow_l):', "if False:"),
    "multi-label public suffixes ignored (example.gov.uk groups as gov.uk)":
        ('if len(labels) > n and ".".join(labels[-n:]) in sfx:', "if False:"),
    "zero-parseable-rows guard removed (garbage log reports clean)":
        ('    if not rows:\n        raise CannotTell("%s: no parseable DNS',
         '    if False:\n        raise CannotTell("%s: no parseable DNS'),
    # ---- latency ----
    "containment threshold boundary (>= instead of >)":
        ('durs["ack_to_contain"] > max_contain_minutes * 60',
         'durs["ack_to_contain"] >= max_contain_minutes * 60'),
    "missing containment time no longer flagged":
        ('flags.append("NOT CONTAINED")', "pass"),
    "unparseable timestamp silently treated as missing":
        ('raise CannotTell("unparseable timestamp %r; cannot tell" % s)', "return None"),
    # ---- coverage ----
    "explicit exclusion no longer overrides a wildcard include":
        ('matches(e, sc["include"]) and e not in excluded_logged]', 'matches(e, sc["include"])]'),
    "empty-seen guard removed (no logs reports full coverage)":
        ('    if not seen_set:\n        raise CannotTell("no environments',
         '    if False:\n        raise CannotTell("no environments'),
}


def run_suite(module_path: str) -> tuple[bool, str]:
    env = dict(os.environ, TEA_MODULE=module_path)
    p = subprocess.run([sys.executable, "-m", "unittest", SUITE], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env)
    summary = [ln for ln in p.stderr.splitlines() if ln.startswith(("Ran ", "OK", "FAILED"))]
    return p.returncode == 0, " ".join(summary)


def main() -> int:
    src = open(TOOL, encoding="utf-8").read()
    tmp = tempfile.mkdtemp(prefix="tea-mutants-")
    bad = False
    try:
        ok, summary = run_suite(TOOL)
        print("real transitive_egress_audit.py: %s  (%s)" % ("PASS" if ok else "FAIL", summary))
        bad = not ok
        for i, (name, (old, new)) in enumerate(MUTANTS.items()):
            n = src.count(old)
            if n != 1:
                print("mutant: %s -> TARGET FOUND %d TIMES (want 1); the mutation would test nothing" % (name, n))
                bad = True
                continue
            path = os.path.join(tmp, "m%02d_transitive_egress_audit.py" % i)
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(src.replace(old, new, 1))
            passed, summary = run_suite(path)
            print("mutant: %s -> %s" % (name, "NOT CAUGHT: the suite does not test this" if passed
                                          else "caught (%s)" % summary))
            bad = bad or passed
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%s" % ("MUTATION HARNESS FAILED" if bad else "all %d mutants caught" % len(MUTANTS)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
