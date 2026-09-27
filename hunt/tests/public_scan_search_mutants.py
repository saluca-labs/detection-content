#!/usr/bin/env python3
"""Mutation harness for hunt/public_scan_search.py. Stdlib only.

  python hunt/tests/public_scan_search_mutants.py

Runs hunt/tests/test_public_scan_search.py once against the tool as written (must pass), then once
per MUTANT: a copy of the tool with one guarantee deliberately broken (must fail). A suite that
still passes against a mutant is not testing that guarantee, and this script exits non-zero if that
happens. Pattern taken from tkhr-detection-eng/test_append.py.

Every mutation target is asserted present before it is applied, so a refactor that moves the code
makes this harness fail loudly instead of "catching" a mutant that was never applied.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "public_scan_search.py")
SUITE = os.path.join(HERE, "test_public_scan_search.py")

MUTANTS = {
    "probe regex broken: SQL injection family never matches":
        (r'''"sqli": re.compile(r"\bunion\s+(?:all\s+)?select\b|'\s*or\s+1\s*=\s*1|\bor\s+1\s*=\s*1\s*--"),''',
         r'''"sqli": re.compile(r"(?!x)x"),'''),
    "probe regex broken: traversal family narrowed to etc/shadow":
        (r'''"traversal": re.compile(r"etc/passwd|(?:\.\./){2,}|(?:\.\.\\){2,}"),''',
         r'''"traversal": re.compile(r"etc/shadow"),'''),
    "probe regex broadened: html-injection matches any '<'":
        (r'''"html-injection": re.compile(r"<\s*(?:img|iframe|svg|object|embed)\b"),''',
         r'''"html-injection": re.compile(r"<|select|passwd"),'''),
    "classifier ignores the fragment":
        ('haystack = _decode(query_raw) + "\\n" + _decode(frag_raw)',
         'haystack = _decode(query_raw)'),
    "escalation window ignored (any later probe counts)":
        ("                if 0 <= dt <= window:\n                    f = out.setdefault(key(e), {",
         "                if 0 <= dt:\n                    f = out.setdefault(key(e), {"),
    # An earlier mutant here replaced `0 <= dt` with `abs(dt)`. It was EQUIVALENT and survived:
    # the loop only compares a probe with refusals already seen in time order, so ordering is held
    # by the sort, not by the comparison. The guarantee worth testing is the sort itself, because
    # merged logs from several front ends are not in time order.
    "escalation reads the file in line order, not time order (merged logs)":
        ("    for e in sorted(events, key=lambda x: (x.ts, x.line)):\n        c = classify_url(e.url)",
         "    for e in events:\n        c = classify_url(e.url)"),
    "escalation does not key on the source":
        ('return (e.ip, e.host, e.path) if scope == "path" else (e.ip, e.host)',
         'return (e.host, e.path) if scope == "path" else (e.host,)'),
    "non-prod fallback window ignored":
        ("if 0 <= dt <= window:  # same-site fallback window", "if 0 <= dt:  # same-site fallback window"),
    "zero-parseable-lines guard removed (garbage log reports clean)":
        ("    if not events:\n        # CANNOT TELL IS NOT A PASS", "    if False:\n        # CANNOT TELL IS NOT A PASS"),
    "urlquery search proceeds without a key":
        ('    if not key:\n        raise RuntimeError("urlquery.net search requires',
         '    if False:\n        raise RuntimeError("urlquery.net search requires'),
}


def run_suite(module_path: str) -> tuple[bool, str]:
    env = dict(os.environ, LV_PSS_MODULE=module_path)
    env.pop("LV_LIVE", None)
    p = subprocess.run([sys.executable, "-m", "unittest", SUITE], capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=env)
    summary = [ln for ln in p.stderr.splitlines() if ln.startswith(("Ran ", "OK", "FAILED"))]
    return p.returncode == 0, " ".join(summary)


def main() -> int:
    src = open(TOOL, encoding="utf-8").read()
    tmp = tempfile.mkdtemp(prefix="lv-pss-mutants-")
    bad = False
    try:
        ok, summary = run_suite(TOOL)
        print("real public_scan_search.py: %s  (%s)" % ("PASS" if ok else "FAIL", summary))
        bad = not ok
        for i, (name, (old, new)) in enumerate(MUTANTS.items()):
            if src.count(old) < 1:
                print("mutant: %s -> TARGET NOT FOUND; the mutation would test nothing" % name)
                bad = True
                continue
            path = os.path.join(tmp, "m%02d_public_scan_search.py" % i)
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
