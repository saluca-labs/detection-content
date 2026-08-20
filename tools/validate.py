#!/usr/bin/env python3
"""Validate every detection artefact across every campaign.

Runs in CI and before any release. Exits non-zero on the first real problem, so a broken
rule cannot reach a Zenodo deposit with a DOI attached to it.

  python tools/validate.py                     # everything
  python tools/validate.py 2026-08-agentic-intrusion   # one campaign

Checks:
  sigma     every YAML document parses and carries the required Sigma fields, ids are UUIDs
            and unique across the WHOLE repository
  yara      compiles, if yara-python is installed; otherwise a brace and rule-header check
  suricata  balanced parentheses, unique sids, msg/classtype/rev present
  csv       parses and carries the expected columns
  house     no em-dashes anywhere (house style), no obvious secret shapes
"""
from __future__ import annotations

import csv
import glob
import os
import re
import sys
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGMA_REQUIRED = {"title", "id", "status", "description", "logsource", "detection", "level"}
IOC_COLUMNS = {"type", "value", "context", "confidence", "source", "notes"}
# Pre-consolidation schema, kept working because its CSV is attached to a published DOI.
LEGACY_IOC_COLUMNS = {"campaign", "type", "indicator", "context", "source"}

problems: list[str] = []
notes: list[str] = []
seen_ids: dict[str, str] = {}


def fail(msg: str) -> None:
    problems.append(msg)


def campaigns(argv: list[str]) -> list[str]:
    base = os.path.join(ROOT, "campaigns")
    if argv:
        return [os.path.join(base, a) for a in argv]
    return sorted(d for d in glob.glob(os.path.join(base, "*")) if os.path.isdir(d))


def check_sigma(path: str) -> int:
    try:
        import yaml
    except ImportError:
        notes.append("PyYAML absent, sigma parsing skipped")
        return 0
    n = 0
    for f in sorted(glob.glob(os.path.join(path, "detections", "sigma", "*.yml"))):
        try:
            docs = [d for d in yaml.safe_load_all(open(f, encoding="utf-8")) if d]
        except Exception as exc:
            fail("sigma parse %s: %s" % (f, exc))
            continue
        for d in docs:
            missing = SIGMA_REQUIRED - set(d)
            if missing:
                fail("sigma %s :: %s missing %s" % (f, d.get("title", "?"), sorted(missing)))
                continue
            rid = str(d["id"])
            try:
                uuid.UUID(rid)
            except ValueError:
                fail("sigma %s :: id is not a UUID: %s" % (f, rid))
            if rid in seen_ids:
                fail("sigma DUPLICATE id %s in %s and %s" % (rid, seen_ids[rid], f))
            seen_ids[rid] = f
            n += 1
    return n


def check_yara(path: str) -> int:
    files = sorted(glob.glob(os.path.join(path, "detections", "yara", "*.yar")))
    n = 0
    for f in files:
        src = open(f, encoding="utf-8").read()
        try:
            import yara  # type: ignore
            yara.compile(source=src)
        except ImportError:
            if src.count("{") != src.count("}"):
                fail("yara %s: unbalanced braces" % f)
            notes.append("yara-python absent, %s brace-checked only" % os.path.basename(f))
        except Exception as exc:
            fail("yara compile %s: %s" % (f, exc))
        n += len(re.findall(r"^\s*(?:private\s+)?rule\s+\w+", src, re.M))
    return n


def check_suricata(path: str) -> int:
    n = 0
    for f in sorted(glob.glob(os.path.join(path, "detections", "suricata", "*.rules"))):
        txt = open(f, encoding="utf-8").read()
        blocks = re.findall(r"^alert .*?\)\s*$", txt, re.S | re.M)
        sids = re.findall(r"sid:(\d+);", txt)
        if len(sids) != len(set(sids)):
            fail("suricata %s: duplicate sids" % f)
        for b in blocks:
            if b.count("(") != b.count(")"):
                fail("suricata %s: unbalanced parens in %s" % (f, b[:60]))
            for req in ("msg:", "classtype:", "rev:"):
                if req not in b:
                    fail("suricata %s: rule missing %s" % (f, req))
        n += len(blocks)
    return n


def check_iocs(path: str) -> int:
    n = 0
    for f in sorted(glob.glob(os.path.join(path, "iocs", "*.csv"))):
        with open(f, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        if not rows:
            fail("iocs %s: empty" % f)
            continue
        cols = set(rows[0])
        # Two schemas exist. The borrowed-trust pack predates consolidation and its CSV is
        # attached to an immutable Zenodo deposit, so it is accepted as-is rather than
        # rewritten: changing it would make the repository disagree with a published DOI.
        # New packs use the fuller schema, which carries confidence and free-text notes.
        if IOC_COLUMNS <= cols:
            pass
        elif LEGACY_IOC_COLUMNS <= cols:
            notes.append("%s uses the pre-consolidation indicator schema (accepted)"
                         % os.path.basename(os.path.dirname(os.path.dirname(f))))
        else:
            fail("iocs %s: recognises neither schema. Has %s, wants %s"
                 % (f, sorted(cols), sorted(IOC_COLUMNS)))
        n += len(rows)
    return n


def check_house(path: str) -> None:
    """House style and a cheap secret sweep. Detection content is published; a leaked key
    in a rule comment would be published with it."""
    secretish = re.compile(
        r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{36}|"
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)")
    for f in glob.glob(os.path.join(path, "**", "*"), recursive=True):
        if not os.path.isfile(f) or f.endswith((".png", ".jpg", ".pdf")):
            continue
        try:
            txt = open(f, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        if "—" in txt:
            fail("house style: em-dash in %s" % os.path.relpath(f, ROOT))
        m = secretish.search(txt)
        if m:
            fail("POSSIBLE SECRET in %s (%s...)" % (os.path.relpath(f, ROOT), m.group(0)[:8]))


def main() -> int:
    targets = campaigns(sys.argv[1:])
    if not targets:
        print("no campaigns found")
        return 1
    print("Validating %d campaign(s)\n" % len(targets))
    for c in targets:
        name = os.path.basename(c)
        s, y, u, i = check_sigma(c), check_yara(c), check_suricata(c), check_iocs(c)
        check_house(c)
        print("  %-34s sigma=%-3d yara=%-3d suricata=%-3d iocs=%d" % (name, s, y, u, i))
    print()
    for n in dict.fromkeys(notes):
        print("  note: %s" % n)
    if problems:
        print("\n%d PROBLEM(S):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        return 1
    print("\nAll checks passed. %d unique rule ids across the repository." % len(seen_ids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
