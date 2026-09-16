#!/usr/bin/env python3
"""Load every Suricata rule file in a REAL Suricata engine, and fire packs that ship a test pcap.

validate.py checks syntax by pattern: balanced parens, unique sids, required keywords. That was
green for a month while every multi-line rule file in this repository failed to load, because
Suricata does not join lines without a trailing backslash. A rule that does not load protects
nobody. This script asks the engine.

  python tools/suricata_test.py                 # every campaign
  python tools/suricata_test.py 2026-09-slug    # one campaign

Needs Docker. Uses the image below, pinned so a Suricata release cannot change the verdict
silently.

Two checks per campaign:
  load   suricata -T with every custom address group the packs use defined as TEST-NET. Any
         rule that fails, any engine error, or a loaded count lower than the number of rules
         in the file fails the check.
  fire   only if campaigns/<slug>/tests/build_test_pcap.py exists. It builds a pcap and
         exports EXPECT_COUNTS. The alert counts per sid must match EXACTLY: a missing alert
         is a rule that does not fire, and an extra alert is a rule that fires on a negative
         case. Needs scapy.
"""
from __future__ import annotations

import collections
import glob
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = "jasonish/suricata:7.0.17"

# Every custom address group any pack references. TEST-NET values: the load check needs the
# variables to exist, not to be right. Adding a pack with a new variable means adding it here.
ADDRESS_GROUPS = {
    "HOME_NET": "[192.0.2.0/24,10.0.0.0/8]",
    "OT_NET": "[192.0.2.0/24]",
    "RESTRICTED_NET": "[192.0.2.0/25]",
    "AI_ALLOWED_NET": "[192.0.2.128/25]",
    "SANDBOX_NET": "[198.51.100.0/24]",
    "AZURE_STORAGE_NET": "[203.0.113.0/25]",
    "AWS_S3_NET": "[203.0.113.128/25]",
}

problems: list[str] = []


def docker(args: list[str], mounts: dict[str, str]) -> subprocess.CompletedProcess:
    cmd = ["docker", "run", "--rm", "--entrypoint", "suricata"]
    for host, guest in mounts.items():
        cmd += ["-v", "%s:%s" % (host, guest)]
    cmd.append(IMAGE)
    cmd += args
    for k, v in ADDRESS_GROUPS.items():
        cmd += ["--set", "vars.address-groups.%s=%s" % (k, v)]
    env = dict(os.environ, MSYS_NO_PATHCONV="1")   # Git Bash on Windows mangles /paths
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


def count_rules(path: str) -> int:
    return sum(1 for line in open(path, encoding="utf-8") if line.startswith("alert "))


def check_load(campaign: str) -> None:
    for f in sorted(glob.glob(os.path.join(campaign, "detections", "suricata", "*.rules"))):
        name = os.path.relpath(f, ROOT)
        expected = count_rules(f)
        r = docker(["-T", "-v", "-S", "/r/" + os.path.basename(f), "-l", "/tmp"],
                   {os.path.dirname(f): "/r:ro"})
        out = r.stdout + r.stderr
        m = re.search(r"(\d+) rules successfully loaded, (\d+) rules failed", out)
        errors = [ln for ln in out.splitlines() if ln.startswith("E:")]
        if r.returncode != 0 or not m or int(m.group(2)) or int(m.group(1)) != expected or errors:
            loaded = m.group(1) if m else "?"
            problems.append("load %s: rc=%d loaded=%s of %d\n      %s" % (
                name, r.returncode, loaded, expected, "\n      ".join(errors[:5]) or out[-400:]))
        else:
            print("  load  %-70s %d/%d" % (name, int(m.group(1)), expected))


def check_fire(campaign: str) -> None:
    builder = os.path.join(campaign, "tests", "build_test_pcap.py")
    if not os.path.exists(builder):
        return
    spec = importlib.util.spec_from_file_location("pcap_builder", builder)
    mod = importlib.util.module_from_spec(spec)
    sys.argv, saved = [builder], sys.argv
    try:
        spec.loader.exec_module(mod)            # builds the packet list at import
    finally:
        sys.argv = saved
    rules = glob.glob(os.path.join(campaign, "detections", "suricata", "*.rules"))
    work = tempfile.mkdtemp(prefix="suricata-fire-")
    try:
        from scapy.all import wrpcap  # type: ignore
        wrpcap(os.path.join(work, "t.pcap"), mod.pkts)
        for f in rules:
            shutil.copy(f, work)
        args = ["-k", "none", "-r", "/w/t.pcap", "-l", "/w"]
        for f in rules:
            args += ["-S", "/w/" + os.path.basename(f)]
        r = docker(args, {work: "/w"})
        fast = os.path.join(work, "fast.log")
        got = collections.Counter(
            int(s) for s in re.findall(r"\[1:(\d+):\d+\]", open(fast).read())) if os.path.exists(fast) else {}
        want = collections.Counter(mod.EXPECT_COUNTS)
        name = os.path.basename(campaign)
        if got != want:
            missing = {k: want[k] - got.get(k, 0) for k in want if got.get(k, 0) < want[k]}
            extra = {k: got[k] - want.get(k, 0) for k in got if got[k] > want.get(k, 0)}
            problems.append("fire %s: missing %s extra %s (rc=%d)" % (name, missing, extra, r.returncode))
        else:
            print("  fire  %-70s %d alerts across %d sids, as expected" % (name, sum(got.values()), len(got)))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    base = os.path.join(ROOT, "campaigns")
    targets = [os.path.join(base, a) for a in sys.argv[1:]] or \
        sorted(d for d in glob.glob(os.path.join(base, "*")) if os.path.isdir(d))
    print("Suricata engine test, image %s\n" % IMAGE)
    for c in targets:
        check_load(c)
        check_fire(c)
    if problems:
        print("\n%d PROBLEM(S):" % len(problems))
        for p in problems:
            print("  - %s" % p)
        return 1
    print("\nAll Suricata rule files load and every shipped pcap test fires exactly as expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
