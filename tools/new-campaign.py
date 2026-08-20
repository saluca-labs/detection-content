#!/usr/bin/env python3
"""Scaffold a new campaign pack, pre-filled with the parts that are always the same.

The point of this script is that the next pack starts from the house structure and the
house honesty, not from a blank directory. The README stub in particular ships with the
"What you cannot detect here" section already present, because that is the section that
gets skipped when someone is in a hurry, and it is the one that keeps the pack credible.

  python tools/new-campaign.py 2026-09-some-campaign --title "Some Campaign"

Then: write the rules, run tools/validate.py, follow WORKFLOW.md.
"""
from __future__ import annotations

import argparse
import os
import uuid
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

README = '''# {title}

{oneliner}

Defensive only. Apache-2.0. Part of [saluca-labs/detection-content](https://github.com/saluca-labs/detection-content).

---

## The short version

TODO: what happened, who reported it, when, and the single most important technical fact.

## Deploy these first

TODO: ranked, with the reasoning for the ranking. Three or four, not everything.

## What you cannot detect here

Write this section BEFORE the rules, not after. It is the section that keeps the pack
honest and it is the first thing a competent reader checks.

- TODO: what indicators do not exist, and say so plainly if none were published
- TODO: what is structurally invisible to the sensors these rules use
- TODO: what a competent operator changes to evade this, and what it costs them
- TODO: which rules are hunting rather than alerting, and why

## Limitations

TODO: thresholds that need baselining, telemetry that may not exist in a given estate.

## What was actually validated

TODO: be exact. Syntax validated is not the same as tested against real telemetry. If no
campaign telemetry was available, say so.

## Scope and intent

Defensive. These rules detect intrusion activity; nothing here assists in conducting one.

## Sources

TODO

## AI disclosure

Written with AI assistance. Rule logic and the limitations above were authored and reviewed
by a human.

## License

Apache-2.0.
'''

SIGMA_STUB = '''# Sigma - {title}
#
# TODO: what this catches, and just as importantly what it does not.
#
# Ref: TODO
# Author: Cristian Ruvalcaba and the Saluca Agentic AI Research Team, {today}

title: TODO
id: {rule_id}
status: experimental
description: |
  TODO. State whether this is an ALERT or a HUNT, and why.
references:
    - TODO
author: Cristian Ruvalcaba and the Saluca Agentic AI Research Team
date: {today}
tags:
    - attack.TODO
logsource:
    category: TODO
detection:
    selection:
        TODO: TODO
    condition: selection
falsepositives:
    - TODO. Be specific. "Unknown" is not an answer.
level: medium
'''

IOCS = ('type,value,context,confidence,source,notes\n'
        'NOTE,TODO,{slug},n/a,TODO,"State here whether atomic indicators exist for this '
        'campaign. If none were published, say so explicitly so nobody assumes coverage."\n')


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("slug", help="e.g. 2026-09-campaign-name")
    ap.add_argument("--title", required=True)
    ap.add_argument("--oneliner", default="TODO: one sentence on what this pack covers.")
    a = ap.parse_args()

    base = os.path.join(ROOT, "campaigns", a.slug)
    if os.path.exists(base):
        print("already exists: %s" % base)
        return 1
    for d in ("detections/sigma", "detections/kql", "detections/splunk",
              "detections/suricata", "detections/yara", "iocs"):
        os.makedirs(os.path.join(base, d), exist_ok=True)

    today = date.today().isoformat()
    open(os.path.join(base, "README.md"), "w", encoding="utf-8").write(
        README.format(title=a.title, oneliner=a.oneliner))
    open(os.path.join(base, "detections/sigma/example.yml"), "w", encoding="utf-8").write(
        SIGMA_STUB.format(title=a.title, rule_id=uuid.uuid4(), today=today))
    open(os.path.join(base, "iocs/indicators.csv"), "w", encoding="utf-8").write(
        IOCS.format(slug=a.slug))

    print("scaffolded campaigns/%s" % a.slug)
    print("  a fresh rule id for you: %s" % uuid.uuid4())
    print("\nnext: write the README's 'what you cannot detect' section FIRST, then the rules,")
    print("      then `python tools/validate.py %s`, then follow WORKFLOW.md" % a.slug)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
