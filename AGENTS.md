# AGENTS.md

Instructions for AI coding agents working in this repository.

## Setup

```bash
python -m pip install pyyaml yara-python scapy
docker pull jasonish/suricata:7.0.17
```

Python 3.12. Docker is needed only for the Suricata engine test.

## Test

```bash
python tools/validate.py          # must end "All checks passed."
python tools/suricata_test.py     # must end "All Suricata rule files load and every shipped pcap test fires exactly as expected."
python -m unittest hunt/tests/test_rsa_oracle_audit.py hunt/tests/test_public_scan_search.py hunt/tests/test_transitive_egress_audit.py
```

`.github/workflows/validate.yml` runs these plus the mutation harnesses, the Semgrep test and the
SoftHSM2 test.

## Conventions

- One pack per campaign under `campaigns/<slug>/`; start a new one with `python tools/new-campaign.py <slug> --title "<name>"`.
- Every pack README keeps its "What you cannot detect here" section, written before the rules.
- Rules ship `status: experimental`. Sigma ids are UUIDs, unique across the whole repository; Suricata sids are unique.
- Suricata rules are one rule per line (the engine does not join lines without a trailing backslash).
- Indicator files name a source on every row, or carry a NOTE row saying no atomic indicators were published.
- Hunt scripts are strictly read-only and say so in their headers.
- No em-dashes in docs (`tools/validate.py` checks this).

## Do not

- Add malware samples, payloads, exploit code or working attack automation. Test pcaps use inert values.
- Edit a published paper (`campaigns/<slug>/*-v*.md`, `.pdf`) in place; publish a new version or a dated correction.
- Commit hunt output (`*.results.json`, sweep reports): it records hostnames, usernames and paths.
- Commit secrets, hostnames, internal paths or personal emails.

## Done means

`tools/validate.py` and `tools/suricata_test.py` pass, and any changed pack README still states
what it cannot detect.
