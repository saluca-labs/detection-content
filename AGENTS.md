# AGENTS.md

Orientation and rules for AI coding agents working in this repository.

## What this is, in two lines

Defensive detection content: one pack per public threat campaign under `campaigns/<slug>/`
(Sigma, KQL, SPL, Suricata, YARA, Semgrep rules and an indicator CSV), plus read-only hunt
scripts in `hunt/` and the checks in `tools/`. It is rule files and test tooling, not a library.

## Read in this order

1. [README.md](README.md): the campaign table, validation results and the "How it works" diagram.
2. [docs/README.md](docs/README.md): every document, by intent.
3. The README of the pack you are touching, `campaigns/<slug>/README.md`, especially "What you cannot detect here".
4. [tools/validate.py](tools/validate.py) and [tools/suricata_test.py](tools/suricata_test.py): their docstrings say exactly what is and is not checked.
5. [.github/workflows/validate.yml](.github/workflows/validate.yml): what CI runs.

## What you can and cannot see

- You can see every rule, indicator file, hunt script, test and fixture, and the paper markdown for 7 of the 9 packs.
- You cannot see the Zenodo records themselves (only their DOIs), the Borrowed Trust paper (Zenodo only), the private PDF build tool and content tooling that WORKFLOW.md names, or any real telemetry: no rule here has been run against a production SIEM, and the KQL and SPL are not executed anywhere.
- Packs that are in open pull requests are not on `main`. Do not describe them as shipped.

## The only numbers to trust

| Number | Source |
|---|---|
| Campaign count, rules per pack, unique rule id count, indicator rows | the output of `python tools/validate.py` (computed by `tools/validate.py` from `campaigns/`) |
| Suricata rules loaded per file | the output of `python tools/suricata_test.py` |
| Expected pcap alerts per sid | `EXPECT_COUNTS` in `campaigns/<slug>/tests/build_test_pcap.py` |
| Pinned engine versions | `IMAGE` in `tools/suricata_test.py` and `hunt/tests/semgrep_test.py`; `python:3.12-slim` in `hunt/tests/pkcs11_softhsm_test.py` |
| Paper DOIs | the README Citation table and `CITATION.cff` (concept DOIs) |

Counts written in prose inside a pack README can be stale (the Borrowed Trust README said 24
Suricata rules where there are 26, corrected 2026-10-22). Re-run the tool rather than quoting prose.

## Agent quickstart

```bash
python tools/validate.py                                  # whole repository
python tools/validate.py 2026-09-transitive-egress        # one pack
python tools/suricata_test.py 2026-09-transitive-egress   # one pack, needs Docker
python tools/new-campaign.py 2026-10-slug --title "Name"  # scaffold a pack
```

Every command and script is listed in [llms.txt](llms.txt). If it is not listed there, it does not exist.

## Setup

```bash
python -m pip install pyyaml yara-python scapy
docker pull jasonish/suricata:7.0.17
```

Python 3.12. Docker is needed only for the Suricata, Semgrep and SoftHSM2 tests.

## Test

```bash
python tools/validate.py          # must end "All checks passed."
python tools/suricata_test.py     # must end "All Suricata rule files load and every shipped pcap test fires exactly as expected."
python -m unittest hunt/tests/test_rsa_oracle_audit.py hunt/tests/test_public_scan_search.py hunt/tests/test_transitive_egress_audit.py
```

`.github/workflows/validate.yml` runs these plus the two mutation harnesses
(`hunt/tests/public_scan_search_mutants.py`, `hunt/tests/transitive_egress_audit_mutants.py`),
`hunt/tests/semgrep_test.py` and `hunt/tests/pkcs11_softhsm_test.py`.

## Conventions

- One pack per campaign under `campaigns/<slug>/`; start a new one with `python tools/new-campaign.py <slug> --title "<name>"`.
- Every pack README keeps its "What you cannot detect here" section, written before the rules.
- Rules ship `status: experimental`. Sigma ids are UUIDs, unique across the whole repository (`tools/validate.py` enforces this). Suricata sids must not repeat; `tools/validate.py` checks this within each file only, so check across packs yourself when adding sids.
- Suricata rules are one rule per line (the engine does not join lines without a trailing backslash).
- Indicator files name a source on every row, or carry a NOTE row saying no atomic indicators were published.
- Hunt scripts are strictly read-only and say so in their headers.
- No em-dashes. `tools/validate.py` checks files under `campaigns/` only; nothing checks the root docs, so check them yourself.

## Do not

- Add malware samples, payloads, exploit code or working attack automation. Test pcaps use inert values.
- Edit a published paper (`campaigns/<slug>/*-v*.md`, `.pdf`) in place; publish a new version or a dated correction.
- Rewrite `campaigns/2026-08-borrowed-trust/iocs/indicators.csv` into the newer schema: it is attached to a published DOI.
- Run `tools/zenodo_deposit.py`. It needs a maintainer's token, and publishing a deposit is a human action.
- Commit hunt output (`*.results.json`, sweep reports): it records hostnames, usernames and paths.
- Commit secrets, hostnames, internal paths or personal emails.

## Done means

`tools/validate.py` and `tools/suricata_test.py` pass, any changed pack README still states
what it cannot detect, and the root README campaign table is updated when a pack is added.
