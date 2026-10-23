# Docs index

Every document in this repository, grouped by what you came to do. One line each on what it
answers. Paths are relative to the repository root.

## Start here

- [README.md](../README.md): what the repository is, the campaign table, validation results, install, quickstart, citation.
- [Each campaign README](../campaigns/): what that pack detects, what it cannot detect, which rules are alerts and which are hunts, deployment order. Read it before deploying anything from that pack.

## Deploy rules in your estate

- `campaigns/<slug>/detections/sigma/*.yml`: Sigma rules (host and log). Every rule ships `status: experimental`.
- `campaigns/<slug>/detections/kql/*.kql`: Defender XDR and Sentinel hunting queries. Never executed by this repository.
- `campaigns/<slug>/detections/splunk/*.spl`: Splunk searches. Never executed by this repository.
- `campaigns/<slug>/detections/suricata/*.rules`: network rules, one per line, loaded in a real engine by CI.
- `campaigns/2026-08-borrowed-trust/detections/yara/*.yar`: the only YARA rules (the only pack with samples to key on).
- `campaigns/2026-09-rsa-raw-oracle/detections/semgrep/raw-rsa.yml`: the only Semgrep rules.
- `campaigns/<slug>/iocs/indicators.csv`: atomic indicators with a source on every row, or a NOTE row saying none were published.

## Hunt (read-only scripts)

- [hunt/](../hunt/): cross-campaign hunt scripts. Each script's header states its arguments and that it is read-only:
  `Invoke-AgenticExposureSweep.ps1`, `Invoke-BorrowedTrustSweep.ps1`, `Invoke-DevToolchainExposureReview.ps1`,
  `public_scan_search.py`, `rsa_oracle_audit.py`, `transitive_egress_audit.py`.

## Read the analysis

- `campaigns/<slug>/<paper>-v*.md` and `.pdf`: the companion papers, where the pack has one (7 of 9). The citable record is the concept DOI in the README's Citation section.
- [RELEASE-NOTES-v1.0.0.md](../RELEASE-NOTES-v1.0.0.md): the v1.0.0 consolidation release. Historical: its "one citation that grows" plan was reverted on 2026-08-20 (see WORKFLOW.md section 5); each analysis now has its own DOI.

## Contribute or maintain

- [WORKFLOW.md](../WORKFLOW.md): the maintainers' procedure from public report to pack, paper and deposit, with the checklist.
- [AGENTS.md](../AGENTS.md): orientation and rules for AI coding agents working here.
- [tools/validate.py](../tools/validate.py), [tools/suricata_test.py](../tools/suricata_test.py): what the checks actually check, in their docstrings.
- [.github/workflows/validate.yml](../.github/workflows/validate.yml): exactly what CI runs.

## Cite

- [CITATION.cff](../CITATION.cff): how to cite the repository; each paper has its own concept DOI.

## For agents

- [llms.txt](../llms.txt): the complete public surface (every command and script) and this map, in one fetch.
