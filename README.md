# Saluca Detection Content

Detection engineering for campaigns worth writing about. One pack per campaign, one
repository. Each analysis is published separately with its own DOI.

Defensive only. Apache-2.0.

---

## Campaigns

| Campaign | Date | What it covers | Indicators | Paper |
|---|---|---|---|---|
| [2026-08-borrowed-trust](campaigns/2026-08-borrowed-trust/) | Aug 2026 | Three concurrent campaigns sharing one primitive: a validly signed binary resolves a malicious dependency at runtime | atomic + behavioural | [10.5281/zenodo.21880002](https://doi.org/10.5281/zenodo.21880002) |
| [2026-08-agentic-intrusion](campaigns/2026-08-agentic-intrusion/) | Aug 2026 | Intrusion run by orchestrated LLM agents, after the July 2026 campaign against Taiwanese government and energy targets | behavioural only | [10.5281/zenodo.22033405](https://doi.org/10.5281/zenodo.22033405) |

Cross-campaign hunt scripts live in [`hunt/`](hunt/). They tend to outlive the campaign that
prompted them, so they are not filed under one.

## What this is, and what it is not

Each pack is written to a standing rule: **state what it cannot detect before stating what
it can.** Every campaign README carries a "What you cannot detect here" section, and it is
written before the rules rather than after, because deciding the limits up front determines
which rules are worth writing at all.

Some packs have no atomic indicators, because none were published. Those say so in the first
row of their indicator file. A pack that quietly omits that is worse than no pack, because
the reader assumes coverage they do not have.

Rules ship `status: experimental` until they have been tuned against real telemetry in a
real estate. Thresholds are starting points. Anyone deploying these as alerts without
baselining first should expect noise, and that is documented rather than hidden.

## Using it

```bash
python tools/validate.py                       # validate everything
python tools/validate.py 2026-08-agentic-intrusion
python tools/new-campaign.py 2026-09-slug --title "Name"   # scaffold the next one
```

Validation covers Sigma schema and UUID uniqueness across the whole repository, YARA
compilation, Suricata sid uniqueness and syntax, indicator CSV columns, house style, and a
sweep for secret-shaped strings. It runs in CI, and nothing gets a DOI until it is green.

The full procedure from public report to published article is in [WORKFLOW.md](WORKFLOW.md).

## Citation

**Each campaign analysis is deposited separately with its own DOI**, so a specific campaign
can be cited directly. This repository is the shared companion, linked from every deposit.

| Paper | DOI |
|---|---|
| Borrowed Trust | [10.5281/zenodo.21880002](https://doi.org/10.5281/zenodo.21880002) |
| Agentic Intrusion | [10.5281/zenodo.22033405](https://doi.org/10.5281/zenodo.22033405) |

Cite the concept DOI to reference the newest revision of a given paper. To cite the
detection content itself rather than an analysis, cite this repository and the release tag.

Report text is CC-BY-4.0, matching the deposits. The detection content and tooling in this
repository are Apache-2.0. See [CITATION.cff](CITATION.cff).

## Scope and intent

Defensive. These rules detect intrusion activity. Nothing here assists in conducting one: no
offensive tooling, no exploit code, no attack automation. Hunt scripts are strictly
read-only and say so in their own headers.

## AI disclosure

Written with AI assistance throughout. Rule logic, the limitations sections, and every claim
about what was and was not validated are authored and reviewed by a human. The limitations
sections exist specifically because generated detection content tends to overstate coverage.

## License

Apache-2.0. See [LICENSE](LICENSE).

— Saluca Labs
