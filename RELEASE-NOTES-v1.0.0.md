# v1.0.0 — consolidation, and the agentic intrusion pack

First release of the consolidated repository. Two campaign packs, shared tooling, and one
citation that grows rather than fragmenting into a DOI per campaign.

## What is in it

**`campaigns/2026-08-borrowed-trust`** — migrated from `saluca-labs/borrowed-trust-detections`.
Three concurrent campaigns sharing one primitive: a validly signed binary resolves a
malicious dependency at runtime. 22 Sigma rules, 12 YARA rules, 26 Suricata rules, 103
indicators, atomic and behavioural.

**`campaigns/2026-08-agentic-intrusion`** — new. Written after the July 2026 campaign against
Taiwanese government and energy targets, in which up to eight LLM agents built on the
open-source Hermes and OpenClaw frameworks worked 21 systems over four days, taking 85+
accounts and 2,500+ personnel records before expanding to a nuclear safety regulator and
seven energy companies. 7 Sigma rules, 8 Suricata rules, KQL and SPL packs, 22 behavioural
indicators.

## The contribution in this release

No atomic indicators were published for the Taiwan campaign. No hashes, no addresses, no
domains, no filenames. So the pack is behavioural, and its argument is a **tempo model**.

Three actors produce three rhythms. A human is slow and irregular. A script is fast and
uniform and does not change technique when it fails. An agent emits machine-speed bursts
separated by inference-latency pauses of roughly two to thirty seconds, and changes technique
after a failure because a planner re-ranked its options. That third pattern is a property of
inference-driven planning rather than of any particular framework, so it survives the
operator changing tools, models, or infrastructure. The SPL and KQL packs score sources
against it and return a verdict.

The second contribution is narrower but more actionable: the reported guardrail bypass was
not a jailbreak. Operators framed the campaign as an authorized penetration test, which the
model had no reliable way to verify or reject. That is a separation-of-duties failure rather
than a model-safety failure, and it is only observable at a gateway you operate, which the
`llm-authorization-assertion` rules target directly.

## What this release does not do

Stated here as well as in each pack, because it is the part that matters.

- There are no indicators of compromise for the Taiwan campaign. None were published.
- The prompt-level bypass is invisible to network sensors. It happened inside TLS to a
  third-party provider.
- Self-hosted inference defeats every egress rule in the agentic pack completely.
- Open-source agent frameworks are legitimate software. Rules keying on them are hunting
  rules, marked as such, and detect capability rather than compromise.
- No rule in the agentic pack has been tested against telemetry from the actual campaign,
  because none is public. The tempo thresholds are reasoned from published inference
  latencies and must be baselined before use.

## Tooling

- `tools/validate.py` — Sigma schema and UUID uniqueness across the whole repository, YARA
  compilation, Suricata sid uniqueness and syntax, indicator schemas, house style, and a
  sweep for secret-shaped strings. Runs in CI on every push.
- `tools/new-campaign.py` — scaffolds the next pack, with the "what you cannot detect here"
  section present before any rule is written.
- `WORKFLOW.md` — the standing procedure from public report to published article.

## Citation

This release establishes the concept DOI. Cite the concept DOI to reference the work as a
whole; it always resolves to the newest version.

The Borrowed Trust pack retains its own DOI, [10.5281/zenodo.21880002](https://doi.org/10.5281/zenodo.21880002),
from before consolidation. That deposit is immutable and still resolves, so it is cited here
rather than replaced, and its original indicator schema is preserved unchanged.

Apache-2.0. Defensive only.
