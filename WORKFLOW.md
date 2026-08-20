# Campaign workflow

The standing procedure for turning a public threat report into a Saluca detection pack, a
citable paper, and an article. Written to be followed without re-deriving it each time.

**Recall pointers.** `ask_internal("detection content workflow")` in the `ops` corpus, or
open this file. The corpus entry is a summary; this file is authoritative.

---

## The shape

Three artefacts, one source of truth, published in a fixed order:

```
  repo (this)  ->  Zenodo version  ->  Substack article
  the content      the citation        the reach
```

Order matters. The article links the repo and the DOI, so both must exist first. Publishing
the article early and backfilling the links is how a piece goes out pointing at a 404.

---

## 1. Scaffold

```bash
python tools/new-campaign.py 2026-09-slug --title "Campaign Name"
```

Creates `campaigns/2026-09-slug/` with the house structure and a README stub.

**Write the README's "What you cannot detect here" section before writing any rules.** This
is not a formality. Deciding up front what the pack cannot do determines which rules are
worth writing, and it is the section a competent reader checks first. Written afterwards it
becomes an apology; written first it becomes the design.

## 2. Decide what is actually detectable

Ask, in this order:

1. **Were atomic indicators published?** Hashes, IPs, domains, filenames. If not, say so in
   row one of `iocs/indicators.csv` and build a behavioural pack. Never imply coverage you
   do not have.
2. **What is structurally invisible?** Anything inside TLS to a third party, anything that
   happened in a prompt, anything that used valid credentials successfully.
3. **What is a consequence of the technique rather than an operator choice?** These are the
   durable detections. An operator can change a hash trivially and infrastructure cheaply,
   but not the shape of what the technique requires.
4. **What is a hunting rule and what is an alert?** Mark every rule honestly. Anything
   keying on legitimate widely-installed software is a hunt, always.

## 3. Write

Per-campaign directory, one file per platform:

```
campaigns/<slug>/
  README.md                       analysis + limitations
  detections/sigma/*.yml          host and log rules
  detections/kql/*.kql            Defender XDR and Sentinel
  detections/splunk/*.spl         SPL searches
  detections/suricata/*.rules     network, if there is anything to see
  detections/yara/*.yar           only if samples exist. Omit the directory if not.
  iocs/indicators.csv             atomic or behavioural, labelled as such
```

Cross-campaign hunt scripts go in the root `hunt/`, not the campaign folder, because they
tend to outlive the campaign that prompted them.

House conventions: every Sigma rule gets a real UUID and a comment block above the YAML
explaining the reasoning; `status: experimental` until tuned against real telemetry;
`falsepositives` is never "unknown"; author line is `Cristian Ruvalcaba and the Saluca
Agentic AI Research Team`; no em-dashes anywhere.

## 4. Validate

```bash
python tools/validate.py                 # whole repo
python tools/validate.py 2026-09-slug    # one campaign
```

Checks Sigma schema and UUID uniqueness **across every campaign**, YARA compilation,
Suricata sids and balance, CSV columns, house style, and sweeps for secret-shaped strings.
This runs in CI too. A pack does not get a DOI until it is green.

## 5. Zenodo

**One concept DOI, a new version per campaign.** Do not mint a fresh standalone DOI each
time: a single growing citable work compounds, and every new version inherits the citation
history of the prior ones.

1. Tag a release: `git tag v<n>-<slug> && git push --tags`
2. Zenodo picks up the GitHub release and creates a new **version** under the existing
   concept DOI.
3. Update root `CITATION.cff` with the new version and date.
4. Add the campaign to the table in the root `README.md`.

Prior work with its own DOI stays cited rather than absorbed. `borrowed-trust-detections`
holds `10.5281/zenodo.21880002` from before consolidation; that deposit is immutable and
still resolves, so it is referenced, not replaced.

## 6. Paper

The Zenodo deposit carries the pack. A separate white paper is worth writing only when
there is a **transferable idea** rather than campaign specifics. The agentic-intrusion pack
had one, the tempo model; the borrowed-trust pack did not, and correctly did not get a paper.

If there is one, it goes to the same concept DOI as a version, or to its own deposit if it
stands alone as research.

## 7. Substack

Last, because it links the other two. The article is not a summary of the report, which
anyone can read. It is the argument the report makes possible.

Draft into subcon rather than publishing directly:

```bash
python -c "import sys; sys.path.insert(0, r'C:/AI/saluca-monitor/subcon'); import store; \
  c = store.connect(store.DEFAULT_DB); \
  i = store.add(c, origin='drop', source_url='<report url>'); \
  print('subcon item', i)"
```

Then generate the cover through the worker, review in subcon, and press Upload yourself.
**The agent never publishes and never schedules.**

## 8. Corpus

Detection reasoning goes to `tkhr-detection-eng`: why a rule exists, what it structurally
misses, validated versus assumed, and what the false positives turned out to be in practice.

Do **not** create a corpus per campaign, and do not put OSINT feeds into a corpus. Structured
feeds like KEV and NVD already have good indexes and TKHR adds nothing over them. Campaign
TTPs map into `tkhr-threat-intel`, which already holds ATT&CK v19.1 by tactic.

---

## Checklist

```
[ ] scaffolded with tools/new-campaign.py
[ ] "what you cannot detect here" written FIRST
[ ] atomic indicators present, or their absence stated in indicators.csv row 1
[ ] every rule marked alert or hunt
[ ] falsepositives specific on every rule
[ ] tools/validate.py green
[ ] root README campaign table updated
[ ] release tagged, Zenodo version minted, CITATION.cff updated
[ ] article drafted into subcon, cover generated, NOT published by the agent
[ ] detection reasoning added to tkhr-detection-eng
```
