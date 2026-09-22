# LLM-Tasked C2

Detection content for **malware with no command-and-control server**, which asks four commercial LLM providers what to do next and takes the plurality answer. Written after Cisco Talos published CLOSEDQUORUM and open-sourced the CAIRN framework on 22 September 2026.

Defensive only. Apache-2.0. Part of [saluca-labs/detection-content](https://github.com/saluca-labs/detection-content).

**Paper:** not yet deposited. This README is the analysis until it is.

---

## The short version

CLOSEDQUORUM is a 16.4 MB Go implant for Windows. It has no C2 server. On each cycle it queries **DeepSeek, Qwen, Mistral and Google Gemini**, and aggregates their answers by plurality vote in a function named `interModelDiscussion()`. Talos: "Each provider's Decision field value increments a `map[string]int` counter, and the highest-count decision wins." Ties break to DeepSeek, then Qwen, then Mistral, then Gemini.

Model replies are constrained to a typed JSON schema with four capabilities: `steal`, `inject`, `persist`, `move`. The embedded system prompt reads `You are an advanced malware strategist. Provide ONLY executable decisions.` Stolen credentials leave over Discord webhooks, AES-256-GCM, under a key derived from the current date. Execution runs at randomised 5 to 15 minute intervals. Six SHA256 hashes were published, spanning seven days of development builds. Developer artifacts connect the author to carding forum postings dating to 2025.

Talos classify it **A4, LLM-Tasked C2**, in the CAIRN archetype taxonomy (A0 to A11).

**Say this before anyone assumes a breach.** Talos state plainly that they have "no confirmation of in-the-wild deployment." The distribution binary carries `dummy_api_key` and `dummy_webhook_url`, and they "did not observe a complete end-to-end execution of the architecture." This is a working capability of unproven deployment, found by metadata hunting rather than by incident response. Most coverage will blur that. A pack that blurs it too is worse than no pack.

Here is the line that defines the problem, from the report itself:

> Instead of a singular, unique C2 server, CLOSEDQUORUM calls up to four commercial LLM provider endpoints used by thousands of legitimate applications daily.

## Why this pack exists when we already publish an LLM egress rule

[`2026-08-agentic-intrusion`](../2026-08-agentic-intrusion/) ships `sigma/llm-api-egress-from-server.yml`, and it already lists `api.deepseek.com`, `openrouter.ai` and `api.mistral.ai`. On a domain controller or an application server, that rule catches this today and this pack adds nothing.

The gap is **the workstation**. CLOSEDQUORUM is a credential stealer: LSASS, process injection, WMI persistence, Discord exfiltration. It lives where people work, and the August pack says in its own text that on a workstation LLM API egress is a hunt rather than an alert, because developers generate it constantly. One process talking to one model provider on a laptop in 2026 is noise.

So the discriminator cannot be the endpoint.

## The one idea: LLM-tasked C2 has a quorum signature

This is the contribution and it is worth stating plainly before the rules.

The implant polls **four** providers and holds a vote, because no single model is reliable enough to be trusted with a tactical decision alone. That is the attacker's reliability engineering, and it is the defender's signal.

**Legitimate software commits to a provider.** It holds one API key, against one SDK, and calls one host. Real applications do implement multi-provider fallback, but fallback fails *over*: sequentially, on error, one at a time. It does not fan out to four providers at once and compare the answers, because there is no reason to. Only something that does not trust its own brain needs a quorum.

Talos reach the same place from the sample side: far fewer legitimate applications contact several providers "while also accessing LSASS, injecting into suspended processes, or creating WMI persistence."

There is a second idea worth noticing. The **typed decision schema is a gift to defenders.** By constraining the model to `steal`, `inject`, `persist`, `move`, the malware's own design enumerates the host behaviour to join the network signal to. Three of those four verbs are directly observable in ordinary Sysmon telemetry. The attacker had to write down what the malware is allowed to do, and then shipped that list inside the binary.

## Deploy these three first

1. **The quorum** (`detections/sigma/llm-quorum-c2.yml`, `kql`, `splunk`). One process, two or more distinct LLM providers, ten minutes. Start the threshold at two, look at what comes back, allowlist your own tooling by full image path, and only then decide whether to move to three. This is a hunt on day one and an alert after you have baselined.
2. **Quorum joined to capability** (same files). The quorum plus LSASS access, remote thread creation, or WMI persistence by the same process inside thirty minutes. **This is the one to alert on.** An LLM gateway does not read LSASS.
3. **Discord webhook egress from a process that is not Discord** (same files). A commodity exfiltration channel, not specific to this family, which makes the rule more useful rather than less.

The hashes are in [`iocs/indicators.csv`](iocs/indicators.csv) and are the least useful thing in this pack. Six development builds across seven days, no confirmed deployment. **A clean hash sweep is not coverage of this technique and must not be reported as coverage.**

## What you cannot detect here

Say all of this to your stakeholders before they assume they are covered.

- **You cannot block the C2.** It is `api.deepseek.com`. The endpoints are in the indicator file so that you can *count* them, not so that you can deny them. If your answer to this threat is a blocklist, the threat has already won the argument: the whole point of the design is that its infrastructure is indistinguishable from infrastructure you are under commercial pressure to permit.
- **A single-provider variant defeats this entire pack.** Everything here counts distinct providers. An implant that asks one model produces no quorum, and one that runs an open-weight model on the host produces no network signal at all.
- **This detection has a shelf life, and that is a property of it rather than a defect.** The quorum exists to compensate for single-model unreliability. As models get better, the reason for the fan-out goes away and these rules quietly stop working. Deploy them now. Distrust them later. Do not build a control narrative that assumes they keep earning their place.
- **LLM routers are true positives for the logic and false positives for you.** LiteLLM, OpenRouter clients, Portkey, Helicone and anything else whose job is to sit in front of several providers do exactly what the rule describes, for good reasons. If you run one, raise the threshold and record what you gave up.
- **The 5 to 15 minute cadence is genuinely hard.** Jitter across that range overlaps with update checkers, telemetry agents and sync clients. The cadence query narrows a candidate you already have. Run it broadly and you will drown.
- **Nothing here sees the decision.** The tasking happens inside TLS to a commercial provider, and the response is four JSON words. Unless you operate the gateway, you observe that a vote occurred and never what it decided.
- **The providers are better placed than you are.** DeepSeek, Alibaba, Mistral and Google can see this from their side, as a pattern of API calls whose prompts say `You are an advanced malware strategist`. Talos's report makes no statement about whether any of them were notified or took action, and neither do we.

## A note on cognitive artifacts, and why reading the adversary's narration is sound here

CAIRN hunts what Talos call **cognitive artifacts**: "prompt templates, provider endpoints, API keys, jailbreak terms, and other artifacts embedded throughout their tooling." In CLOSEDQUORUM that includes the system prompt compiled into the binary.

It is worth being precise about why reading an adversary's own narration is sound here, because in our companion research it was not.

In [Detection Without Indicators](https://doi.org/10.5281/zenodo.21770780) we proposed agent narration as a detection surface, and then narrowed the whole family in v1.1 after a vendor measured a monitor that read a live agent's reasoning trace. It flagged about 1% of actions, because the agent's stated belief that it was in a simulation persuaded the monitor the activity was permitted. With the reasoning withheld, the flag rate on identical material rose to about 50%. The narration did not fail to help. It argued the monitor out of its own alarm.

The difference is not that one narration is honest and the other is deceitful. Both are adversarial. **The difference is that a string in a binary cannot react to being examined.** It cannot notice the analyst, and it cannot argue.

So the rule to carry into anything that reads what an AI system says about itself: **static narration is evidence; live narration offered by the subject of an investigation is a claim to be falsified against ground truth.** CAIRN is on the right side of that line, and it is a useful demonstration that the line exists.

## What was actually validated

Honest accounting, because the rest of this repository sets that precedent.

- Sigma parses and validates, rule UUIDs are unique across every campaign in this repository, and both correlation rules resolve to base rules that exist. Verified by `tools/validate.py`.
- A YAML break was found and fixed during authoring: a colon inside a `falsepositives` entry silently terminated the document. It was caught by the validator, and the validator was then checked against that exact broken input to confirm it rejects it rather than passing everything.
- **No rule in this pack has been run against CLOSEDQUORUM telemetry.** We did not obtain a sample. Everything behavioural is derived from Talos's published description of the mechanism.
- The KQL and SPL are written against Defender advanced hunting and Sysmon field names respectively and have **not** been executed against a live tenant or index. Expect field name drift and treat the first run as a syntax check.
- The quorum argument itself is reasoned from the published design, not measured. We have not sampled a corpus of benign software to establish how many legitimate processes contact two or more providers in ten minutes. **That number is the one thing that decides whether rule 1 is deployable in your estate, and we do not have it.** Measure it before you alert.
- No YARA here. Talos published a rule and it is theirs to maintain; duplicating it would add risk and no coverage.

Treat the pack as a well-argued hypothesis to tune, not a finished product.

## Scope and intent

Defensive. These rules detect malware that delegates its decisions to commercial language models. Nothing here assists in building such a thing: no offensive tooling, no prompts, no orchestration code, no exploit code. The mechanism is described because a defender cannot detect what has not been described, and it is already public in the primary source.

This pack names no provider as culpable. DeepSeek, Alibaba, Mistral and Google are being used as infrastructure by someone abusing an ordinary commercial API, which is the same thing that has happened to every hosting provider, CDN and paste site before them.

## Sources

- Cisco Talos, Ryan Fetterman, "The Closed Quorum: Inside the first reported autonomous AI C2 implant", 22 September 2026 (primary; mechanism, hashes, endpoints, YARA, detection guidance, and the statement that in-the-wild deployment is unconfirmed)
- Cisco Talos, Ryan Fetterman, "Introducing CAIRN: Frontier tracking for AI-integrated malware", 22 September 2026 (primary; the AI-integrated malware definition, cognitive artifacts, the A0 to A11 archetypes, the three-tier rule ontology)
- [Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network](https://github.com/Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network), MIT (the framework, the archetype list, 26 validated rules across T1 to T3)
- Help Net Security, "Researchers uncover malware that uses AI to choose its next move", 22 September 2026 (secondary; no technical claim in this pack rests on it)

## AI disclosure

Written with AI assistance. The quorum argument, the static-versus-live narration distinction, the rule logic, the rankings and the limitations above were authored and reviewed by a human, who is responsible for the claims. The "what you cannot detect here" section exists specifically because generated detection content tends to overstate coverage.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
