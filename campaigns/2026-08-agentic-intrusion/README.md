# Agentic Intrusion

Detection content for intrusions run by **orchestrated LLM agents** rather than by a person at a keyboard or a script on a timer, written after the July 2026 campaign against Taiwanese government and energy targets.

Defensive only. Apache-2.0.

**Paper:** [Agentic Intrusion: A Detection Engineering Analysis of the July 2026 Taiwan Campaign, and a Tempo Model for Agent-Driven Attacks](https://doi.org/10.5281/zenodo.22033405) · [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22033405.svg)](https://doi.org/10.5281/zenodo.22033405)
Local copies: [`agentic-intrusion-v1.0.pdf`](agentic-intrusion-v1.0.pdf) · [`.md`](agentic-intrusion-v1.0.md)

---

## The short version

Over four days in early July 2026 an operator ran up to **eight LLM agents concurrently** against Taiwanese government systems. The toolkit was 1,395 files in a 160 MB archive, built around two freely downloadable open-source agent frameworks, **Hermes** and **OpenClaw**. The agents mapped 21 government systems, continuously re-ranked attack paths as evidence arrived, and when a path failed they searched the internet and devised another. Outcome: 85+ accounts, 2,500+ personnel records, then a nuclear safety regulator and at least seven energy companies. Reported by Dream, surfaced by the Financial Times on 12 August 2026. Simplified Chinese appeared in internal communications; no group attribution was made.

The guardrail bypass is the part worth internalising:

> Operators circumvented safety controls by **framing the entire campaign as an authorized penetration test, a scenario the model apparently had no reliable way to verify or reject.**

Nobody jailbroke anything. The operator **asserted an entitlement** and the model had no mechanism to check it. That is not a model-safety failure that better training fixes. It is an architecture failure: the component performing the actions was also the component judging whether it was permitted to.

## Why this repository exists, and what is different about it

Every other detection pack we have written starts from indicators. This one cannot, because **no hashes, IP addresses, domains, or file names have been published**. What has been published is a description of *how the intruder behaved*, and that behaviour has properties a human operator and a conventional script do not have.

So this is a **behavioural** pack. It will not tell you that you were hit by this specific operator. It is built to catch the *class*: an LLM agent, with tools, acting against your estate.

## The one idea: agentic intrusions have a tempo signature

This is the contribution here and it is worth stating plainly before the rules.

- A **human** operator is slow and irregular. Seconds to minutes between actions, frequent long gaps, and technique changes that follow reading and thinking.
- A **script** is fast and uniform. Sub-second intervals, low variance, and it does not change technique when it fails. It just keeps going or stops.
- An **agent** is neither. It emits a **burst** of actions at machine speed, then **pauses for inference latency**, typically two to thirty seconds, then acts again. Critically, **after a failure it changes technique**, because a planner re-ranked the options.

That combination, machine-speed bursts separated by think-pauses, with strategy change on failure, is not something humans or scripts produce. It is the most reliable signal in this pack, and it survives the attacker changing tools, models, or infrastructure, because it is a property of how inference-driven planning works rather than of any particular implementation.

The second-strongest signal is **breadth with adaptation**. Scanners are broad and uniform. Humans are narrow and adaptive. Agents are broad *and* adaptive: 21 systems in four days with technique changes between them.

## Deploy these four first

1. **LLM API egress from anything that is not a workstation** (`sigma/llm-api-egress-from-server.yml`, `suricata`, `kql`). Domain controllers, jump hosts, application servers and appliances have no reason to reach `api.anthropic.com`, `api.openai.com`, `openrouter.ai` or `generativelanguage.googleapis.com`. If one does, either someone has installed an agent on it or an agent is running there. This is cheap, high signal, and almost free of false positives once you allowlist your genuine AI workloads.
2. **Authentication tempo profiling** (`splunk/agentic-tempo.spl`, `kql`). The burst-pause-adapt rhythm described above, expressed against your auth logs.
3. **Agent framework artefacts on hosts** (`sigma/agent-framework-execution.yml`, `hunt/`). Hermes, OpenClaw, `uv`/`uvx` spawning MCP servers, agent config directories appearing where no developer works.
4. **Authorization assertions at the LLM gateway** (`sigma/llm-authorization-assertion.yml`). If you proxy your own model traffic, prompts asserting "authorized penetration test", "red team engagement" or "you have permission to" are directly observable. This is the actual bypass used, and it is only visible if you sit in the path.

## What you cannot detect here

Say this to your stakeholders before they assume coverage.

- **There are no indicators of compromise in this pack.** None were published. Anyone selling you IOCs for this campaign is guessing.
- **The bypass itself is invisible to your network sensors.** It happened inside a prompt, between the operator and a model provider. Unless you operate the gateway, you will never see it.
- **Valid-credential activity looks valid.** Once the agents were using the 85 compromised accounts, the authentication succeeded. Tempo and breadth analysis is what catches that phase, not credential-failure alerting.
- **Open-source frameworks are not malware.** Hermes and OpenClaw are legitimate, widely used, and present in many normal environments including ours. Detecting them tells you an agent is present, not that an intrusion is happening. Every rule here that keys on a framework is a *hunting* rule, not an alert, and is marked as such.
- **A competent operator can flatten the tempo signature** by inserting jitter and refusing to parallelise. Doing so costs them most of the speed advantage that made the campaign notable, which is the point, but do not treat tempo detection as unevadable.
- **Model choice is irrelevant to all of this.** Nothing here depends on which provider or model was used, and rules that key on provider domains will miss a self-hosted model entirely. See the limitations section.

## Limitations

Self-hosted inference defeats the egress rules completely. An operator running a local model on their own infrastructure produces no third-party API traffic at all, and the only remaining signals are tempo, breadth, and host artefacts. Given the direction of open-weight model quality, assume this becomes the common case and weight your detection investment accordingly.

The tempo thresholds in these rules are starting points derived from published inference latencies, not from telemetry of this campaign, which was not released. **Tune them against your own baseline before enabling anything as an alert.** Every rule ships as `status: experimental` for that reason.

## What was actually validated

Honest accounting, because the sibling repository sets that precedent.

- Rule syntax was validated: Sigma against the schema, YARA compiled, Suricata rules parsed.
- **No rule in this pack has been tested against telemetry from the actual campaign**, because none is public.
- The tempo model was reasoned from first principles about inference latency and planner behaviour, then sanity-checked against locally generated agent traffic. It has **not** been validated against a real intrusion.
- The framework artefact paths were verified against genuine Hermes and OpenClaw installations.

Treat the whole pack as a well-argued hypothesis to tune, not as a finished product.

## Scope and intent

Defensive. These rules detect intrusion activity; nothing here assists in conducting one. No offensive tooling, no exploit code, no attack automation.

## Sources

- Dream, via the Financial Times, 12 August 2026
- Security Affairs, "China-Linked Hackers Use AI Agents in Autonomous Attack on Taiwan"
- The Register, "Near-autonomous AI agents attack Taiwan's nuclear safety agency"
- Reuters via US News, "Taiwan Says It Was Targeted Last Month in AI-Driven Hacking Campaign"
- CNN Business, "Hackers used autonomous AI agents to attack Taiwan"

## AI disclosure

Written with AI assistance. The tempo model, the rule logic, and the limitations above were authored and reviewed by a human, and the "what you cannot detect" section exists specifically because generated detection content tends to overstate coverage.

## License

Apache-2.0. See [LICENSE](LICENSE).
