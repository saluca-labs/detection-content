# Coordination Substrate

Detection content for **multi-agent intrusion seen from inside the victim estate**, written after
Unit 42's 2 September 2026 account of an AI-assisted intrusion that ended with the attacker
repurposing the victim's own AI endpoints.

Defensive only. Apache-2.0. Part of [saluca-labs/detection-content](https://github.com/saluca-labs/detection-content).

**Paper:** [The Coordination Substrate: A Detection Engineering Analysis of the September 2026 Unit 42 Agentic Intrusion, and Why Provider-Egress Detection Fails Against Borrowed Inference](https://doi.org/10.5281/zenodo.22678061) - [![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22678061.svg)](https://doi.org/10.5281/zenodo.22678061)
Local copies: [`coordination-substrate-v1.0.pdf`](coordination-substrate-v1.0.pdf) - [`.md`](coordination-substrate-v1.0.md)
**Predecessor:** [Agentic Intrusion](../2026-08-agentic-intrusion/) - [10.5281/zenodo.22033405](https://doi.org/10.5281/zenodo.22033405)

---

## The short version

Unit 42 investigated an intrusion at an enterprise running cloud infrastructure and its own AI
services. Ransom motive, no attribution offered. **Roughly ten hours, more than fifty ATT&CK
techniques**, against an estimated two weeks for an equivalent human operation. Web service breach,
then automated microservice mapping, then sub-agents harvesting hardcoded credentials, then the
secrets manager, then a CI/CD hijack with an attempted Terraform backdoor that branch protection
blocked. Then the part this pack exists for: **stolen cloud keys used to repurpose the victim's own
AI endpoints as post-compromise infrastructure.**

Two ideas come out of it, one new and one a correction to our own August pack.

## 1. The coordination substrate

A single agent needs no coordination artifacts, because its state is its context window. Several
agents do, because they do not share one. State that has to cross a process or session boundary gets
written down.

Set the two published corpora side by side and nothing matches. Different operator, different victim,
different motive, different continent, disclosed three weeks apart, no shared indicator of any kind.
Except this:

| Taiwan, July 2026 (Dream) | Enterprise, September 2026 (Unit 42) |
|---|---|
| 1,395 files in a 160 MB workspace, `.hermes` and `.openclaw` directories, sub-agents lettered A through Q, structured after-action reporting between twelve waves | structured Markdown files passing information between agents and sessions, paired asset folders, Python caches, an 80-page technical audit |

The orchestration wrote itself down, in both cases, as a by-product of running. That is a consequence
of the architecture rather than a choice: context windows are finite and metered, sub-agents are
separate processes, and a planner that re-ranks needs the prior evidence without paying to resend it
every call. An operator can change model, provider, framework and infrastructure for free and still
has to put the shared state somewhere the next agent can read it.

**The signal is the conjunction, never the file type.** Markdown files and `__pycache__` are
everywhere. What is not everywhere is a service-context process writing dozens of structured,
cross-referencing state files in minutes, on a host where nobody develops, in the same window as
authentication activity.

## 2. Borrowed inference, and a correction to our August pack

The [August pack](../2026-08-agentic-intrusion/) shipped provider-egress as its highest-value
control: a server or restricted zone reaching `api.openai.com`, `api.anthropic.com` and friends. That
rule is correct and **it produces silence against this incident**, because the destination was inside
the victim's own tenancy, allowlisted by construction, reached with a valid credential, and possibly
never crossing the monitored perimeter at all.

We predicted this failure mode in the August limitations and got the mechanism wrong. We expected it
to arrive through operators self-hosting open-weight models. It arrived in the very next disclosed
incident, through operators using **the victim's**.

**Borrowed inference:** an attacker who compromises an estate operating AI workloads inherits its
inference capability along with its data and its compute, and that inference is indistinguishable
from the estate's own by every network-layer control the estate owns. It is the same shape as stolen
cloud credentials used for mining, with one difference that matters for detection. Mining is an
anomalous workload on general compute. Borrowed inference is the *expected* workload on the exact
service built to serve it. It looks like the product working.

The transferable lesson is larger than the rule: **a detection keyed on a destination fails the
moment the attacker acquires a legitimate instance of that destination.** Keying on identity does not
have that failure mode.

## Deploy these first

1. **First-ever inference call by a principal** (`splunk` search 1, `kql` query 1, `sigma/borrowed-inference.yml`).
   The borrowed-inference control and the highest-value rule here. Asked in the control plane, so it
   is indifferent to provider, framework, model and network position. Run the baseline search first;
   without it, everything looks novel.
2. **Inference volume step change per principal** (`splunk` 2, `kql` 2). Catches the compromised
   identity that already calls the endpoint legitimately, which rule 1 misses by construction.
3. **Bulk secret read into first inference call** (`splunk` 3, `kql` 3, `sigma`). The privilege phase
   into the resource-abuse phase, in one query.
4. **Parallel sessions with divergent actions** (`splunk` 4, `kql` 5). Unit 42 names the 401 to 200
   transition; the parallelism join is what separates an agent swarm from a spray tool. Spray repeats
   one action widely, agents divide the work.

The coordination-substrate rules are deliberately **not** in that list. They are hunting content and
they are vantage-limited. See below.

## What you cannot detect here

Say all of this to your stakeholders before they assume coverage.

- **There are no indicators of compromise in this pack.** No hashes, IPs, domains or file names were
  published. The first row of `iocs/indicators.csv` says so.
- **The substrate is invisible when the agents run somewhere else.** Every substrate rule here
  assumes the agents executed on your hosts, which is the Unit 42 case. In the Taiwan case they ran
  on the operator's infrastructure and a defender saw authentication activity and nothing else.
  **Roughly half the published corpus is out of reach of these rules**, and a pack that does not say
  so is selling coverage it does not have.
- **Borrowed inference is invisible without model-invocation logging.** Azure OpenAI diagnostic logs,
  Bedrock model invocation logging and Vertex AI audit logs are off or partial by default in most
  tenancies, and are often retained for days rather than months. This is the single most consequential
  prerequisite in the pack. If it is not on, the Tier 1 control is inert.
- **Both corpora exist because of operator error.** A 160 MB archive exposed to the internet, and an
  80-page audit left on a victim host. Neither is a control. Do not plan on the next operator being
  as untidy.
- **Ten hours is inside most detection and response cycles.** A control that fires correctly on day
  two is a post-mortem input, not a defence.
- **Tempo is still unmeasured.** By us, and by Unit 42. See the next section, which is the one we
  would most like read.

## Convergence is not confirmation

Our August pack published a tempo model: machine-speed bursts separated by inference-latency pauses,
with technique change after failure. Thirteen days later Unit 42 recommended hunting for "bursty API
requests, rapid 401/200 HTTP state shifts, parallel authentications and sudden model usage from
unexpected identities."

That is recognisably the same shape, reached independently, from a different incident. It is tempting
to call it corroboration.

**It is not.** Unit 42 published no interval data, no request rates, no timestamps and no latency
measurements. Their list is guidance about where to look; ours is a model reasoned from published
inference latencies. Neither is a measurement. Two teams reasoning from the same structural facts
will reach the same primitives, and their agreement is evidence that the inference is unremarkable,
not that the detection fires at a usable rate on real activity.

The compounding hazard is the reason this is in the README and not buried in the paper: **a third
party citing both sources will count two independent confirmations of a tempo signature. There are
zero.** Falsification condition 1 from the August paper is still open, and we would rather say that
than accept a corroboration we did not earn.

## Limitations

Every threshold here is a starting point, not a measurement: the 40-file burst, the 10x volume
multiple, the 5-failure transition floor. No telemetry from either incident is public. Baseline
against your own estate before enabling anything as an alert. Every rule ships `status: experimental`
for that reason.

The substrate argument is architectural. It reasons from how multi-agent systems must work and
predicts the artifact class, rather than being derived from a survey of one. The paper states the
four conditions that would falsify it; the most likely by far is coordination state moving in-band,
which costs an operator very little.

n equals two, and both corpora are what two vendors chose to publish.

## What was actually validated

- Sigma parses and validates against the schema; rule ids are UUIDs and unique across the repository.
- Indicator CSV parses and carries the house schema.
- **No rule in this pack has been executed against telemetry from either incident**, because none is
  public.
- **KQL and SPL are authored and not executed.** There is no tenant and no index behind them. Table
  names, column names and sourcetypes follow the documented schemas but have not been run. Expect to
  fix at least one field name per query.
- The framework workspace paths were checked against genuine Hermes and OpenClaw installations.

Treat the pack as a well-argued hypothesis to tune, not as a finished product.

## What actually found it

Fourth consecutive campaign in this series where the answer is not the defender's detection stack.
Incident response after the fact, materially assisted by an audit the attacker left behind. Taiwan:
researchers finding an exposed operator archive. The wiki collusion: a volunteer moderator reading an
edit log. Hugging Face: the victim, and a competitor's disclosure.

Four incidents, four detections, none of them a rule that fired.

## Credit

Unit 42 published hunt guidance rather than a capability advertisement, and separated what they
observed from what they assessed with confidence. That separation is the entire basis of the
convergence section above: had they presented their hunt list as measurement, we would have read it
as corroboration and been wrong.

## Sources

- Unit 42, Palo Alto Networks, *An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation*, 2 September 2026
- Dream, *Inside a Multi-Agent AI Framework Used to Compromise Government Entities in Asia*, August 2026

## Scope and intent

Defensive. These rules detect intrusion activity; nothing here assists in conducting one. No
offensive tooling, no exploit code, no attack automation.

## AI disclosure

Written with AI assistance. The coordination substrate synthesis, the borrowed inference naming, the
convergence argument, the rule logic and the limitations were authored and reviewed by a human. The
"what you cannot detect here" section was written before the rules, because generated detection
content tends to overstate coverage, and the convergence section exists specifically because the
convenient reading of the evidence was the wrong one.

## License

Apache-2.0. See [LICENSE](../../LICENSE).
