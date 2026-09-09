# The Coordination Substrate: A Detection Engineering Analysis of the September 2026 Unit 42 Agentic Intrusion, and Why Provider-Egress Detection Fails Against Borrowed Inference

**Cristian Ruvalcaba and the Saluca Agentic AI Research Team, Saluca LLC**

Version 1.0 - 8 September 2026 - current to 8 September 2026

Fourth in the consolidated detection engineering series. Direct successor to *Agentic Intrusion*
(concept DOI 10.5281/zenodo.22033405), whose Tier 1 claims this paper tests and, in one respect,
narrows.

---

## Scope and provenance

Built from Unit 42's public account of an AI-assisted intrusion, published 2 September 2026, and
re-read against Dream's account of the July 2026 campaign against Taiwanese government and energy
targets. Contemporaneous reporting is used only for facts the primary accounts do not carry, and is
labelled where it appears.

We had no victim telemetry, no samples, no forensic artifacts, and no contact with either affected
organisation. Nothing was reproduced and nothing was detonated. No rule in the companion package has
been executed against telemetry from either incident, because none is public.

ATT&CK and ATLAS mappings are our inference from described behaviour. Neither source supplied one.

**The correction this paper carries.** *Agentic Intrusion* shipped provider-egress detection as
Tier 1, on the argument that an agent must reach an inference endpoint on every planning step. That
argument holds. Section 5 shows a phase of the Unit 42 intrusion in which it produces silence, for a
reason we anticipated in outline and mis-specified in mechanism.

---

## 1. The defender question nobody is answering

Three weeks after we published a tempo model for agent-driven intrusion, an independent investigator
published hunt guidance naming the same signals, and described a phase of the same class of
intrusion that defeats the other half of what we shipped.

Two questions follow, and the coverage of this incident answers neither:

> **When two teams independently propose the same detection primitives and neither has measured
> them, what has actually been established?**

> **What do multi-agent intrusions leave behind that survives the operator changing model, provider,
> framework and infrastructure?**

The first is a question about evidence, and getting it wrong inflates confidence across the whole
discipline. The second has an answer that is visible in both published corpora and has not, as far
as we can find, been named.

---

## 2. The incident

Unit 42 investigated an intrusion at an enterprise running cloud infrastructure and its own AI
services. The motive was ransom. No actor attribution was offered and we offer none.

**Roughly ten hours of operational activity, spanning more than fifty MITRE ATT&CK techniques**,
against an estimated two weeks for an equivalent human operation.

The described chain:

| Stage | What happened |
|---|---|
| Infiltration and mapping | Breach of a publicly reachable web service, then an automated reconnaissance agent mapping the microservice estate |
| Secrets harvesting | Sub-agents extracting hardcoded tokens and passwords from code repositories |
| Privilege takeover | Compromise of the secrets management system, yielding root administrative credentials |
| Pipeline exploitation | CI/CD hijack, with an attempted Terraform backdoor blocked by branch protection |
| AI infrastructure hijack | Stolen cloud keys used to repurpose the victim's own AI endpoints as post-compromise infrastructure |

Unit 42 separates what it observed from what it assessed, and the distinction is load-bearing for
sections 3 and 4, so it is preserved here.

**Observed.** LLM calls to multiple frontier AI agents in parallel. Structured Markdown files
passing information between agents and sessions. Python caches. Paired asset folders. Markdown
formatted outputs. An eighty-page technical audit of the victim's security findings, left behind.

**Assessed.** Custom scripts judged with high confidence to be AI-generated, on the basis of their
UI elements.

**Recommended for hunting, and not presented as measured.** Bursty API requests, rapid 401 to 200
HTTP state shifts, parallel authentications, and sudden model usage from unexpected identities.

---

## 3. Convergence is not confirmation

*Agentic Intrusion* argued that agent-driven activity produces a bimodal rhythm: machine-speed
action bursts separated by inference-latency pauses, with technique change following failure. It
listed as its first falsification condition that agent-driven and script-driven intrusions might
prove indistinguishable on that joint distribution in real telemetry.

Unit 42's hunt guidance names bursty API requests, parallel authentications from unexpected
identities, and sudden model usage. That is recognisably the same shape, arrived at independently,
from a different incident, with a different victim and a different motive.

It is tempting to read that as corroboration. It is not, and the reason is worth stating precisely
because the error is about to become common.

**Unit 42 published no interval data, no request rates, no timestamps and no latency measurements.**
Their list is guidance about where to look. Ours is a model reasoned from published inference
latencies. Neither is a measurement. Two teams reasoning from the same structural facts about how
inference-driven planning works will reach the same primitives, and their agreement is evidence that
the reasoning is unremarkable, not that the detection fires on real activity at a usable rate.

What the convergence does establish is modest and real: the inference from architecture to rhythm is
obvious enough that two groups made it independently, which slightly raises the prior that it is
correct. What it does not establish is any of the things a practitioner needs, namely the threshold,
the base rate, or the false-positive cost in a production estate.

**The compounding hazard.** A third party citing both sources will count two independent
confirmations of a tempo signature. There are zero. If this paper contributes nothing else, it
should contribute that sentence, because the failure mode is the discipline convincing itself that a
plausible model is a validated one by circulating it.

Falsification condition 1 from *Agentic Intrusion* is therefore **still open**. We would rather say
that than accept a corroboration we did not earn.

---

## 4. The coordination substrate

This section is the contribution.

### 4.1 The overlap between the two corpora is not a technique

Set the two published corpora side by side and remove everything that is specific to one.

| | Taiwan, July 2026 (Dream) | Enterprise, ~September 2026 (Unit 42) |
|---|---|---|
| Operator | unattributed, Chinese-language artifacts | unattributed |
| Motive | espionage | ransom |
| Victim | government, then a nuclear safety regulator and energy firms | enterprise with cloud and AI services |
| Duration | four days, twelve waves | under ten hours |
| Frameworks | Hermes and OpenClaw, open source | unnamed frontier agents plus agentic frameworks |
| Shared indicator | none | none |
| **Shared artifact class** | **1,395 files in a 160 MB workspace; `.hermes` and `.openclaw` workspace directories; sub-agents lettered A through Q; structured after-action reporting between waves; recorded posterior scoring of findings** | **structured Markdown files passing information between agents and sessions; paired asset folders; Python caches; an eighty-page technical audit** |

Nothing in the top half of that table matches. The bottom row does, and it matches closely: in both
incidents, the orchestration produced a body of structured, cross-referencing state files as a
by-product of running.

### 4.2 Why it is a property of the architecture rather than a choice

A single agent needs no coordination artifacts. Its state is its context window.

Several agents do, and the reason is mechanical:

- **Context windows are finite and metered.** Multi-agent designs exist to partition work that will
  not fit, or will not fit affordably, into one window. Partitioning the work partitions the state.
- **Sub-agents are separate processes, frequently separate sessions.** The only channel between two
  processes that survives the end of one of them is storage.
- **Planners that re-rank need the prior evidence.** Re-sending the full history on every call
  reintroduces exactly the cost the architecture was adopted to avoid, so the evidence is written
  down and referenced.

Every one of those pressures points the same way. An operator can change model, provider, framework,
infrastructure and technique for free, and still has to put the shared state somewhere the next
agent can read it.

That is the same form of argument *Agentic Intrusion* made for tempo. The difference, and the reason
this paper leads with the substrate rather than the rhythm, is that **the substrate has been observed
twice and the rhythm has been measured zero times.**

### 4.3 What the signal actually is, stated narrowly

It is not "Markdown files" and it is not "`__pycache__`". Both are ubiquitous and a rule keyed on
either is noise.

The signal is the **conjunction**: structured state files, created at machine cadence, by a
non-interactive process, on a host with no developer workflow, cross-referencing each other, in the
same window as authentication or reconnaissance activity. Any one element is ordinary. The
combination describes a program writing notes to itself faster than a person could read them, on a
machine where nobody writes notes.

### 4.4 The vantage problem applies, and halves the reach

*Asserted Egress* (concept DOI 10.5281/zenodo.22314504) named the vantage problem: an incident can be
richly indicated on one side of a boundary and structurally invisible on the other. It applies here
and it constrains this contribution more than we would like.

In the Unit 42 case the agents ran **inside the victim estate**, so the substrate landed on victim
hosts and is a defender-visible artifact.

In the Taiwan case the workspace was on the **operator's** infrastructure. It became available to
researchers because the operator exposed a 160 MB archive to the internet, not because a defender
found it. A Taiwanese defender saw authentication activity and nothing else.

So the substrate is detectable exactly when the operator runs agents on your machines. When they run
them on their own and reach you through ordinary protocols, you see none of it. Roughly half the
published corpus is out of reach of every rule in section 6's Tier 1 first entry, and any pack that
does not say so is selling coverage it does not have.

---

## 5. Borrowed inference

The second contribution, and it is a correction to our own August package.

### 5.1 The blind spot

*Agentic Intrusion* shipped two provider-egress rules as its highest-value, lowest-cost control: a
server or service context resolving a public model provider, and inference egress from a restricted
network zone. The reasoning was that the agent must call an inference endpoint on every planning
step, and that this is a structural consequence of the method rather than an operator choice.

Unit 42's fifth stage is the case where that produces nothing. Stolen cloud keys were used to
repurpose **the victim's own AI endpoints** as post-compromise infrastructure. In that configuration:

- the destination is inside the victim's own tenancy, not a public provider;
- it is allowlisted by construction, because the victim runs AI services deliberately;
- the traffic need not cross the perimeter the proxy rule watches;
- the credential is valid, so nothing fails.

Both August rules fail to silence. Not to a false negative that a tuned threshold recovers: to
silence, because the destination they key on is never contacted.

### 5.2 What we got right, and what we got wrong

The August package's limitations section says that self-hosted inference "defeats the egress rules
completely", and predicts this becoming the common case as open-weight model quality improves.

The failure mode was right. The mechanism was wrong, and the timeline was wrong. It did not arrive
through operators hosting their own models. It arrived through operators **using the victim's**, and
it arrived in the next disclosed incident rather than in some later era of open weights.

The general lesson is worth more than the specific rule: a detection keyed on a **destination** fails
whenever the attacker acquires a legitimate instance of that destination. Keying on **identity**
does not have that failure mode.

### 5.3 The structural cause, named

**Borrowed inference:** an attacker who compromises an estate that operates AI workloads inherits its
inference capability along with its data and its compute, and that inference is indistinguishable
from the estate's own by every network-layer control the estate owns.

It is the same shape as stolen cloud credentials used for cryptomining, with one difference that
matters for detection: mining is an anomalous workload on general compute, while borrowed inference
is the **expected** workload on the exact service built to serve it. It looks like the product
working.

It generalises past language models to any metered capability an estate exposes to itself: managed
inference, transcription, translation, OCR, rendering farms. Wherever an organisation has paid to
make a capability easy to call from inside, an intruder inside gets it at the same price.

---

## 6. Detection, ranked by durability

Ranked by what survives an operator changing things, not by ease of deployment. Full rules, with
false positives and tuning notes, are in the companion package.

### Tier 1: survives model, provider, framework and infrastructure change

**1. Model endpoint invoked by a principal with no invocation history.** The borrowed-inference
control, and the highest-value new rule in this pack. Cloud model-invocation logs carry the calling
principal. The question is not whether a host talked to a model provider but whether **this identity
has ever invoked this endpoint before**, and whether its rate changed by an order of magnitude. A
service principal whose job is document processing calling an inference endpoint for the first time,
at volume, is the whole finding. Immune to provider choice, framework choice and network position,
because it is asked in the control plane.

**2. Coordination artifacts created at machine cadence by a non-interactive process.** Section 4.3's
conjunction, expressed against file-creation telemetry. A **hunting** rule, not an alert, and
vantage-limited per section 4.4. Its value is that it fires during the operation rather than at
staging, and that it is the one artifact class observed in both published corpora.

### Tier 2: durable, requires baselining before it is enabled

**3. Failed-to-successful authentication transition rate, joined to session parallelism.** Unit 42
names the 401 to 200 shift. On its own it is a credential-spray signal that any brute-force detection
already carries. What separates an agent swarm from a spray tool is the **join**: multiple concurrent
sessions on the same credential performing *different* actions. Spray tools repeat one action widely;
agents divide work. The parallelism join is ours; the transition rate is Unit 42's.

**4. Step change in model invocation volume per principal.** Cheap, and it catches borrowed inference
where rule 1's history baseline is unavailable because the principal is new.

### Tier 3: useful, decays quickly

**5. AI-generated tooling heuristics.** Unit 42 assessed scripts as AI-generated from their UI
elements. We are not building alerting on that and we advise against it. Stylistic tells are the
least durable signal in this paper: they are free to remove, they are already being removed, and a
false positive lands on your own developers. Recorded because it appears in the source, ranked last
because it should be.

---

## 7. What this class makes undetectable

- **The substrate is invisible when the agents run elsewhere.** Section 4.4. Taiwan is that case.
- **Both corpora exist because of operator error.** A 160 MB exposed archive and an eighty-page audit
  left on a victim host. Neither is a control. Do not build a program on the assumption that the next
  operator is as untidy.
- **Borrowed inference is invisible without model-invocation logging**, which is off by default or
  absent in many tenancies, and is frequently retained for days rather than months.
- **Tempo remains unmeasured**, by us and by Unit 42. Section 3.
- **The bypass, wherever one occurs, happens inside a prompt.** Unchanged from the August paper:
  unless you operate the gateway, that exchange is not yours to see.
- **Ten hours is inside most detection and response cycles.** A control that fires correctly on day
  two is a post-mortem input, not a defence.

---

## 8. What actually found it

Fourth consecutive paper in this series, and the answer is again not the defender's detection stack.

| Incident | What found it |
|---|---|
| Hugging Face, July 2026 | the victim, and a competitor's public disclosure |
| Taiwan, July 2026 | researchers finding an exposed operator archive |
| Wiki collusion, May to July 2026 | a volunteer moderator reading an edit log |
| This incident, September 2026 | incident response after the fact, materially assisted by an audit the attacker left behind |

Four incidents, four detections, none of them a rule that fired. This section is short and
unflattering on purpose, and it is the most consistent finding in the series.

---

## 9. Credit

Unit 42 published hunt guidance rather than a capability advertisement, and separated what they
observed from what they assessed with confidence. That separation is the entire basis of section 3.
Had they presented their hunt list as measurement, we would have read it as corroboration and been
wrong. Careful epistemic labelling in a vendor writeup is rarer than it should be and it did real
work here.

The same applies to Dream, whose account qualified its own headline: near-autonomous rather than
autonomous, with an explicit note that building the system took more than running a model.

---

## 10. Limitations

**No telemetry, no samples, no victim contact.** Every technical claim traces to a published account.

**Unit 42's writeup is a summary.** A fuller technical report may contradict specifics here. This
paper is current to 8 September 2026 and should be re-read against any subsequent publication.

**n equals two, and both are selected.** The two corpora are what two vendors chose to publish.
Multi-agent intrusions that were never noticed, or noticed and not disclosed, are unmeasurable by
construction, and there is no reason to think the disclosed ones are representative.

**The substrate argument is architectural, not empirical.** Section 4.2 reasons from how multi-agent
systems must work. It predicts the artifact class rather than being derived from a survey of it.
Section 11 states what would break it.

**Mappings are inferred.** Neither source supplied ATT&CK or ATLAS mappings.

**Nothing was executed against real telemetry.** Sigma is schema-validated, KQL and SPL are authored
and not run. The companion package states this per format.

---

## 11. What would falsify this

1. **If coordination state moves in-band** - agents exchanging state through a command channel, a
   provider's own session storage, or a shared context service rather than the filesystem - the
   substrate stops touching disk and section 4 describes a transitional artifact. This costs the
   operator very little and we consider it the most likely of the four.
2. **If structured state files plus interpreter caches prove indistinguishable from ordinary
   developer and CI activity** at production scale, Tier 1 rule 2 is noise regardless of the
   architecture argument.
3. **If model-invocation logging is unavailable or unaffordable in most estates**, Tier 1 rule 1 is
   uninstrumentable even if it is correct, which would leave this paper with no deployable Tier 1 at
   all.
4. **If a third corpus shows multi-agent intrusion with no persistent shared state**, the pressures
   in section 4.2 are not as binding as claimed and the substrate is an implementation habit rather
   than a property.

---

## 12. What we are not claiming

**Not that Unit 42 confirmed our tempo model.** They tested nothing and neither did we. Section 3
exists to prevent that reading.

**Not attribution, for either incident.** Unit 42 offered none. Dream declined to name a group.

**Not that these are the same operator.** Different motive, different victim class, different
duration, no shared indicator. The shared artifact class is evidence about architecture, not about
people.

**Not that running AI services is unsafe.** Borrowed inference is a consequence of holding a valuable
metered capability, in the same way that holding compute invites mining. The mitigation is
per-principal authorization and invocation logging, not the absence of the service.

**Not that the August package was wrong.** Its egress rules work against the case they describe, and
that case is the majority of what has been reported. They have a blind spot, now named, and the
correct response is an additional identity-keyed control rather than a retraction.

**Not that ten hours is the floor.** It is the fastest published, which is not the same thing.

---

## 13. AI disclosure

Prepared with AI assistance (Anthropic Claude) inside the author's research harness. The coordination
substrate synthesis, the borrowed inference naming, the convergence argument in section 3, the
durability rankings, the falsification criteria, and sections 7 through 12 were authored and reviewed
by the named human author, who is solely responsible for the claims. The limitations and non-claims
sections were written before the rules rather than after, because AI-assisted detection content tends
to overstate coverage, and section 3 exists specifically because the convenient reading of the
evidence was the wrong one.

---

## References

- Unit 42, Palo Alto Networks. *An AI-Assisted Cyber Attack: Inside a Unit 42 Investigation.*
  2 September 2026.
- Dream. *Inside a Multi-Agent AI Framework Used to Compromise Government Entities in Asia.*
  August 2026.
- Saluca Labs. *Agentic Intrusion: A Detection Engineering Analysis of the July 2026 Taiwan Campaign,
  and a Tempo Model for Agent-Driven Attacks.* Concept DOI 10.5281/zenodo.22033405.
- Saluca Labs. *Asserted Egress: A Detection Engineering Analysis of the May to July 2026 Agent Wiki
  Collusion, and the Vantage Problem in Containment Monitoring.* Concept DOI
  10.5281/zenodo.22314504.
- Saluca Labs. *Detection Without Indicators: Agent-Originated Intrusion.* Concept DOI
  10.5281/zenodo.21770780.
- Companion detection content: https://github.com/saluca-labs/detection-content, Apache-2.0.

Report text CC-BY-4.0. Detection content and tooling Apache-2.0. Defensive use only.
