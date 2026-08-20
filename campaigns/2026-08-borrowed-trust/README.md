# Borrowed Trust

**Detection content for three concurrent campaigns that share one execution primitive.**

Current to **2026-08-10**. Defensive material only.

---

## The short version

In the first days of August 2026, three separate stories about malicious VPN software were
circulating at once. They read like three problems. They are close to one.

| | Campaign | Delivery | Payload | Disclosed |
|---|---|---|---|---|
| **A** | ~292 brand-impersonation GitHub repositories | repo README -> `*.github.io` redirector -> padded ZIP | BoryptGrab-lineage infostealer | Arctic Wolf, July 2026 |
| **B** | QuickFox VPN | the vendor's own Windows installer | FDMTP implant | Fortinet, 2026-08-05 |
| **C** | "Free VPN for PC" GitHub repository | `Launch.exe` dropper | Lumma Stealer | CYFIRMA, ~Oct 2025 |

In all three, **the binary that executes is legitimate and the malicious code arrives as
something that binary resolves at runtime.**

- **A** ships a legitimate, signed copy of the WinGUP updater (`gup.exe`, the generic update
  component used by Notepad++) renamed to whatever vendor is being impersonated, next to a
  trojanized `libcurl.dll`. Arctic Wolf: *"When the user runs the executable, gup.exe
  side-loads libcurl.dll, which decodes and reflectively executes an embedded infostealer
  entirely in memory."* The report describes the updater as legitimate and signed but does not
  name the signer, so neither do we.
- **B** is the vendor's real installer, correctly signed, that happened to carry two extra lines
  of JavaScript in its Electron renderer. Later generations sideload through `csmonitor.exe`,
  a legitimate Microsoft Azure emulator binary, loading `Microsoft.ServiceHosting.Tools.dll`.
- **C** masquerades its payload as `msvcp110.dll`, a Visual C++ runtime name, then injects into
  `MSBuild.exe` and `aspnet_regiis.exe`, two signed Microsoft utilities.

The trust is real in every case. It is attached to the wrong thing. Signing authenticates the
container; it says nothing about what the container loads after it starts. Platform reputation
does the same at the other end: a `github.io` redirect means GitHub served a redirect, not that
GitHub vouched for the destination.

We call the pattern **borrowed trust**, and it is why one rule shape catches all three.

**Where the synthesis is weaker, stated plainly.** A and B are clean instances: the process that
executes is a legitimate signed binary and the malicious code is a dependency it resolves. C is
not. Its first stage, `Launch.exe`, is attacker-authored and carries no borrowed trust at all;
the pattern only appears at the second stage, where the payload takes a Visual C++ runtime
filename and then injects into signed Microsoft utilities. So C belongs to the family by its
later behaviour, not its delivery. Anyone using this framing should apply it to A and B first
and treat C as the partial case. Overstating that would make the argument tidier and worse.

## What this repository contains

```
detections/
  sigma/      22 rules across three campaign files, plus a validator
  yara/       12 rules, plus a compile-and-false-positive validator
  kql/        15 Defender XDR / Sentinel advanced hunting queries
  splunk/     16 Sysmon-based searches, plus lookup table definitions
  suricata/   24 network rules, SID 1000001-1000060
hunt/
  Invoke-BorrowedTrustSweep.ps1            read-only host sweep for all three campaigns
  Invoke-DevToolchainExposureReview.ps1    read-only review of npm install scripts and
                                           editor run-on-open hooks
iocs/
  indicators.csv                           every published indicator, one row each, sourced
```

Nothing here executes a payload, reproduces one, or explains how to build one. The hunt scripts
read the filesystem, registry, DNS cache, and process list, and write a JSON report. They do not
delete, quarantine, modify, or terminate anything.

## Deploy these four first

Everything else in here decays. BoryptGrab rebuilds its archive roughly every sixty seconds and
had around 78 redirector accounts live simultaneously, so its hashes were stale before the report
publishing them was finished. These four key on the structure of the attack rather than its
current infrastructure:

1. **`libcurl.dll` loading from a user-writable path.** Legitimate software ships it inside its
   own install directory. It has no business loading out of Downloads.
   `detections/sigma/boryptgrab-fake-github-repos.yml`, KQL Q2, SPL S2.
2. **Any process whose `OriginalFileName` is `gup.exe` running under a different name.** The
   version resource survives the rename, and no legitimate deployment does this.
   Same file, KQL Q3, SPL S3.
3. **`protocol=DotNet-TcpFDMTP` anywhere in a URI.** The endpoint name rotates across seven
   variants and the staging domains rotate faster; the protocol identifier does not.
   `detections/sigma/quickfox-fdmtp-supply-chain.yml`, Suricata 1000020, KQL Q10, SPL S10.
4. **An archive fetched with a `.github.io` referrer from a host that is not GitHub.** This is
   the lure shape itself, independent of any domain in the IOC list.
   Suricata 1000008, KQL Q13, SPL S14.

Two further notes on deployment. Block `193.143.1.0/24` rather than the single C2 address: the
same Proton66 netblock held an earlier BoryptGrab C2 at `.104` and the current one at `.131`.
And widen the lookback for the QuickFox rules to your retention limit, not the 90 days most of
these queries default to, because that installer carried the backdoor for roughly a year.

Two rules need tuning before you enable them. The IME registry rule
(`6730b546-546a-47d4-b69d-065a44192a3e`) needs a baseline against a known-good image, because
third-party input method editors write there legitimately. The FDMTP port-range rule will hit
custom internal services unless you scope it to non-RFC1918 destinations. The `.sbs` TLD Suricata
rule is deliberately shipped as a hunt, not an alert.

## What you cannot detect here

This section is the point of the package, and it is short on purpose.

**Hash coverage is theatre for campaign A.** The archive is regenerated per request. Every hash
in `iocs/indicators.csv` is a record of one download by one researcher at one moment. Shipping
them is honest bookkeeping, not a control.

**Signature-based allowlisting fails by construction.** The executable in campaign A is
genuinely signed by the Notepad++ project. In campaign B it is signed by the VPN vendor. An
allowlist keyed on valid signatures admits both. This is not a defect in anyone's signing
process; it is what signing means.

**A clean sweep is weak evidence for campaign A.** BoryptGrab installs no persistence at all: no
Run keys, no scheduled tasks, no service. It executes once, collects, exfiltrates, and is gone.
An endpoint that ran it in July and has since rebooted looks identical to one that never saw it,
apart from the staging directory it neglects to clean up. If that directory was cleared, there is
nothing left to find.

**A clean sweep is weak evidence for campaign B for the opposite reason.** The loader only
proceeds when at least one of 26 specific applications is running, and aborts outright if
`steam.exe` is present. An endpoint with the trojanized installer that never met the criteria was
never implanted, and so carries no artifacts, while remaining fully exposed to the next
generation of the same loader. Inventory the installed version; do not infer safety from a
quiet host.

**None of these were caught by endpoint detection.** Campaign B ran for approximately a year
inside a signed vendor installer before a vendor research team found it. Campaign A was
identified because it impersonated a security company that happened to look. Campaign C surfaced
through a research writeup, not a victim's alerting. In all three the discovery path ran through
someone doing threat research, not through a defender's own stack firing. That is unflattering to
the discipline and it is the most important line in this file.

## Limitations

- **No victim forensic artifacts.** Everything here is built from published vendor research. We
  detonated nothing and had access to no incident data.
- **Two of the three campaigns were not independently verified by us.** The indicators are
  reproduced from the vendors' published reports and attributed per row in `indicators.csv`.
- **The one campaign we could test against, we tested against nothing.** The host sweep was run
  on a clean machine, so it has demonstrated that it completes and reports cleanly. It has not
  demonstrated that it catches a live infection.
- **MITRE ATT&CK technique mappings in the Sigma rules are inferred.** None of the three source
  reports supplied a mapping. They are labelled in the rule tags and should be treated as our
  reading, not the researchers'.
- **Attribution is an assessment, not an adjudicated fact.** FDMTP has been associated with
  Mustang Panda by prior reporting; campaign A's operator is assessed as Russian-speaking and
  financially motivated on the basis of code comments, commit metadata, and infrastructure. We
  are repeating other people's assessments, not making our own.
- **KQL, SPL, and Suricata are reviewed, not executed.** See the validation table below for
  exactly what was and was not run.

## What was actually validated

| Content | Status |
|---|---|
| YARA, 12 rules | **Compiled** under yara-python 4.5.4. Smoke-tested against `notepad.exe`, `curl.exe`, `msvcp_win.dll`, `kernel32.dll`. Zero false positives. Reproduce with `detections/yara/validate.py`. |
| Sigma, 22 rules | **Parsed and checked.** Required keys present, 22 unique UUIDs, every selection referenced in a condition is defined. Reproduce with `detections/sigma/validate.py`. |
| PowerShell, 2 scripts | **Executed** end to end on Windows 11 / PowerShell 5.1. |
| KQL, 15 queries | **Not executed.** Authored against the Defender XDR schema. No tenant was available. |
| SPL, 16 searches | **Not executed.** Authored against the Sysmon add-on field names. No Splunk instance was available. |
| Suricata, 24 rules | **Not executed.** No sensor was available to load them. |

The `curl.exe` case in the YARA smoke test is deliberate: one rule targets a trojanized libcurl,
and a rule that flags the real thing is worse than no rule.

## Credit

This package is derived work. The research is theirs:

- **Arctic Wolf** for the BoryptGrab analysis, including the reverse engineering, the IOC set, and
  their own YARA rules. Their repository is
  [`rtkwlf/wolf-tools`](https://github.com/rtkwlf/wolf-tools/tree/main/threat-intelligence/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/).
  **Run their rules as well as these.** Ours were written independently against the published
  behaviour specifically so that a revision on their side cannot silently remove your coverage,
  which is a reason to run both and not a reason to prefer either.
- **Fortinet FortiGuard Labs** for the QuickFox supply chain analysis, including the AES key, the
  victim-validation logic, and the cluster infrastructure.
- **CYFIRMA** for the "Free VPN for PC" execution chain.

There is a specific thing worth saying about Arctic Wolf. The campaign impersonated *them*, among
292 other brands, and they published the analysis anyway, including the detail that the fake
organisation was convincing enough to warrant a full writeup. Publishing an unflattering account
of an attack that used your own name is what makes work like this possible.

## Sources

- Arctic Wolf, *Malicious GitHub Campaign: Fake "Arctic Wolf" and 290+ Brand-Impersonation Repositories Deliver BoryptGrab-Lineage Infostealer* - https://arcticwolf.com/resources/blog/fake-github-repositories-deliver-boryptgrab-lineage-infostealer/
- Fortinet FortiGuard Labs, *QuickFox Supply Chain Attack Used to Deploy FDMTP Implant* - https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant
- CYFIRMA, *GitHub Abused to Spread Malware Disguised as Free VPN* - https://www.cyfirma.com/research/github-abused-to-spread-malware-disguised-as-free-vpn/

## Scope and intent

Defensive material only. No exploitation guidance, no offensive code, no targeting data, no
reproduction of any payload. The indicator list exists so defenders can search their own
telemetry for it.

## AI disclosure

This package was produced with agentic AI assistance under human direction. The human researcher
originated the analysis, made every go/no-go decision, and is solely accountable for the
contents. AI assistance was used for source review, rule drafting, and validation tooling. Every
technical claim traces to one of the three primary sources listed above.

## Citation

Companion paper: *Borrowed Trust: A Detection Engineering Analysis of Three Concurrent
Signed-Binary Sideload Campaigns, August 2026*, Cristian Ruvalcaba and the Saluca Agentic AI
Research Team, Saluca Labs.

**DOI: [10.5281/zenodo.21880002](https://doi.org/10.5281/zenodo.21880002)** · Zenodo, 2026 ·
CC-BY-4.0

Published 2026-08-11. See `CITATION.cff` for machine-readable citation metadata.

```bibtex
@techreport{ruvalcaba2026borrowedtrust,
  title  = {Borrowed Trust: A Detection Engineering Analysis of Three Concurrent
            Signed-Binary Sideload Campaigns, August 2026},
  author = {Ruvalcaba, Cristian and {Saluca Agentic AI Research Team}},
  year   = {2026},
  institution = {Saluca Labs},
  doi    = {10.5281/zenodo.21880002},
  url    = {https://doi.org/10.5281/zenodo.21880002}
}
```

## License

Apache License 2.0. See `LICENSE`.

---

*Cristian Ruvalcaba and the Saluca Agentic AI Research Team, Saluca Labs.*
