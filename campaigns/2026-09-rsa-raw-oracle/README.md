# Raw RSA Oracle Forgery

Detection for the attack in *Forging 1024-bit RSA signatures in nearly SNFS time* (Shea, Haller,
Suhl, Heninger, Thomé, IACR ePrint 2026/2131): an attacker with temporary access to a **raw** RSA
signing or decryption oracle makes a few billion queries, walks away, and can then forge signatures
under that key forever, without ever recovering it.

Defensive only. Apache-2.0. Part of [saluca-labs/detection-content](https://github.com/saluca-labs/detection-content).

---

## The short version

On 20 September 2026 researchers at UC San Diego and Inria Nancy published the first practical
implementation of a 2007 algorithm by Joux, Naccache and Thomé. Against a 1024-bit key held in a
Thales Luna HSM, they spent about 1,200 core-years on precomputation from the public key alone,
made **4,067,419,331** raw signing queries to the HSM (about a week of sustained signing at ~6,500
signatures per second), and could then forge a signature on any message offline in about 180
core-years. Factoring the same key is estimated at 500,000 to 1,000,000 core-years.

The precondition is the whole story. The oracle must compute `x^d mod N` on **attacker-chosen**
`x`, with no padding. PKCS#1 v1.5 and PSS signers are not meaningfully exposed; the paper says so.
The exposed deployments are:

- **RFC 9474 blind RSA** (Privacy Pass publicly verifiable tokens, Apple Private Access Tokens,
  iCloud Private Relay, GNU Taler), where the signer is a raw oracle by design.
- **HSMs and keystores with raw RSA enabled** (PKCS#11 `CKM_RSA_X_509`), usually because the
  application applies a padding the HSM does not implement: ISO 9796-2, ANSI X9.31, RSA-FDH.
- **Unpadded decryption APIs**, for example Android KeyMint, and Bleichenbacher padding oracles
  used as a (much more expensive) way to manufacture raw queries.

The authors extrapolate 2^90 work and 2^43 queries for 2048-bit keys, and 2^119 work and 2^57
queries for 4096-bit keys. Not an immediate threat at 2048; a 15 to 30 bit gap against the
factoring estimates everyone sizes keys by.

## Deploy these first

Ranked by how well they survive a competent attacker, not by how easy they are.

1. **Signing-ledger reconciliation** (`splunk` search 1, `kql` query 1, `hunt/rsa_oracle_audit.py reconcile`).
   Every signature your key produces goes in a ledger. A signature that verifies under your key and
   is not in the ledger is a forgery, whatever produced it. For token systems the same idea is a
   count: **per key, redemptions must never exceed issuances.** This is the only detection that
   works after the fact, and the only one blinding cannot touch.
2. **Per-key private-key operation budget** (`sigma` correlation, `splunk` search 2, `kql` query 2).
   The attack needs 2^32 queries at 1024 bits and 2^43 at 2048. Alert on cumulative operations per
   key against a forecast, not on rate, because a patient attacker spreads the draw.
3. **The configuration that makes it possible** (`sigma` rules 1-3, `semgrep`,
   `hunt/rsa_oracle_audit.py scan-code` and `pkcs11`). Any key whose policy permits
   `CKM_RSA_X_509`, any raw mechanism use on a key that should only ever see padded operations,
   and any tooling invocation that asks for unpadded RSA.
4. **Padding enforcement at the raw-call boundary.** Not a detection, a control. If your
   application pads in software and calls the HSM raw, put a gate in front of the raw call that
   refuses anything not in your padding format. Blinding does not survive this, because a blinded
   value will not carry the expected structure. `hunt/rsa_oracle_audit.py shape --expect-padding`
   shows the check.

## What you cannot detect here

Written before the rules.

- **There are no atomic indicators.** This is published research, not a campaign. No hashes,
  infrastructure or samples exist, and `iocs/indicators.csv` says so in row one.
- **The forged signature is perfect.** It is a valid RSA signature, bit-for-bit what the key would
  have produced. No verifier-side rule can distinguish it. Detection at verification time is
  structurally unavailable; only a ledger comparison can find it.
- **Two of the three phases never touch you.** The ~1,200 core-year precomputation needs only the
  public key and the ~180 core-year forgery needs only the attacker's own stored results. Both run
  on the attacker's hardware. **The query phase is the only observable phase.**
- **Against blind RSA, the queries are indistinguishable from legitimate ones.** The paper says
  this directly. There is no query-content detection for RFC 9474 deployments. What remains is
  volume per key and issuance-versus-redemption reconciliation.
- **Input shape is a tripwire, not coverage.** As demonstrated, the queries are small integers
  (every prime up to 2^36, and values `a - b*m` far below the modulus), which a full-width padded
  value never is. But anyone holding the public key can blind their own queries into uniformly
  random-looking values at negligible cost. The shape rule catches the attack as published and
  nothing more.
- **Many HSMs do not log individual cryptographic operations.** Audit logs commonly cover
  administration, login and policy events, not each `C_Sign`. If your HSM cannot tell you how many
  private-key operations each key performed, rule 2 cannot run, and that absence is the finding.
- **Rate is a weak signal.** The researchers' own remote HSM ran at ~2,500 signatures per second
  and the queries can be spread across weeks and many clients. Anything keyed on bursts will miss a
  patient attacker. Budgets are cumulative for that reason.

## Rules in this pack

| File | What | Alert or hunt |
|---|---|---|
| `detections/sigma/rsa-raw-oracle.yml` | 1. raw RSA mechanism on a non-allowlisted key; 2. correlation, per-key raw operation budget; 3. HSM policy change permitting non-approved / raw operation; 4. unpadded RSA requested from command-line tooling | 1 alert, 2 alert, 3 alert, 4 hunt |
| `detections/splunk/rsa-raw-oracle.spl` | ledger reconciliation, cumulative per-key budget, token issuance vs redemption, input-shape tripwire | 1 and 3 alert, 2 alert after baseline, 4 hunt |
| `detections/kql/rsa-raw-oracle-hunting.kql` | the same logic for Sentinel custom tables | as above |
| `detections/semgrep/raw-rsa.yml` | code signatures for raw RSA in Python, Java/Kotlin, Go, C/C++, JavaScript, PKCS#11 | hunt (inventory) |
| `../../hunt/rsa_oracle_audit.py` | read-only audit tool: code scan, PKCS#11 key policy audit, ledger reconciliation, input-shape check | hunt |

There is no Suricata or YARA content, because there is nothing to see on the wire (the oracle
traffic is whatever authenticated API the signer already exposes, usually inside TLS or on a
PCIe bus) and there are no samples.

## Log schema you must map

HSM and KMS audit formats differ by vendor, and this pack does not pretend otherwise. The Sigma
rules use a small neutral schema under `logsource: product: hsm`. Map your source onto it:

| Field | Meaning |
|---|---|
| `key_label` | stable identifier of the key (label, handle, KMS key id) |
| `operation` | `sign`, `decrypt`, `policy_change`, ... |
| `mechanism` | PKCS#11 mechanism name, e.g. `CKM_RSA_X_509`, `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS` |
| `client_id` | the authenticated principal or partition client |
| `policy_name`, `new_value` | for policy change events |

The Splunk and KQL queries use the same names so one mapping serves all three.

## Limitations

- Thresholds are placeholders. A key that legitimately signs 10^9 times a day and one that signs
  twice a year need different budgets; forecast each key before enabling rule 2.
- The paper's figures are an upper bound on attacker cost, by the authors' own statement; better
  implementations and GPUs (they estimate 2 to 9 GPU-years for the 1024-bit forgery) lower it.
- Rule 3 cannot know your vendor's policy vocabulary. It matches on intent (`FIPS`, `non-approved`,
  raw mechanism allow) and will need editing.
- Ledger reconciliation requires that the observed-signature feed actually exists: CT logs,
  token redemption logs, code-signing verification telemetry. Where you never see your signatures
  used, you cannot reconcile them.

## What was actually validated

Exact, as of 2026-09-26:

| Artefact | Check | Result |
|---|---|---|
| Sigma (4 rules incl. 1 correlation) | `tools/validate.py`; official `sigma check` (sigma-cli 3.1.0, ATT&CK v19 data) | 0 errors, 0 issues |
| Semgrep (11 rules, 6 languages) | `hunt/tests/semgrep_test.py`, real engine in the `semgrep/semgrep` container | 20 of 20 expected matches, 0 unexpected, all 11 rules exercised. Mutation-tested: broadening one rule produces 2 unexpected matches and fails the harness |
| `hunt/rsa_oracle_audit.py` | `hunt/tests/test_rsa_oracle_audit.py`, 21 unit tests | pass; every check tested firing AND quiet, and "cannot tell" inputs tested to raise |
| `rsa_oracle_audit.py pkcs11` | `hunt/tests/pkcs11_softhsm_test.py` against a real SoftHSM2 token | four keys, four correct verdicts (PSS-only ok, raw-allowed flagged, unrestricted flagged, 1024-bit raw flagged with the size warning) |
| The control itself | same harness | SoftHSM2 **refused** a raw operation on the PSS-restricted key (`MechanismInvalid`) and allowed it on the raw-permitted key. Restricting `CKA_ALLOWED_MECHANISMS` closes the oracle on this token; confirm on yours |
| SPL, KQL | none | **Not run.** No Splunk or Sentinel instance with HSM telemetry was available. Syntax reviewed by eye only |
| Everything | real HSM telemetry | **Not run.** No vendor audit log was available. All rules are `experimental` |

One defect found by the SoftHSM2 test and fixed before release: python-pkcs11 (0.10.0) has no
handler for `CKA_ALLOWED_MECHANISMS` and raises `NotImplementedError` on reading it, so the audit
would have crashed on the exact attribute it exists to check. The tool now registers its own
handler. Unit tests alone would never have found this.

## Citation

Paper: *Oracle Drawdown: A Detection Engineering Analysis of RSA Signature Forgery from a Raw
Signing Oracle, and Why the Key Never Has to Leave*, `oracle-drawdown-v1.0.md` in this directory.
DOI reserved as 10.5281/zenodo.22981798 (version DOI, deposit NOT yet published). The concept DOI
will be read off the published record and recorded here; cite that one once it exists.

## Scope and intent

Defensive. These rules detect the preconditions and the observable phase of a published
cryptanalytic attack. Nothing here generates oracle queries, performs descent, or assists in
carrying the attack out.

## Sources

- Laura Shea, Miro Haller, Adam Suhl, Nadia Heninger, Emmanuel Thomé, *Forging 1024-bit RSA
  signatures in nearly SNFS time*, IACR ePrint 2026/2131, 20 September 2026.
  https://eprint.iacr.org/2026/2131
- Antoine Joux, David Naccache, Emmanuel Thomé, *When e-th roots become easier than factoring*,
  ASIACRYPT 2007.
- RFC 9474, *RSA Blind Signatures*. https://www.rfc-editor.org/rfc/rfc9474
- OASIS PKCS #11 Cryptographic Token Interface, `CKM_RSA_X_509` and `CKA_ALLOWED_MECHANISMS`.

## AI disclosure

Written with AI assistance. Rule logic and the limitations above were authored and reviewed
by a human.

## License

Apache-2.0.
