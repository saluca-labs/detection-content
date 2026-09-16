# Gulf Conflict Cyber Activity

Detection content for cyber activity that public reporting has attributed to Iran-nexus actors
during the armed conflict that began on 28 February 2026. It covers activity against UAE targets
and its spread to other Gulf states, to US and allied operational technology, and to
multinationals.

Defensive only. Apache-2.0. Part of [saluca-labs/detection-content](https://github.com/saluca-labs/detection-content).

---

## Editorial standard

This pack concerns an active armed conflict, so it is written to a stricter neutrality rule than
the others.

- **Attribution is the publisher's, never ours.** "Iran-nexus", "IRGC" and "MOIS-linked" appear
  here only as the stated assessment of the named source. This pack makes no attribution of its
  own and none should be read into it.
- **Claims by threat actors are labelled CLAIMED** and never presented as fact. Several
  high-profile claims in this conflict remain unverified.
- **No position is taken on the conflict,** its causes, or the legitimacy of any party's
  actions. The scope is one direction of reported activity, because that is what the defensive
  question asked. Cyber operations against Iran are also reported, and they are out of scope here.
- Every source is listed with its affiliation so a reader can weigh it.

## The short version

- **UAE officials have reported sustained cyberattack volume since the conflict began.** They
  cite about 800,000 attempts a day in April, and 640,000 on 15 September 2026. On 16 September
  the head of the UAE Cyber Security Council named the IRGC as behind "many" of them. No technical
  evidence or counting method has been published.
- **The technical record that CAN be used is narrower:**
  - A US joint advisory (CISA AA26-097A, 7 April 2026, updated 22 July) on Iranian-affiliated
    exploitation of internet-exposed PLCs, with 21 IP indicators in STIX.
  - Check Point Research on exploitation attempts against Hikvision and Dahua cameras in eight
    countries and regions, with CVEs but no IPs.
  - Unit 42 infrastructure lists, including UAE- and Saudi-themed phishing domains.
- **Most indicators here are not UAE-specific,** which is why this pack exists as its own
  campaign: the camera and PLC tradecraft applies to any estate running those device families.

## Deploy these first

1. **Internet-to-OT on industrial ports** (`sigma/ot-plc-exposure.yml`, `kql` search 1, `splunk`
   search 1, `suricata` rules 9200100-9200104). An inbound session from the internet to 44818,
   2222, 102 or 502 is an architectural failure with or without an attacker. This rule is
   independent of the actor, so it survives any rotation of infrastructure. It is first because
   CISA reports this path already exploited against US critical infrastructure.
2. **Camera exploit shapes** (`sigma/camera-exploitation.yml`, `suricata` rules 9200110-9200114).
   These key on the request shape the vulnerability requires, not on who sends it.
3. **Bulk destructive actions from device management** (`kql` search 5, `splunk` search 5). The
   destructive operations reported in this conflict are wipes at scale. Watching the management
   plane for mass wipe and retire actions catches that regardless of the malware used, and
   catches a compromised administrator account doing it with no malware at all.
4. **CISA AA26-097A IPs** (`sigma/cisa-aa26-097a-ips.yml`, `suricata` 9200120-9200121). These are
   atomic and will decay, but they come from a primary government STIX file and are the
   highest-confidence atomic indicators in the pack.

## What you cannot detect here

Written before the rules.

- **Almost none of the headline incidents have published indicators.** The claimed operations
  against the Dubai Courts, Dubai Land Department, Dubai RTA (April 2026) and Fujairah port
  (May 2026) are CLAIMED by the Handala persona and unverified. No hashes, IPs or domains were
  published for them. Nothing in this pack is derived from those claims, and anyone offering
  atomic indicators "for Fujairah" should be asked where they came from.
- **The UAE's daily attack figures are not detection content.** They are self-reported volumes
  with no method published. They say nothing about what to look for.
- **The camera campaign used commercial VPN exits** (Mullvad, ProtonVPN, Surfshark, NordVPN) and
  VPS. No IP list was published, and a blocklist of consumer VPN exits blocks legitimate users.
  The durable detection is the exploit shape, not the source.
- **Camera and PLC firmware rarely produces logs you collect.** The web-exploit rules need either
  a reverse proxy or NVR front-end that logs, or network sensor coverage of the camera segment.
  Many estates have neither, and the rules will then silently never fire. Check that before
  assuming coverage.
- **The Unit 42 domains are from April 2026.** Short-lived phishing domains are usually dead or
  re-registered within weeks. They are useful for retrospective hunting and weak as blocks. The
  published list is also a sample, not a feed.
- **A wipe performed with valid administrator credentials through legitimate management tooling
  is indistinguishable from an administrator doing their job,** except by volume and timing. The
  bulk-action rule is a threshold and must be baselined.
- **Hunting rules, not alerts:** the brand-typosquat pattern search, the StealC numbered-host
  pattern, and the bulk-wipe threshold. Each keys on patterns that legitimate activity can
  produce.
- **Nothing here detects AI-assisted phishing as such.** UAE officials and OpenAI both report
  model misuse by Iranian-linked actors. The output is still a phishing email, and it is detected
  (or not) by the same controls as any other.

## Limitations

- The bulk-wipe thresholds (10 actions in 15 minutes) are starting points. Baseline your MDM first.
- The OT port rules assume you can define `$OT_NET` / an OT subnet list. Without it they are too
  broad to run.
- KQL and SPL are authored against documented schemas and have not been executed against a live
  tenant. Budget for at least one field-name fix per query.
- The camera exploit signatures follow the public descriptions of each CVE and the request shapes
  used by widely distributed public scanner templates. They were not tested against vulnerable
  devices. Firmware variants may differ.

## What was actually validated

- **Suricata, loaded in a real engine:** all 15 rules load with 0 failures on Suricata 7.0.17
  (`jasonish/suricata:7.0`), with `OT_NET` defined.
- **Suricata, fired against traffic:** `tests/build_test_pcap.py` builds a synthetic capture of
  positive cases (request structure only, inert values) and benign near-misses. Run on
  2026-09-16:
  - Every positive fired exactly as expected: 16 alerts across 15 sids.
  - Every negative stayed silent, including a different auth value, a benign language PUT, a
    plain-address ping, an unlisted IP in the same /24, and the real `dubaicustoms.gov.ae`.
  - This proves the rules match the shapes they claim. It does not prove those shapes match
    real exploit traffic from every firmware version.
- **Sigma:** all 9 rules convert with `sigma-cli` (Splunk backend, no pipeline). With no pipeline
  the Splunk backend renders `|cidr` as plain equality, so use a pipeline or the hand-written SPL
  for the CIDR conditions.
- **CISA IPs:** extracted programmatically from the two official STIX JSON files downloaded from
  cisa.gov on 2026-09-16, and matched against the advisory's HTML tables (21 unique).
  - SHA-256 of the 2026-04 file: `3f23f8c8b917abad5050c4991714434c53cf304842abdf8ffa87de5d4c2a63a8`
  - SHA-256 of the 2026-07 file: `079eb0f5eaeb15988f3bedf4c7f57b5f8bacfcef046cd9756b4df13ad3fc7c7b`
- **Unit 42 domains and the APK hash:** each value string-matched against the raw Unit 42 page
  fetched on 2026-09-16. All matched.
- **Hunting regexes** (typosquat, brand chain, StealC host):
  - They match every relevant Unit 42 domain.
  - They match none of a benign set of real brand and file-sharing domains.
- **KQL and SPL:** authored, NOT executed. There is no tenant behind them.
- **Not tested at all:** real campaign telemetry, which was not available.

## Scope and intent

Defensive. These rules detect intrusion activity. Nothing here assists in conducting one. No
exploit payloads are included: the camera rules match request structure, not working exploits.

## Sources

| Source | Affiliation | Used for |
|---|---|---|
| [CISA AA26-097A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a) | US government, joint advisory (CISA, FBI, NSA, DOE, EPA, USCYBERCOM) | PLC TTPs, IPs, ports, device models |
| [Check Point Research](https://research.checkpoint.com/2026/interplay-between-iranian-targeting-of-ip-cameras-and-physical-warfare-in-the-middle-east/) | Security vendor, Israel-headquartered | Camera CVEs, geography, timing |
| [Unit 42 threat brief](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/) (updated 2026-04-17) | Security vendor, US | Phishing and StealC infrastructure, actor names |
| [Halcyon](https://www.halcyon.ai/ransomware-alerts/iranian-use-of-cybercriminal-tactics-in-destructive-cyber-attacks-2026-updates) | Security vendor, US | Actor context only. Its indicators were not independently checked and are not included |
| [The National, 2026-09-16](https://www.thenationalnews.com/news/uae/2026/09/16/irans-irgc-behind-many-cyberattacks-on-uae-says-security-chief/) | UAE, state-owned | UAE official statements |
| [Security Affairs](https://securityaffairs.com/190716/hacking/iran-linked-group-handala-claims-to-have-breached-three-major-uae-organizations.html) | Trade press | Handala Dubai claim (CLAIMED) |
| [UpGuard](https://www.upguard.com/news/port-of-fujairah-data-breach-2026-05-07) | Security vendor | Handala Fujairah claim (CLAIMED) |
| [OpenAI threat reports](https://openai.com/index/disrupting-malicious-ai-uses/) | AI vendor, primary | Model misuse by Iranian-linked actors |

## AI disclosure

Written with AI assistance. Rule logic and the limitations above were authored and reviewed
by a human.

## License

Apache-2.0.
