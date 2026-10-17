# REVIEW — DAC-BT-0002 BeyondTrust RS/PRA: successful web login from a first-seen source IP for a known user

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
Successful `login` on web/login or web/appliance where the (site, user, source network) pair first appears in the last 24h and the user has ≥7 days of history in a 30-day lookback. Source network = IPv4 /24, or the exact address for IPv6.

## ATT&CK mapping check (v19.2)
T1078 → initial-access, persistence. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `event`, `status`, `target`, `who`, `who_ip`, `site`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
Ponytail pass 2 (2026-10-17, high-fidelity review):
- Kept: `status=success` only (near-miss fixture: failed login from a new IP); rep_client excluded.
- F1 (correctness): `\((?<bt_user>[^)]+)\)` takes the FIRST parentheses. Failing input: `who=Jane Doe (Contractor)(jdoe) using password` → actor `contractor`, a fake new pair for every contractor-tagged user. Fix: anchor to the last `(...)` before the optional ` using <method>` suffix.
- F2 (correctness): docs show failed integrated logins as `who=unknown () using gssapi`; with the old regex such an actor didn't parse and `coalesce(bt_user, who)` fell back to the full who string. Fix: drop events whose actor is empty/`unknown` or that lack `who_ip`.
- F3 (fidelity): DHCP/VPN pool churn. Failing input: admin seen from 10.0.0.5 for 30d, today from 10.0.0.23 → alert. Fix: baseline on IPv4 /24 (`src_net`), exact match for IPv6. `who_ip` values kept in output.
- F4 (fidelity): `web/api` logins come from integrations that often run on cloud/autoscaled egress, and the API `who` format isn't documented in the examples. Failing input: an integration whose runner moves to a new egress IP each week alerts weekly. Fix: removed `web/api`; covered partially by DAC-BT-0003. Listed in Bypass.
- F5 (fidelity/threshold): `actor_first_seen < -1d` let a user created 2 days ago alert on every new network during their first week. Fix: require ≥7 days of history (tunable). Window changed from `-1d` to `-24h` and `latest=now` pinned so a daily schedule has no gap/overlap at the boundary; schedule must be every 24h.
- Output adds `actor_known_nets` (distinct baseline networks) to help triage: a user with 1 known network logging in from a new one is stronger than a roaming user with 12.

## Bypass table
| Attacker variation | Result |
|---|---|
| Log in from an IP already used by the victim (e.g. via a compromised admin host) | MISSED |
| Use the API (`target=web/api`) with stolen or attacker-created API credentials | MISSED here (web/api removed for fidelity, see F4); DAC-BT-0003 fires on api_account_added / secret regeneration |
| Log in from another host in a /24 the victim already used | MISSED (accepted trade-off of F3) |
| Log in more than 30 days after a one-off use of the same IP | MISSED (lookback limit) |
| Representative console | Out of scope |

## False-positive check
- Admins travelling, new VPN egress IPs, or DHCP churn on admin workstations. Tune with an allowlist of corporate egress ranges.
- The first login of a user with <7 days of history is suppressed by design.

## Unverified ideas
- 7-day history and /24 grouping are judgement thresholds, not measured on real data. Tune after running in a tenant.
- Schedule assumption: daily over 30d. Cost on busy sites unmeasured.
- No residential/VPN ASN enrichment (the blog's suggestion); first-seen is the proxy.
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0002/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

