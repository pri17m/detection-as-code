# REVIEW — DAC-BT-0002 BeyondTrust RS/PRA: successful web login from a first-seen source IP for a known user

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
Successful `login` on web/login, web/appliance or web/api where the (site, user, who_ip) pair first appears in the last 24h and the user has older history in a 30-day lookback.

## ATT&CK mapping check (v19.2)
T1078 → initial-access, persistence. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `event`, `status`, `target`, `who`, `who_ip`, `site`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
- `who` is free text like `Name(user) using password`, so the username in parentheses is extracted and lowercased to stop the auth-method suffix creating fake 'new' pairs.
- rep_client logins excluded (high churn; representatives on dynamic IPs).
- Brand-new users are suppressed (needs `actor_first_seen` older than 24h). A new attacker-created user is DAC-BT-0003's job.

## Bypass table
| Attacker variation | Result |
|---|---|
| Log in from an IP already used by the victim (e.g. via a compromised admin host) | MISSED |
| Use the API with an attacker-created API account | Partly. A new client is suppressed as a new user; DAC-BT-0003 fires on api_account_added |
| Log in more than 30 days after a one-off use of the same IP | MISSED (lookback limit) |
| Representative console | Out of scope |

## False-positive check
- Admins travelling, new VPN egress IPs, or DHCP churn on admin workstations. Tune with an allowlist of corporate egress ranges.
- The first login of a brand-new user is suppressed by design (needs older history).

## Unverified ideas
- Schedule assumption: daily over 30d. Cost on busy sites unmeasured.
- No residential/VPN ASN enrichment (the blog's suggestion); first-seen is the proxy.
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0002/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

