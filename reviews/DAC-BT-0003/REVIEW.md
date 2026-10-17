# REVIEW — DAC-BT-0003 BeyondTrust RS/PRA: new user, API account, security provider, or log/outbound destination change

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
user_added, api_account_added/changed, security_provider_* and security_provider_setting_*, syslog_server_changed, outbound_event HTTP/email recipient added/changed, admin_password_reset_to_factory_default.

## ATT&CK mapping check (v19.2)
T1136, T1098, T1556, T1562.006 → persistence, credential-access, defense-impairment. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `event`, `who`, `who_ip`, `site`, `client_id`, `syslog_servers`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
- Removals (except security_provider_removed) left out: they reduce access. Provider removal stays because it can force fallback to local auth.
- `client_secret` is always `***` per docs, so it isn't used.
- `fillnull` added so `stats` keeps events missing who_ip.

## Bypass table
| Attacker variation | Result |
|---|---|
| Modify an existing user instead of adding one | DAC-BT-0001 covers admin grants. Jump-item role raises MISSED (unconfirmed field) |
| Change group policy to add rights | MISSED (group_policy events not included; candidate for v2) |
| Disable syslog entirely via /appliance | Covered if it logs syslog_server_changed; otherwise DAC-BT-0004 sees the gap |

## False-positive check
- Routine admin changes. Correlate with change tickets; suppress known automation who/who_ip after review.

## Unverified ideas
- Field coverage of `security_provider_setting_*` and outbound event payloads not checked against real samples.
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0003/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

