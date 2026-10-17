# REVIEW — DAC-BT-0003 BeyondTrust RS/PRA: API account, security provider, or log/outbound destination change

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
api_account_added, api_account_changed (enabled or client_secret changed only), security_provider_* and security_provider_setting_*, syslog_server_changed, outbound_event HTTP/email recipient added/changed, admin_password_reset_to_factory_default.

## ATT&CK mapping check (v19.2)
T1098, T1556, T1562.006 → persistence, credential-access, defense-impairment. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `event`, `who`, `who_ip`, `site`, `client_id`, `syslog_servers`, `new_enabled`, `new_client_secret`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
Ponytail pass 2 (2026-10-17, high-fidelity review):
- Kept: removals excluded except `security_provider_removed` (can force fallback to local auth); `client_secret` value not used (always `***`).
- F1 (fidelity): `user_added` fired on every routine onboarding. Failing input: helpdesk creates 20 non-admin users in a day → 20 medium alerts. Fix: `user_added` removed; admin-level creation stays covered by DAC-BT-0001 (user_added with permissions:admin=1). T1136 mapping removed with it. Plain user creation is a bypass (listed).
- F2 (fidelity): `api_account_changed` fired on comment edits. Failing input: `event=api_account_changed; old_comments=CI; new_comments=CI pipeline` → alert. Fix: only alert when `new_enabled` (re-enable/disable) or `new_client_secret` (secret regenerated) is present, following the documented old_/new_ convention. Near-miss fixture added.
- F3 (triage): output adds `change_class` and `dc(change_class)`. One actor touching ≥2 classes in the window (e.g. new auth provider + syslog redirect) is the ARMORY CASTLE-style pattern and should be triaged first.
- Rows stay per (site, who, who_ip); `fillnull` keeps events missing who_ip.

## Bypass table
| Attacker variation | Result |
|---|---|
| Create a plain (non-admin) local user | MISSED here (user_added removed, F1). Admin-level creation is DAC-BT-0001 |
| Modify an existing user instead of adding one | DAC-BT-0001 covers admin grants. Jump-item role raises MISSED (unconfirmed field) |
| Change group policy to add rights | MISSED (group_policy events not included; candidate for v2) |
| Disable syslog entirely via /appliance | Covered if it logs syslog_server_changed; otherwise DAC-BT-0004 sees the gap |

## False-positive check
- Routine admin changes. Correlate with change tickets; suppress known automation who/who_ip after review.

## Unverified ideas
- `new_enabled` / `new_client_secret` on api_account_changed follows the documented old_/new_ convention, but no real api_account_changed sample was seen. If the appliance emits these unprefixed, enable/secret changes would be dropped. Verify on real data.
- Field coverage of `security_provider_setting_*` and outbound event payloads not checked against real samples.
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0003/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

