# REVIEW — DAC-BT-0001 BeyondTrust RS/PRA: administrator permission granted to a local user

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
`user_changed` where `new_permissions:admin`=1 and the `old_` snapshot isn't 1; `user_added` with `permissions:admin`=1.

## ATT&CK mapping check (v19.2)
T1098 → persistence, privilege-escalation. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `event`, `who`, `who_ip`, `site`, `old_username`, `old_permissions:admin`, `new_permissions:admin`, `permissions:admin`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
- Docs say `new_` appears only for changed settings, so `new_permissions:admin=1` is a real grant, not a snapshot. Display-name edits on admins don't fire.
- Added `fillnull` on site/who/who_ip so events without `who_ip` aren't dropped by `stats`.
- Revocations (1→0) excluded on purpose (near-miss fixture).

## Bypass table
| Attacker variation | Result |
|---|---|
| Raise Jump Item/team role (`permissions:jump_item_role:*`) instead of the admin flag, which is what ARMORY CASTLE actually did | MISSED. That field appears in the Mandiant blog and the Sekoia sample but not in the BeyondTrust field tables, so it was excluded under the confirmed-fields rule. Top follow-up once confirmed. |
| Grant admin via group policy (`group_policy_*` events) | MISSED, out of scope |
| Use an existing admin account | Not this rule; see DAC-BT-0002 |
| Delete logs afterwards | Event is already forwarded off-box; DAC-BT-0004 covers gaps |

## False-positive check
- Planned admin onboarding or role changes. Confirm a change record and that `who` is a known administrator.

## Unverified ideas
- Whether `user_added` carries `permissions:admin` unprefixed or as `new_permissions:admin`. The query accepts both.
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0001/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

