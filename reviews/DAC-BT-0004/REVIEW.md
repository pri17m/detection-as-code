# REVIEW — DAC-BT-0004 BeyondTrust RS/PRA: appliance syslog gap far above its own baseline

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
Per-host gap between consecutive `beyondtrust:sra` events, or since the last event until now, in the last 24h, that is ≥4h and >2× the host's 30-day p99 gap.

## ATT&CK mapping check (v19.2)
T1562.006 → defense-impairment. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `host`, `_time`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
- A fixed threshold would flood: BeyondTrust only logs admin/login activity, so quiet periods are normal. The per-host p99 baseline is the fix.
- Added the synthetic 'now' row so an appliance that stopped sending entirely is caught (the most likely tampering outcome).
- Uses only `host` and `_time`, so it doesn't depend on any unconfirmed field.

## Bypass table
| Attacker variation | Result |
|---|---|
| Delete on-box logs only (forwarded copies survive) | Not a gap; forwarded events already in SIEM. Covered by the other BT rules |
| Short interruption under 4h | MISSED by design |
| Keep a noise generator sending while tampering | MISSED |

## False-positive check
- Planned maintenance, appliance upgrades/reboots, SC4S or network outages (check other SC4S sources for the same window).
- Low-activity sites: BeyondTrust only logs admin/login events, so quiet periods are normal. The baseline percentile handles this, but nights and weekends may still trip it.

## Unverified ideas
- 30-day raw search cost on busy appliances unmeasured. Consider a summary index.
- `host` assumed to be the appliance (SC4S sets host from the syslog header).
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0004/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

