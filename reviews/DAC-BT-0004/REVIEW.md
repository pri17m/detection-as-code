# REVIEW — DAC-BT-0004 BeyondTrust RS/PRA: appliance syslog gap far above its own baseline

## Coverage before
No BeyondTrust appliance-telemetry rule in the repo. Public libraries (SigmaHQ, Splunk security_content, Elastic, Azure-Sentinel) only have endpoint-side "RMM tool present" logic; none read RS/PRA syslog (see research notes, 2026-10-17).

## Coverage after
Per-host gap between consecutive 10-minute `beyondtrust:sra` activity buckets (tstats), or since the last bucket until now, ending in the last 24h and starting in the last 72h, that is ≥4h and >2× the host's p99 gap over days 2–30 (≥20 baseline gaps).

## ATT&CK mapping check (v19.2)
T1562.006 → defense-impairment. Matches existing repo usage for these techniques.

## Source and fields
- Behaviour: Mandiant/GTIG ARMORY CASTLE BeyondTrust post (CVE-2026-102764, NVD-confirmed: RS ≤ 26.2.3, CVSS 4.0 9.3).
- Fields used: `host`, `_time`. All are in BeyondTrust's Syslog events / Message format docs, except `host`/`_time` (Splunk metadata).
- No public rule adapted, so no THIRD_PARTY_NOTICES entry.

## Ponytail review
Ponytail pass 2 (2026-10-17, high-fidelity review):
- Kept: per-host baseline (fixed threshold floods because BT only logs admin/login activity); synthetic 'now' row for a host that stopped sending; only `host`/`_time` used.
- F1 (correctness, real miss): the p99 baseline included the gap being tested. Failing input: 50 gaps of 30 min then one 6h gap in the last 24h → perc99 over 51 values lands at or near the 6h gap itself (≈3.2h with linear interpolation, 6h with nearest-rank), so 6h > 2×p99 is false and the tampering gap is MISSED. Fix: `baseline_gap` only counts gaps that ended >24h ago.
- F2 (speed/load): raw 30-day event search with `sort 0` over every event. On a busy appliance that is millions of rows per run. Fix: `tstats` into 10-minute buckets per host (≤4,320 rows/host for 30d); 10-min resolution is fine against a 4h floor (gaps can read up to 10 min long).
- F3 (fidelity): new or near-silent hosts had a null or tiny-sample p99. Failing input: host with 3 events in 30d → p99 from 2 gaps, alerts on ordinary silence. Fix: require `baseline_n >= 20` (tunable).
- F4 (fidelity/dedupe): a decommissioned appliance raised "still silent" every day forever. Fix: only alert while the gap started within 72h (≈3 daily alerts per outage).
- Output adds `p99_gap_hours` and `baseline_n` for triage. Severity stays low: an SC4S/network outage looks identical with these fields.

## Bypass table
| Attacker variation | Result |
|---|---|
| Delete on-box logs only (forwarded copies survive) | Not a gap; forwarded events already in SIEM. Covered by the other BT rules |
| Short interruption under 4h | MISSED by design |
| Silence lasting >72h before the first scheduled run sees it | Alerted on the runs inside the 72h window only (F4 de-dupe) |
| Appliance with <20 baseline gaps (new or near-silent) | MISSED until baseline builds (F3) |
| Keep a noise generator sending while tampering | MISSED |

## False-positive check
- Planned maintenance, appliance upgrades/reboots, SC4S or network outages (check other SC4S sources for the same window).
- Low-activity sites: BeyondTrust only logs admin/login events, so quiet periods are normal. The baseline percentile handles this, but nights and weekends may still trip it.

## Unverified ideas
- 20-gap minimum, 72h de-dupe window and 10-minute buckets are judgement thresholds, not measured on real data.
- SC4S/network outages can't be told apart using only this sourcetype; correlating with other SC4S sourcetypes needs tenant-specific names, so it isn't in the rule.
- `host` assumed to be the appliance (SC4S sets host from the syslog header).
- Search-time field names assume SC4S default JSON to HEC (`t_json_values`), so vendor keys arrive as JSON keys such as `new_permissions:admin`. Native `;` KV format (`SC4S_DEST_BEYONDTRUST_SRA_SPLUNK_HEC_FMT=NONE`) is not auto-extracted. Unverified in a real tenant.
- BeyondTrust's own Splunkbase apps (6968/6913) poll the API into `beyondtrust_rs`/`beyondtrust_pra` with an undocumented event sourcetype. This rule does not cover that path.
- Not run in Splunk. Fixtures are synthetic and not run (repo has no runner).
- Depends on PR #60 (adds `beyondtrust:sra` to allowed_sourcetypes).

## Tests
Synthetic fixtures in `tests/cases/DAC-BT-0004/` (malicious, benign, near-miss). Not run.

## Reviewer status: pending human approval

