# Phase-1 Backlog Summary — Windows Splunk DaC

**To:** Threat Detection Engineer  
**From:** Detection Engineer (DaC Phase-1 planning)  
**Date:** 2026-09-10 (Asia/Kolkata)  
**Repo:** https://github.com/pri17m/detection-as-code  
**Scaffold branch:** `cursor/dac-scaffold-05fa`  
**Threat Intel pack:** `/workspace/dac-phase1-windows-ad-attack-pack.md`  
**Telemetry canonical:** `/workspace/dac-telemetry-windows/` (`config/sourcetype_map.yaml` + docs)

---

## Executive summary

Contract-aligned Windows backlog of **97** analytics (`DAC-WIN-0001` … `DAC-WIN-0097`):

- **0001–0015** = Threat Intel pack top-15 **exact order/titles**.
- Remainder expands **P0 → P1 → P2** toward ~100 high-value Windows host + AD detections.
- Macros only from Telemetry allowlist; **no `index=`**; `status=draft`; `platforms=[windows]`; `telemetry_validated=false`.
- High-level SPL sketches **only for top-15**; `required_fields` from Telemetry map (empty when Event ID unmapped).

---

## Contract alignment

| Control | Stance |
| --- | --- |
| IDs | DAC-WIN-#### |
| Sourcetypes | windows_security / windows_system / windows_powershell_* / windows_sysmon |
| MITRE techniques | Required on every rule |
| Schema | status, platforms, telemetry_validated, required_fields, false_positives, references |
| Extra channels | Not invented; **32** rules with telemetry_gap |

---

## Counts by tier

| Tier | Count |
| --- | --- |
| P0 | 29 |
| P1 | 34 |
| P2 | 34 |
| **Total** | **97** |

### By category

| Category | Count |
| --- | --- |
| ad-auth | 22 |
| defense-evasion | 17 |
| logon | 13 |
| other | 1 |
| persistence | 19 |
| priv-esc | 3 |
| process | 22 |

### Progress

| Item | Count |
| --- | --- |
| required_fields populated | 78 |
| required_fields empty (map gap) | 19 |
| Top-15 SPL sketches | 15 |
| SigmaHQ wave-1 shortlist | 139 |

---

## Telemetry / scaffold dependencies

1. Use **`/workspace/dac-telemetry-windows/config/sourcetype_map.yaml`** (scaffold branch `cursor/dac-scaffold-05fa`).
2. Expand field map for 4662, 5145, 4719, 4702, 4724, 4740/4741, 4738, 5136/5137, 4886–4888, 4104; Sysmon 4/6/8/16/17–21/25.
3. fieldsummary before leaving draft.
4. Tier-0 + jump-host allowlists for Valid Accounts / RDP.

---

## Package paths

| Path |
| --- |
| `/workspace/dac-phase1/00-naming-and-metadata.md` |
| `/workspace/dac-phase1/01-priority-100-windows-detections.md` |
| `/workspace/dac-phase1/02-sigmahq-import-shortlist.md` |
| `/workspace/dac-phase1/03-phase1-backlog-summary.md` |
| `/workspace/dac-phase1/priority-100.csv` |

---

## Next steps after scaffold PR

1. Confirm sourcetype_map in scaffold branch.
2. TDE reviews DAC-WIN-0001..0015.
3. Close Telemetry field gaps; harden SPL.
4. Import Sigma wave-1 (`builtin/security` + LSASS process_access first).
5. CI schema lint; promote telemetry_validated only after checklist.

*Planning only — verify audit policy + Sysmon before measuring coverage.*

