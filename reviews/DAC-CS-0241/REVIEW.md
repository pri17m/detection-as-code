# REVIEW — DAC-CS-0241 Falcon: bcdedit safeboot / SafeBoot write then shutdown /r

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a13345-5468-734a-9ae1-a3a3c8c60322 by Fatima Suvaid (@arhaminafs). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## Coverage before / after
DAC-CS-0235 already correlates bcdedit safeboot with a SafeBoot service registration command line. This rule adds the reboot stage (shutdown /r) and does not use ServiceInstalled or UserLogon scoring.

## ATT&CK v19.2
- T1688 Safe Mode Boot — defense-impairment
- T1685 Disable or Modify Tools — defense-impairment

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Source filter `Stage =~ in(bcdedit_safeboot, safeboot_registry) OR StageCount >= 2` then `StageCount >= 1` alerts on a lone bcdedit safeboot with no reboot | Only `bcdedit /set {current} safeboot minimal` | Require correlate of safemode stage AND shutdown /r within 1h |
| 2 | Must | Source counted every ServiceInstalled and every remote UserLogon as a stage — any service install + remote logon in the window could alert | ServiceInstalled + LogonType 3 on a helpdesk host | Removed ServiceInstalled and UserLogon stages (ServiceInstalled ESN also unverified in LCC) |
| 3 | Should | Source used AsepValueUpdate/RegGenericValueUpdate for SafeBoot keys — Falcon coverage of those keys undocumented (same reason DAC-CS-0235 avoided them) | Missing registry events → miss | Use ProcessRollup2 CommandLine containing `\SafeBoot\(Minimal|Network)\` instead |
| 4 | Nice | Overlap with DAC-CS-0235 | — | Documented: 0235 = service registration; 0241 = reboot |

### Merge-time ponytail pass (2026-10-17)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 5 | Must | Title/description say safe-mode stage "followed by" `shutdown /r`, but `correlate()` defaults to `sequence=false` (any order), so a reboot that happened before the safeboot change also matched | `shutdown /r /t 0` at 10:00, then `bcdedit /set {current} safeboot minimal` at 10:20 on the same aid | Added `sequence=true` (library.humio.com functions-correlate: "Events in a constellation must occur in the order that queries are defined"). Fixture `near_miss_reboot_before_safeboot.json` |
| 6 | Should | SafeBoot registry branch matched any command line naming `\SafeBoot\Minimal\` or `\Network\`, including read-only or delete commands, though the description says "writes" | `reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\ /s` then `shutdown /r` | Require a write verb in the same command line: `add`, `import`, `copy`, `New-Item`, `New-ItemProperty`, `Set-ItemProperty`. Fixture `near_miss_reg_query_safeboot.json` |

## Field verification
| Field / ESN | Status | Source |
|---|---|---|
| ProcessRollup2, FileName, CommandLine, aid | verified | LCC Hunting bcdedit.exe usage.md |
| correlate(), sequence=true | verified | https://library.humio.com/data-analysis/functions-correlate.html ; used by DAC-CS-0235 |
| AsepValueUpdate / RegGenericValueUpdate on SafeBoot | unverified for this key path (not used) | — |
| ServiceInstalled | unverified (removed) | 0 LCC hits |

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0241/; result: not run.
