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

## Field verification
| Field / ESN | Status | Source |
|---|---|---|
| ProcessRollup2, FileName, CommandLine, aid | verified | LCC Hunting bcdedit.exe usage.md |
| correlate() | verified | library.humio.com functions-correlate; used by DAC-CS-0235 |
| AsepValueUpdate / RegGenericValueUpdate on SafeBoot | unverified for this key path (not used) | — |
| ServiceInstalled | unverified (removed) | 0 LCC hits |

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0241/; result: not run.
