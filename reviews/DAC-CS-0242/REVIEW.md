# REVIEW — DAC-CS-0242 Falcon: Microsoft Defender tamper (MpPreference / MpCmdRun / sc / registry)

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a13344-944a-7211-9fc7-f5b1002993b6 by Fatima Suvaid (@arhaminafs). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## ATT&CK v19.2
- T1685 Disable or Modify Tools — defense-impairment
- T1112 Modify Registry — defense-impairment, persistence

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Source opened with `CommandLine = *` which does nothing and scans every ProcessRollup2 | All Win ProcessRollup2 | Removed |
| 2 | Should | Source branches matched DefenderControl/dControl/DefenderRemover by ImageFileName — rename bypass and not behavioural | `evil.exe` doing the same Set-MpPreference | Dropped tool-name IOC branches; kept MpPreference/sc/registry behaviour |
| 3 | Should | Source missed `-DisableTamperProtection` / `-DisableBehaviorMonitoring` on Set-MpPreference | `Set-MpPreference -DisableTamperProtection $true` | Added those flags (https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference) |
| 4 | Nice | No aggregation | — | groupBy for Filter Alerts shape |

### Merge-time ponytail pass (2026-10-17)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 5 | Must | The Disable* flag branch fired on any mention of the flag, including the command that turns protection back ON, which is the opposite of the described behaviour and a common admin step after troubleshooting | `powershell Set-MpPreference -DisableRealtimeMonitoring $false` | Split into `MpPreferenceExclusion` (Set/Add + Exclusion*) and `MpPreferenceDisable` (Set-MpPreference + Disable*), and the Disable branch now drops command lines where the flag is set to `$false` or `0` (Microsoft documents these parameters as Boolean: https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference). Fixture `near_miss_reenable_rtp.json`. Known gap: a single command setting one Disable* flag to `$true` and another to `$false` is dropped |

## Field verification
| Field | Status | Source |
|---|---|---|
| ProcessRollup2 fields | verified | LCC |
| Set-MpPreference parameters | verified | Microsoft Learn Set-MpPreference |
| MpCmdRun -RemoveDefinitions -All | verified | Microsoft Learn Defender Antivirus command-line arguments |

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0242/; result: not run.
