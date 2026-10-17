# REVIEW — DAC-MDE-0093 QueueUserAPC + remote memory + Early Bird (≤60s)

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a13157-ffc9-748c-a025-4a9cec1e367e by Unknown. No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## ATT&CK v19.2
- T1055 Process Injection — stealth, privilege-escalation
- T1055.004 Asynchronous Procedure Call — stealth, privilege-escalation

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Source ended with `where EarlyBird or isnotempty(RemoteActions)` after an **inner** join to remote — RemoteActions is always non-empty, so Early Bird was never required and any APC+remote-mem pair alerted even into a long-lived process | APC + NtAllocate into explorer.exe hours after create | Require inner join to process-creation and SecondsSinceChildCreated between 0..60 |
| 2 | Must | Source listed WriteProcessMemoryApiCall and NtWriteVirtualMemoryRemoteApiCall — not in FalconFriday 0xFF-0081 verified ActionType set | Tenant without those ActionTypes | Kept only QueueUserApcRemoteApiCall, NtAllocateVirtualMemoryRemoteApiCall, NtMapViewOfSectionRemoteApiCall (FalconFriday + detection.wiki) |
| 3 | Should | `ago(7d)` + broadcast join hint | Heavy / unsupported hint | Lookback 1d; removed hint.strategy=broadcast |
| 4 | Should | leftouter children join could attach an unrelated same-PID recycle | PID reuse after 60s window confusion | inner join + 0..60s bound |

## Field verification
| ActionType | Status | Source |
|---|---|---|
| QueueUserApcRemoteApiCall | verified | FalconFriday 0xFF-0081; detection.wiki Defender-DeviceEvents |
| NtAllocateVirtualMemoryRemoteApiCall | verified | same |
| NtMapViewOfSectionRemoteApiCall | verified | same |
| WriteProcessMemoryApiCall | unverified (removed) | not in FalconFriday list |
| NtWriteVirtualMemoryRemoteApiCall | unverified (removed) | not in FalconFriday list |

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0093/; result: not run.
