# REVIEW — DAC-CS-0243 DLL sideload from user-writable path with unsigned DLL

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a13344-3442-756a-a20a-02d8b048c3f5 by Fatima Suvaid (@arhaminafs). No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## ATT&CK v19.2
- T1574.001 DLL — stealth, execution (T1574.002 DLL Side-Loading is **revoked** in v19.2; do not use)
- T1036.005 Match Legitimate Resource Name or Location — stealth

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must (brief) | Source hard-coded a long vendor exe name list (vlc, zoom, msmpeng, crowdstrike, …) — rename bypass and maintenance trap | `legitname.exe` from Downloads loading evil.dll | Removed the exe basename list; any .exe from a user-writable path |
| 2 | Must (brief) | Source did not require the DLL to be unsigned | Signed partner DLL next to a portable app | Require SignInfoFlags NO_SIGNATURE or not HAS_VALID_SIGNATURE via bitfield:extractFlags (LCC Decode SignInfoFlags.md) |
| 3 | Must | Source used ClassifiedModuleLoad / ModuleLoad / FilePath / FileName — ClassifiedModuleLoad had 0 hits in LCC snapshot; ImageHash uses ImageFileName | ClassifiedModuleLoad events never arrive | ImageHash + ImageFileName only (LCC Search-ByProcessContext.yaml) |
| 4 | Should | Same-directory correlate without Dir in group key could pair unrelated paths sharing a PID | PID reuse across dirs | groupBy includes Dir |
| 5 | Should | T1574.002 revoked in ATT&CK v19.2 | — | Techniques: T1574.001, T1036.005 only |

## Field verification
| Field / ESN | Status | Source |
|---|---|---|
| ImageHash + ContextProcessId | verified | LCC Search-ByProcessContext.yaml Image Hash Events widget |
| SignInfoFlags bitfield extract (flags 9, 18) | verified on **ProcessRollup2** | LCC Decode SignInfoFlags.md |
| SignInfoFlags populated on **ImageHash** | **unverified** | Decode doc only shows ProcessRollup2; if ImageHash lacks SignInfoFlags the unsigned branch never fires (fail-closed). Tag needs-review |
| ClassifiedModuleLoad / ModuleLoad | unverified (not used) | 0 LCC hits for ClassifiedModuleLoad |
| FilePath / FileName on module events | unverified (not used) | replaced with ImageFileName |

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0243/; result: not run.
