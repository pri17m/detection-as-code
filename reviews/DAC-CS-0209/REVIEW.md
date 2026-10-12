# REVIEW — DAC-CS-0209 Volume shadow or ntdsutil IFM access targeting NTDS.dit

## Coverage before
ProcessRollup2/ProcessBlocked (Win) where (vssadmin|diskshadow|wbadmin|ntdsutil image AND CommandLine matches create shadow|shadow copy|ntds.dit|ifm|full backup|catalog) OR CommandLine matches ntds.dit; exclude MsMpEng/CSFalconService parents.

## Coverage after
Unchanged. **No safe enhancement.**

## ATT&CK mapping check (v19.2)
- T1003.003 NTDS — Credential Access. Correct. https://attack.mitre.org/techniques/T1003/003/

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| `wmic shadowcopy call create` | T1003.003 | Atomic T1003.003 tests 224f7de0 / d893459f | yes | high | dropped | Atomic creates a shadow without mentioning ntds.dit; bare wmic+shadowcopy catches legit backup tooling. Rule already has a separate `ntds.dit` CommandLine OR that catches copies that name the file. |
| PowerShell `(gwmi -list win32_shadowcopy).Create(...)` | T1003.003 | Atomic T1003.003 test 542bb97e | yes | high | dropped | Same: shadow create without ntds.dit is common admin activity (Sigma susp_shadow_copies_creation FP: "Legitimate administrator working with shadow copies"). |
| diskshadow /s script that execs LOLBin | T1003.003 / T1218 | LOLBAS Diskshadow; Sigma diskshadow_child_process_susp | yes (parent/child) | medium | dropped | Needs parent=diskshadow child LOLBin correlation — different analytic; out of scope for this CommandLine rule. |
| esentutl /y /vss ntds.dit | T1003.003 | Atomic T1003.003 test 21c7bf80; LOLBAS Esentutl | yes | low | kept (covered by sibling DAC-CS-0215) | Do not duplicate; 0215 owns esentutl. |
| ntdsutil IFM already covered | T1003.003 | Atomic T1003.003 test 2364e33d | yes | low | kept | Existing. |

## Unverified ideas
- Require DC ProductType=2 (rule FP note suggests ComputerName pattern; aid_master lookup would mirror DAC-CS-0203).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.
No new fixtures (rule unchanged).

## Reviewer status: pending human approval
