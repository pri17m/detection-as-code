# REVIEW — DAC-CS-0203 Scheduled task registration on a DC preceding DCSync tooling

## Coverage before
On ProductType=2 (DC via aid_master_main.csv): ScheduledTaskRegistered (non-Microsoft\\Windows) then later ProcessRollup2/ProcessBlocked matching secretsdump|lsadump::dcsync|ntdsutil.*ifm|ntds.dit|--just-dc or matching images, with t_tool > t_task.

## Coverage after
Same, plus `Get-ADReplAccount` in the tooling CommandLine regex.

## ATT&CK mapping check (v19.2)
- T1053.005 — correct. https://attack.mitre.org/techniques/T1053/005/
- T1003.006 — correct for the second stage. https://attack.mitre.org/techniques/T1003/006/

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| DSInternals Get-ADReplAccount as stage-2 tooling | T1003.006 | Atomic T1003.006 a0bced08 | yes | low | added | Same distinctive cmdlet as DAC-CS-0201. |
| Task under Microsoft\\Windows\\ (hijacked) | T1053.005 | Atomic / ATT&CK | yes | high | dropped | Broadening past the Microsoft\\Windows exclusion would alert on legitimate OS tasks. |
| Ghost Task via registry (no ScheduledTaskRegistered) | T1053.005 | Atomic T1053.005 test 704333ca | no (needs registry telemetry) | n/a | dropped | Not detectable with ScheduledTaskRegistered. |

## Unverified ideas
- Confirm ProductType=2 semantics of aid_master_main.csv in every tenant (rule already notes fallback).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
