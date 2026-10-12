# REVIEW — DAC-CS-0215 esentutl copy of NTDS or registry hive

## Coverage before
ProcessRollup2/ProcessBlocked (Win), ImageFileName esentutl.exe, CommandLine contains `/y` AND (`/vss` OR ntds.dit OR \\config\\sam|system|security OR \\ntds\\).

## Coverage after
Same, plus `\\config\\regback\\(sam|system|security)` and `\\repair\\(sam|system|security)` path tokens (Sigma sensitive-file-copy paths). Author normalised to `DaC`. Technique list adds T1003.002 (SAM hive copy) alongside T1003.003.

## ATT&CK mapping check (v19.2)
- T1003.003 NTDS — correct for ntds.dit. https://attack.mitre.org/techniques/T1003/003/
- T1003.002 SAM — correct for SAM/SECURITY hive copies. Added. https://attack.mitre.org/techniques/T1003/002/

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| esentutl /y /vss of RegBack or repair hives | T1003.002 | Sigma proc_creation_win_esentutl_sensitive_file_copy (paths include config\\RegBack\\* and \\repair\\*); Atomic T1003.002 esentutl SAM copy a90c2f4d | yes | medium → tightened | tightened | Still requires `/y` AND sensitive path; Sigma FP acknowledges forensics/backup — documented in false_positives. |
| esentutl /y of arbitrary file | T1003.003 | LOLBAS Esentutl Copy use case | yes | high | dropped | LOLBAS documents general file copy; without sensitive path this is admin noise. |
| `/m` salvage mode of hive | T1003.002 | Sigma esentutl rule includes `/m` | yes | medium | dropped | Not confirmed as a credential-theft path in Atomic/ATT&CK procedure examples opened for this review; logged under unverified. |

## Unverified ideas
- esentutl `/m` (salvage) against hives.

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
