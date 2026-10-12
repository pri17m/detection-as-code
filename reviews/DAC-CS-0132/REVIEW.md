# REVIEW — DAC-CS-0132 Falcon: Credential Dump Tools with UserIdentity Join

## Coverage before
ProcessRollup2 where CommandLine matches `mimikatz|sekurlsa|procdump.*lsass|lsass.dmp|comsvcs.dll.*MiniDump` OR ImageFileName ends with mimikatz/procdump/pwdump/nanodump.exe; exclude MsMpEng/CSFalconService parents; join UserIdentity on AuthenticationId and SyntheticProcessRollup2 parent hash.

## Coverage after
Same structure, plus command-line patterns for:
- `rdrleakdiag` + `fullmemdmp`/`/memdmp` (LOLBAS / Atomic T1003.001)
- `createdump` + `lsass` (.NET createdump / Atomic T1003.001)
- `sqldumper` + `0x01100:40` (LOLBAS / Sigma)
- ProcDump-style `-ma/-mm/-mp lsass` (Sigma)
- `outflank-dumpert` (Atomic T1003.001)
- `reg save/export HKLM\sam|security` (Atomic T1003.002 / Sigma)
and ImageFileName `nanodump.x64.exe`.

## ATT&CK mapping check (v19.2)
- T1003.001 LSASS Memory — Credential Access. Correct. https://attack.mitre.org/techniques/T1003/001/
- T1003.002 Security Account Manager — Credential Access. Correct for the new `reg save/export` branch. https://attack.mitre.org/techniques/T1003/002/

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| rundll32 + comsvcs.dll MiniDump of LSASS | T1003.001 | https://lolbas-project.github.io/lolbas/Libraries/comsvcs/ ; Atomic T1003.001 test 2536dee2-… ; Sigma proc_creation_win_rundll32_process_dump_via_comsvcs | yes (CommandLine on ProcessRollup2) | low (Sigma FP: Unlikely) | kept (already covered) | Existing `comsvcs.dll.*MiniDump` regex catches it. |
| rdrleakdiag /fullmemdmp /p <lsass> | T1003.001 | https://lolbas-project.github.io/lolbas/Binaries/Rdrleakdiag/ ; Atomic T1003.001 test 47a539d1-… ; Sigma proc_creation_win_rdrleakdiag_process_dumping | yes | low | added | Arguments are dump-specific (`fullmemdmp`/`/memdmp`). |
| createdump -u -f … lsass | T1003.001 | Atomic T1003.001 test 9d0072c8-… ; Sigma proc_creation_win_createdump_lolbin_execution | yes | medium → tightened | tightened | Require `lsass` in the same CommandLine (not bare createdump). |
| sqldumper <pid> 0 0x01100:40 | T1003.001 | https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/ ; Sigma proc_creation_win_lolbin_susp_sqldumper_activity | yes | medium → tightened | tightened | Match only the Mimikatz-compatible flag `0x01100:40` (Sigma's high-signal flag). |
| ProcDump `-ma/-mm/-mp lsass` without binary name match | T1003.001 | Sigma proc_creation_win_sysinternals_procdump_lsass (stable); Atomic T1003.001 tests 0be2230c / 7cede33f | yes | low | added | Flag+process combo; Sigma FP notes "Unlikely". |
| Outflank Dumpert | T1003.001 | Atomic T1003.001 test 7ae7102c-… | yes | low | added | Tool name is unique. |
| `reg save/export HKLM\sam|security` | T1003.002 | Atomic T1003.002 tests 5c2571d0 / 21df41be ; Sigma proc_creation_win_reg_dumping_sensitive_hives | yes | medium → tightened | tightened | Require both save/export AND sam/security hive. SYSTEM hive alone is common for backups. |
| Task Manager GUI dump of LSASS | T1003.001 | Atomic T1003.001 test dea6c349-… ; ATT&CK procedure examples (APT5, Magic Hound, Play) | no (ProcessRollup2 has no dump-intent for Taskmgr; needs handle/process-access telemetry) | n/a | dropped | Not detectable with this log source. |
| Silent Process Exit / WerFault LSASS dump | T1003.001 | ATT&CK T1003.001 (Gilboa 2021); Atomic T1003.001 test eb5adf16-… | no public Falcon field for silent-process-exit registry writes confirmed | n/a | dropped | Not detectable with ProcessRollup2 alone. |
| Renamed procdump/mimikatz (ImageFileName only) | T1003.001 / T1036.003 | https://attack.mitre.org/techniques/T1036/003/ | partial (OriginalFilename on ProcessRollup2 not confirmed in the community-content sources opened for this review) | high | dropped | Bare OriginalFilename matching without a hash allowlist is high-noise; CommandLine patterns still catch many renamed-tool invocations that keep their flags. |

## Unverified ideas
- Falcon process-access / handle-to-LSASS events (no public schema opened confirming field names).
- Pypykatz / Out-Minidump.ps1 PowerShell-only paths (need ScriptControl correlation; separate rule).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
