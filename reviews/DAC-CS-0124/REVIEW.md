# REVIEW — DAC-CS-0124 Falcon: BYOVD Known Vulnerable DriverLoad

## Coverage before
DriverLoad (Win) where `FileName` is one of a hard-coded list of known-abused vulnerable drivers (`gdrv.sys`, `msio64.sys`, `ntiolib.sys`, `kprocesshacker.sys`, `physmem.sys`, `dbk64.sys`, `procexp152.sys`, `AsrDrv104.sys`, `mhyprot2.sys`, `capcom.sys`, `iqvw64e.sys`, `RTCore64.sys`). Groups by aid/ComputerName/FileName/FilePath/ImageFileName.

## Coverage after
Unchanged. **No safe enhancement.**

## ATT&CK mapping check (v19.2)
- T1068 Exploitation for Privilege Escalation — tactic Privilege Escalation. Correct: ATT&CK explicitly documents BYOVD under T1068. Source: https://attack.mitre.org/techniques/T1068/
- T1014 Rootkit — tactic Stealth. Flagged as **partial / stretch**: T1014 is about hiding system components via rootkits; loading a vulnerable driver for privilege escalation is T1068. Keep T1014 only if a later review can show the driver is used as a rootkit; otherwise drop it.

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| Load renamed copy of a known-vulnerable driver (FileName ≠ OriginalFilename) | T1068 / T1036.003 | https://attack.mitre.org/techniques/T1036/003/ ; Falcon field `OriginalFilename` on DriverLoad: https://github.com/CrowdStrike/logscale-community-content/blob/0152b8a763e34991461b9e8f8dd5036b596ba08f/Queries-Only/Helpful-CQL-Queries/Enumerate%20Windows%20Driver%20Loads.md | yes (`OriginalFilename`, `SHA256HashData` on DriverLoad) | medium | dropped | Matching OriginalFilename against the same short list without a hash/blocklist lookup still fails when the PE resources were patched; a Microsoft recommended driver blocklist / LOLDrivers hash join is the correct path and is not yet wired here. |
| Additional named drivers from Sigma (`speedfan.sys`, `vboxdrv.sys`, `dbutil_2_3.sys`, `truesight.sys`, `aswarpot.sys`, `zam64.sys`) | T1068 | https://github.com/SigmaHQ/sigma/blob/master/rules/driver_load/driver_load_win_vuln_drivers_names.yml ; Atomic T1068 tests: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1068/T1068.yaml | yes (`FileName`) | high | dropped | Sigma itself warns that name-only matching of vulnerable drivers produces FPs when a non-vulnerable version shares the name; Atomic T1068 uses `iqvw64e.sys` / `vboxdrv.sys` via `sc create`, which this rule would already catch for iqvw64e. Adding more bare names without hash filtering is not low-noise. |
| Hash-based Microsoft recommended driver blocklist | T1068 | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules ; https://attack.mitre.org/techniques/T1068/ | yes (`SHA256HashData`) | low (once hash list is maintained) | dropped (for now) | Requires an external hash list asset in LogScale; not present in this repo. Logged as future work. |

## Unverified ideas
- Join DriverLoad → TerminateProcess of EDR/AV processes (original ByteRay idea). Deferred in the rule description as "THIN ESN"; no public schema confirmation of the join fields was opened for this review.
- LOLDrivers online catalog hash feed.

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.
No new fixtures (rule unchanged).

## Reviewer status: pending human approval
