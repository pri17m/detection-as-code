# REVIEW — DAC-CS-0201 Remote DCSync-style dump via secretsdump-like tooling

## Coverage before
ProcessRollup2/ProcessBlocked matching secretsdump/wmiexec/smbexec/atexec/mimikatz/ntdsutil image OR CommandLine secretsdump|lsadump::dcsync|/dcsync|ntdsutil.*ifm|ntds.dit|--just-dc|--ntds, selfJoinFilter with NetworkConnectIP4 to ports 445/135/389/636 from the same process.

## Coverage after
Same, plus CommandLine token `Get-ADReplAccount` (DSInternals DCSync-equivalent; Atomic T1003.006).

## ATT&CK mapping check (v19.2)
- T1003.006 DCSync — Credential Access. Correct. https://attack.mitre.org/techniques/T1003/006/
- T1021.002 SMB/Windows Admin Shares — Lateral Movement. Acceptable for the Impacket lateral tools (wmiexec/smbexec/atexec) that share this rule; pure DCSync is T1003.006 only. Not flagged as wrong.

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| DSInternals `Get-ADReplAccount -All -Server …` | T1003.006 | Atomic T1003.006 test a0bced08-… | yes (CommandLine) | low (PowerShell cmdlet name is distinctive) | added | Atomic documents this as a DCSync alternative; still requires the network join. |
| Mimikatz `lsadump::dcsync` already covered | T1003.006 | Atomic T1003.006 test 129efd28-… | yes | low | kept | Existing. |
| Impacket secretsdump from attacker host with no local ProcessRollup2 on DC | T1003.006 | Rule description; ATT&CK | no on victim for ProcessRollup2 | n/a | dropped | Correctly deferred to DAC-WIN-0332 (4662 replication GUIDs). |
| Custom DCSync tool with no string overlap | T1003.006 | ATT&CK | network-only | high | dropped | Without process strings, network ports alone cannot isolate DRSUAPI. |

## Unverified ideas
- Falcon DNS / LDAP operation events naming DRSUAPI GUIDs (no public field opened).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
