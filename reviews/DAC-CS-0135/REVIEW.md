# REVIEW — DAC-CS-0135 Falcon: Scheduled Task PowerShell Encoded Download

## Coverage before
ScheduledTaskRegistered (Win), TaskName not under Microsoft\Windows, TaskExecCommand/Arguments contain powershell/pwsh AND -enc/-encodedcommand AND one of downloadstring|downloadfile|iex|invoke-expression|frombase64string|net.webclient.

## Coverage after
Same gates, plus `downloaddata` and the UTF-16LE Base64 prefixes of `IEX`/`iex` (`SQBFAFgA` / `aQBlAHgA`) inside TaskExecCommand/Arguments. The encoded-command AND download/exec gates remain.

## ATT&CK mapping check (v19.2)
- T1053.005 Scheduled Task — Execution, Persistence, Privilege Escalation. Correct. https://attack.mitre.org/techniques/T1053/005/
- T1059.001 PowerShell — Execution. Correct. https://attack.mitre.org/techniques/T1059/001/
Rule tactics list only persistence+execution; privilege-escalation is also a v19.2 tactic of T1053.005 but is optional here (same technique).

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| EncodedCommand carrying UTF-16LE `IEX` / DownloadString | T1059.001 / T1027.010 | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe (-EncodedCommand); Sigma proc_creation_win_powershell_base64_encoded_cmd (`SQBFAFgA`, `aQBlAHgA`); Atomic T1053.005 test e895677d | yes (TaskExecArguments) | low | added | Already gated by -enc AND download/exec intent; Base64 prefix of IEX is the encoded form of the existing `iex` token. |
| DownloadData (not DownloadString/File) | T1059.001 | Microsoft.Net.WebClient.DownloadData API (peer of DownloadString/DownloadFile used by adversaries); Sigma schtasks_susp_pattern uses `.DownloadData` | yes | low | added | Same family as existing download* tokens, still behind the three AND gates. |
| schtasks /TR "cmd /c powershell -enc …" without TaskExecCommand matching powershell | T1053.005 | Atomic T1053.005 test e895677d | yes (TaskExecArguments still scanned) | n/a | kept (already covered) | Rule ORs TaskExecCommand and TaskExecArguments. |
| Non-PowerShell task (mshta/wscript) with encoded payload | T1059.005 / T1218.005 | Atomic / LOLBAS | yes | high | dropped | Expanding beyond powershell/pwsh removes the high-precision premise of this rule (it is a subset of DAC-CS-0090). |
| Hidden / XML-imported task without -enc | T1053.005 | Atomic T1053.005 tests cd925593 / e16b3b75 | yes | high | dropped | Without -enc the rule's precision contract fails; belongs in a broader scheduled-task rule. |

## Unverified ideas
- Decode `-EncodedCommand` payload inside LogScale and re-scan (possible with `base64Decode` but needs UTF-16LE handling confirmation).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
