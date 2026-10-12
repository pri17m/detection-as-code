# REVIEW — DAC-CS-0207 splunkd spawning shell or LOLBin child process

## Coverage before
ProcessRollup2/ProcessBlocked where ParentBaseFileName is splunkd(.exe) and child is cmd|powershell|pwsh|bash|sh|dash|zsh|certutil|mshta|rundll32|regsvr32|curl|wget; exclude CommandLine containing `splunk cmd` or `instrumentation`.

## Coverage after
Same, plus child ImageFileName endings `wscript|cscript|bitsadmin` (Windows).

## ATT&CK mapping check (v19.2)
- T1190 Exploit Public-Facing Application — Initial Access. Acceptable framing for post-exploitation of a public Splunk instance (e.g. CVE-2023-46214 class). https://attack.mitre.org/techniques/T1190/
- T1059 Command and Scripting Interpreter — Execution. Correct. https://attack.mitre.org/techniques/T1059/
Note: this rule does not prove exploitation; it detects the post-exploit child spawn.

## Bypass table
| bypass | technique ID | source | telemetry available | noise risk | decision | reason |
|---|---|---|---|---|---|---|
| splunkd → wscript/cscript | T1059.005 | Sigma webshell / java-child patterns treat wscript/cscript as high-signal LOLBins; LOLBAS Wscript/Cscript | yes | low under rare parent splunkd | added | Parent rarity keeps noise low. |
| splunkd → bitsadmin | T1197 | LOLBAS Bitsadmin; common post-exploit download LOLBin | yes | low under rare parent | added | Same rationale. |
| splunkd → python/perl | T1059 | Sigma CVE-2023-46214 PoC references | yes | high | dropped | Splunk ships Python; child python from splunkd is expected and untightenable without path allowlists we do not have. |
| Renamed shell (T1036.003) | T1059 / T1036.003 | ATT&CK | partial | high | dropped | ImageFileName-only rule; OriginalFilename not confirmed for this review. |

## Unverified ideas
- Linux-only bash/sh children with event_platform=Lin (rule FP note already mentions this).

## Tests
Tests added as data files under tests/cases/<RULE-ID>/; no per-rule test runner exists in the repo (CI only runs validate_repo.py), so results are **not run**.

## Reviewer status: pending human approval
