# REVIEW - DAC-MDE-0108 MDE: Scheduled task with an all-digit name runs python.exe or pythonw.exe

## Attribution
Clean-room behavioural rule written from public sources opened on 23 Nov 2026 (IST):
- https://hexastrike.com/resources/blog/threat-intelligence/s5pivot-a-python-backconnect-proxy-hidden-inside-a-qilin-ransomware-intrusion/
- https://labs.infoguard.ch/posts/slithering_through_the_noise/
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-random
- https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask
- https://falconforce.nl/falconfriday-malicious-scheduled-tasks-0xff0b/
- https://threathunt.blog/hunting-for-malicious-scheduled-tasks/
- https://detection.wiki/defender-deviceevents/
- https://attack.mitre.org/techniques/T1053/005/
- https://attack.mitre.org/techniques/T1059/006/

No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic. No hashes, domains, hostnames or IPs from the write-ups are used.

## Source context
- Primary write-up: Hexastrike, "S5PIVOT – A Python Backconnect Proxy Hidden Inside a Qilin Ransomware Intrusion" (Maurice Fielenbach, 7 Nov 2026). It describes a SYSTEM scheduled task with a random numeric name that starts `pythonw.exe` every minute with no script argument from a randomly named folder under `C:\ProgramData`, an embeddable CPython 3.13.3 runtime with an added `sitecustomize.py`, and the registration command `Register-ScheduledTask (Get-Random) ... -E pythonw.exe ... -RepetitionI (New-TimeSpan -Mi 1) ... -User System`. It explains the nine- and ten-digit names as the output of `Get-Random`, and recommends alerting on tasks that start `python.exe`/`pythonw.exe` with no script argument and on purely numeric task names. https://hexastrike.com/resources/blog/threat-intelligence/s5pivot-a-python-backconnect-proxy-hidden-inside-a-qilin-ransomware-intrusion/
- Earlier, related case: InfoGuard Labs, "Slithering Through the Noise" (VIPERTUNNEL, 9 Apr 2026). Task `523135538` ran `C:\ProgramData\cp49s\pythonw.exe` with no arguments; `C:\ProgramData\cp49s\Lib\sitecustomize.py` checked argc through `Py_GetArgcArgv` and only then ran the payload through `runpy`. https://labs.infoguard.ch/posts/slithering_through_the_noise/
- The LinkedIn post that started this work (Maurice Fielenbach) was seen as a screenshot and as a search-result snippet; the page itself was not opened. Its text matches the Hexastrike post. It is context only. https://www.linkedin.com/posts/mauricefielenbach_threatintel-dfir-cybersecurity-activity-7524899796046774272-gc58
- Python docs: `site` is imported automatically at startup unless `-S` is given; it then tries to import `sitecustomize` and `usercustomize`, and `.pth` lines that start with `import` are executed. https://docs.python.org/3/library/site.html The Windows docs say a `._pth` file makes Python ignore `site` unless `import site` is listed. https://docs.python.org/3/using/windows.html
- Hashes, domains and hostnames in the write-ups are not used. No IP logic.

## As-is (new rule; close rules on main at 2e447414)
Searched detections/ for 4698, ScheduledTaskCreated, ScheduledTaskRegistered, TaskName and python.
- DAC-WIN-0020 (4698 with a suspicious command): LOLBin list (powershell, cmd, wscript, cscript, mshta, rundll32, regsvr32, bitsadmin, certutil). No python, no task-name check.
- DAC-WIN-0110 (4698 LOLBin/SYSTEM): TaskContent contains powershell, -enc, cmd.exe, mshta, http or the text `SYSTEM`, plus every Sysmon 1 `schtasks /create`. The task XML in the screenshot behind this work showed the principal as `S-1-5-18`, so the `*SYSTEM*` term may not fire, and nothing checks the name or python. Side note, not changed here: in its second `search` line SPL binds OR tighter than the implied AND, so it reads as 4698 AND (content terms OR EventCode=1), and the Sysmon 1 schtasks branch never reaches the output. Not run; it needs its own PR.
- DAC-CS-0090 (Falcon suspicious scheduled task): its user-writable path reason includes `\users\public\` but not `\programdata\`, and S5PIVOT's TaskExecCommand was just `pythonw.exe` with the folder in WorkingDirectory, so it would not fire on the reported shape. A full-path Users\Public python action would hit its path reason.
- DAC-CS-0091..0096 and DAC-CS-0135 (hidden, ComHandler, HighestAvailable, logon trigger, boot trigger, remote registration, encoded PowerShell): none match a time trigger with one-minute repetition, LeastPrivilege, and a python action.
- DAC-MDE-0006 / DAC-MDE-0025: schtasks.exe command lines only.
- No rule checks for all-digit task names.

## After
New defender rule DAC-MDE-0108 on DeviceEvents, ActionType ScheduledTaskCreated or ScheduledTaskUpdated. TaskName's last segment must be digits only. TaskContent must have an Exec Command ending in python.exe or pythonw.exe (quoted or not). Microsoft Learn documents DeviceEvents columns and says AdditionalFields is JSON and ActionType values are in the in-portal schema; the AdditionalFields keys (TaskName, TaskContent, SubjectUserName) and the TaskContent shape (Actions.Exec.Command/Arguments, Triggers) come from FalconForce, threathunt.blog and detection.wiki. The regex runs on the TaskContent text so it works whether TaskContent arrives as an object or as a JSON string, and with more than one action.

## ATT&CK
T1053.005 (Scheduled Task), T1059.006 (Python). Tactics persistence, execution. privilege-escalation is not tagged because this event has no principal. T1546.018 is not tagged: task registration says nothing about a startup hook.

## False-positive check (before writing the query)
- "Mostly digits" names were dropped: the post and the Hexastrike write-up warn they match tasks like OneDrive Reporting Task, whose name carries the user's SID. The match is digits from start to end of the task's own name. A near-miss fixture covers the OneDrive name.
- No public source was found of legitimate software naming tasks with a bare number. That is not proof there is none, so the rule also requires a python.exe/pythonw.exe action.
- Python actions with descriptive names (Anaconda report jobs and the like) do not match. The FP rate is not measured.

## Why this shape
Microsoft's Get-Random page says that with no parameters it returns an integer between 0 and Int32.MaxValue (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-random), and Hexastrike ties that to the nine- and ten-digit names. The task name is matched on its last segment so a numeric task inside a folder still counts. MDE's ScheduledTaskCreated has no principal or RunLevel, so the SYSTEM condition from the brief cannot be applied here. The CrowdStrike (DAC-CS-0254) and Splunk (DAC-WIN-0367) versions do apply it.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Name with a letter prefix or suffix (Task1846203957) | Digits-only match | Known gap, by design (mostly-digits logic is what the post warns against). |
| Action is cmd.exe or powershell.exe that then starts python | Command check | Known gap. Existing LOLBin task rules may catch the wrapper. |
| Interpreter renamed in the task action | Command must end in python(w).exe | Known gap. Pair with DAC-MDE-0107, which uses OriginalFileName at run time. |
| Task created through a path MDE does not report as ScheduledTaskCreated | Event coverage | Unverified. |

## Unverified
- The AdditionalFields key names and the TaskContent shape are from community sources, not Microsoft Learn.
- Whether ScheduledTaskUpdated carries the same keys as ScheduledTaskCreated.
- Whether every tenant gets ScheduledTaskCreated for tasks registered through the ScheduledTasks PowerShell module.
- Query not run on the platform. telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0108/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_ten_digit_pythonw | yes | would alert | match |
| malicious_quoted_full_path_python | yes | would alert | match |
| malicious_updated_numeric_leaf_in_folder | yes | would alert | match |
| near_miss_onedrive_sid_name | no | no alert | match |
| near_miss_mixed_name_python | no | no alert | match |
| near_miss_numeric_powershell | no | no alert | match |
| benign_named_python_task | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | "Mostly digits" logic matches OneDrive Reporting Task names with a SID | `\OneDrive Reporting Task-S-1-5-21-...` | Digits from start to end of the last segment |
| 2 | Must | TaskName carries a leading backslash and may have folders | `\1846203957`, `\Vendor\738201945` | Regex `(^|\\)[0-9]+$` |
| 3 | Should | Quoted command paths are JSON-escaped (`\"`) inside TaskContent | `"\"C:\\ProgramData\\ab12\\python.exe\""` | Command regex allows escaped quotes |
| 4 | Should | No principal in this event | n/a | Documented; SYSTEM check lives in the CS and Splunk rules |

## Reviewer status
pending
