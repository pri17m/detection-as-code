# REVIEW - DAC-WIN-0367 Splunk: Scheduled task created (4698) with an all-digit name, SYSTEM principal and a python.exe or pythonw.exe action

## Attribution
Clean-room behavioural rule written from public sources opened on 23 Nov 2026 (IST):
- https://hexastrike.com/resources/blog/threat-intelligence/s5pivot-a-python-backconnect-proxy-hidden-inside-a-qilin-ransomware-intrusion/
- https://labs.infoguard.ch/posts/slithering_through_the_noise/
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
- https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-userid-principaltype-element
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-random
- https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask
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
New splunk rule DAC-WIN-0367 on Security 4698 through the `windows_security` macro (no index=, no allowlist change). TaskName (or classic Task_Name) last segment must be digits only. TaskContent (or Task_Content) must have an Exec `<Command>` ending in python.exe or pythonw.exe and a `<UserId>` of S-1-5-18, SYSTEM or NT AUTHORITY\SYSTEM. Both plain and entity-escaped tags are accepted. Microsoft's 4698 page documents TaskName as `\task_path\task_name` and TaskContent as the task XML. Companion to DAC-MDE-0108 and DAC-CS-0254.

## ATT&CK
T1053.005 (Scheduled Task), T1059.006 (Python). Tactics persistence, execution, privilege-escalation (SYSTEM principal). T1546.018 is not tagged: task registration says nothing about a startup hook.

## False-positive check (before writing the query)
- "Mostly digits" names were dropped: the post and the Hexastrike write-up warn they match tasks like OneDrive Reporting Task, whose name carries the user's SID. The match is digits from start to end of the task's own name. A near-miss fixture covers the OneDrive name.
- No public source was found of legitimate software naming tasks with a bare number. That is not proof there is none, so the rule also requires a python.exe/pythonw.exe action.
- Python actions with descriptive names (Anaconda report jobs and the like) do not match. The FP rate is not measured.

## Why this shape
Get-Random with no parameters returns an integer between 0 and Int32.MaxValue (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-random); Hexastrike ties that to the nine- and ten-digit names and reports the task ran as SYSTEM. Microsoft's 4698 page also recommends watching tasks created in the library root, which is where `Register-ScheduledTask (Get-Random)` puts them.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Name with a letter prefix or suffix | Digits-only match | Known gap, by design. |
| Principal is not SYSTEM | SYSTEM filter from the brief | Known gap. |
| Audit Other Object Access Events off | No 4698 | Logging gap; enable the subcategory. |
| Logs cleared before forwarding | Hexastrike's victim had no central logging and logs were wiped | Out of scope for the rule. |
| Action is a wrapper (cmd, powershell) | Command check | Known gap. DAC-WIN-0020 may catch the wrapper. |

## Unverified
- How each Splunk Windows TA version renders TaskContent (plain XML, entity-escaped, or as part of Message). Plain and escaped are handled; Message-only rendering is not.
- Whether `-User System` is always written as `S-1-5-18` in TaskContent.
- Query not run on the platform. telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-WIN-0367/. Each has `"synthetic": true` and a `result` that says "not run". There is no Splunk runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_system_ten_digit_pythonw | yes | would alert | match |
| malicious_entity_escaped_content | yes | would alert | match |
| malicious_classic_field_names | yes | would alert | match |
| near_miss_user_principal | no | no alert | match |
| near_miss_onedrive_sid_name | no | no alert | match |
| near_miss_numeric_powershell | no | no alert | match |
| benign_named_python_task | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | "Mostly digits" logic matches OneDrive names with a SID | OneDrive Reporting Task | Digits from start to end |
| 2 | Must | TaskContent can arrive entity-escaped | `&lt;Command&gt;python.exe&lt;/Command&gt;` | Accept `<` or `&lt;` and `>` or `&gt;` |
| 3 | Should | Classic TA uses Task_Name / Task_Content | classic rendering | coalesce both names |
| 4 | Should | Principal as SID or name | `S-1-5-18`, `SYSTEM`, `NT AUTHORITY\SYSTEM` | Accept all three |
| 5 | Should | No bare index= | n/a | windows_security macro |

## Reviewer status
pending
