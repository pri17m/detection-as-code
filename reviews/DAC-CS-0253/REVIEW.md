# REVIEW - DAC-CS-0253 Falcon: Task Scheduler starts python.exe or pythonw.exe from ProgramData or Users\Public with no script

## Attribution
Clean-room behavioural rule written from public sources opened on 23 Nov 2026 (IST):
- https://hexastrike.com/resources/blog/threat-intelligence/s5pivot-a-python-backconnect-proxy-hidden-inside-a-qilin-ransomware-intrusion/
- https://labs.infoguard.ch/posts/slithering_through_the_noise/
- https://docs.python.org/3/library/site.html
- https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Use%20Join%20on%20Two%20Scoped%20Events.md
- https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/ProcessRollup2%20Curation.md
- https://library.humio.com/crowdstrike-query-language/functions-join.html
- https://library.humio.com/crowdstrike-query-language/functions-replace.html
- https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring
- https://reinject.vercel.app/en/posts/windows-security/persistence/windows_schedule_task_internal/
- https://attack.mitre.org/techniques/T1053/005/
- https://attack.mitre.org/techniques/T1546/018/
- https://attack.mitre.org/techniques/T1059/006/

No detections.ai content, no employer data, no CrowdStrike console data. Fixtures are synthetic. No hashes, domains, hostnames or IPs from the write-ups are used.

## Source context
- Primary write-up: Hexastrike, "S5PIVOT – A Python Backconnect Proxy Hidden Inside a Qilin Ransomware Intrusion" (Maurice Fielenbach, 7 Nov 2026). It describes a SYSTEM scheduled task with a random numeric name that starts `pythonw.exe` every minute with no script argument from a randomly named folder under `C:\ProgramData`, an embeddable CPython 3.13.3 runtime with an added `sitecustomize.py`, and the registration command `Register-ScheduledTask (Get-Random) ... -E pythonw.exe ... -RepetitionI (New-TimeSpan -Mi 1) ... -User System`. It explains the nine- and ten-digit names as the output of `Get-Random`, and recommends alerting on tasks that start `python.exe`/`pythonw.exe` with no script argument and on purely numeric task names. https://hexastrike.com/resources/blog/threat-intelligence/s5pivot-a-python-backconnect-proxy-hidden-inside-a-qilin-ransomware-intrusion/
- Earlier, related case: InfoGuard Labs, "Slithering Through the Noise" (VIPERTUNNEL, 9 Apr 2026). Task `523135538` ran `C:\ProgramData\cp49s\pythonw.exe` with no arguments; `C:\ProgramData\cp49s\Lib\sitecustomize.py` checked argc through `Py_GetArgcArgv` and only then ran the payload through `runpy`. https://labs.infoguard.ch/posts/slithering_through_the_noise/
- The LinkedIn post that started this work (Maurice Fielenbach) was seen as a screenshot and as a search-result snippet; the page itself was not opened. Its text matches the Hexastrike post. It is context only. https://www.linkedin.com/posts/mauricefielenbach_threatintel-dfir-cybersecurity-activity-7524899796046774272-gc58
- Python docs: `site` is imported automatically at startup unless `-S` is given; it then tries to import `sitecustomize` and `usercustomize`, and `.pth` lines that start with `import` are executed. https://docs.python.org/3/library/site.html The Windows docs say a `._pth` file makes Python ignore `site` unless `import site` is listed. https://docs.python.org/3/using/windows.html
- Hashes, domains and hostnames in the write-ups are not used. No IP logic.

## As-is (new rule; close rules on main at 2e447414)
Searched detections/ for python/pythonw, sitecustomize, usercustomize, .pth, ProgramData python, svchost Schedule parents, taskeng, 4698, ScheduledTaskCreated and ScheduledTaskRegistered.
- No rule keys on a Task Scheduler parent (svchost `-s Schedule` or taskeng.exe) starting anything, and none on python.exe/pythonw.exe without a script.
- DAC-CS-0112 (Falcon scripting engine outbound NetworkConnectIP4) and DAC-CS-0108 (scripting engine DNS) include python/pythonw. They could see the later C2 session on Falcon only, not the launch. DAC-CS-0074 (direct IP in a command line) does not apply because the command line is bare.
- DAC-MDE-0006 / DAC-MDE-0025 look at `schtasks.exe /create`. Register-ScheduledTask goes through the ScheduledTasks module, so they would not see the S5PIVOT registration, and they do not look at execution.
- No rule watches writes of sitecustomize.py, usercustomize.py or .pth files.

## After
New crowdstrike rule DAC-CS-0253 on ProcessRollup2. ImageFileName is python.exe or pythonw.exe under `\ProgramData\` or `\Users\Public\` (device path or drive letter). ParentBaseFileName is svchost.exe or taskeng.exe. The parent's command line comes from a left join on [aid, ParentProcessId] to [aid, TargetProcessId], 7 days back, the same pattern as DAC-CS-0252 and the public logscale-community-content join example. If the join returns a svchost command line that names another service, the event is dropped. If the join misses, the event is kept as svchost_unconfirmed. The script-argument check uses `replace()` to strip the first token. Companion to DAC-MDE-0107.

## ATT&CK
T1053.005 (Scheduled Task), T1546.018 (Event Triggered Execution: Python Startup Hooks), T1059.006 (Python). Tactics persistence, execution, privilege-escalation (T1053.005 lists all three). The rule sees the task launch; the startup hook is why a bare launch matters, so T1546.018 is tagged even though the hook file itself is not in the query.

## False-positive check (before writing the query)
- Anaconda/Miniconda "All Users" installs go to `C:\ProgramData\Anaconda` or Anaconda3 by default (https://www.anaconda.com/docs/getting-started/advanced-install/multi-user). So "any python from ProgramData" was dropped as too noisy. Scheduled jobs on those installs pass a script (`.py`) or `-m module`, and those are excluded. No public source was found of Anaconda or Miniconda registering a task that runs a bare interpreter. The conda folders are not allowlisted, because the post says the same hook works in any standard CPython, including conda.
- Python-based agents under ProgramData: they start through a script or `-m`, so they are excluded by the argument check. A tool that relies on `.pth` or sitecustomize on purpose and starts with only interpreter options would alert; no public example was found.
- A bare interpreter launched with no stdin has nothing to run and exits, so a legitimate task has no reason to do it. The FP rate is not measured.

## Why this shape
Scheduled-task processes start under the svchost.exe instance hosting the Schedule service (`svchost.exe -k netsvcs -p -s Schedule`), and under taskeng.exe on older Windows (https://reinject.vercel.app/en/posts/windows-security/persistence/windows_schedule_task_internal/; FalconForce and threathunt.blog show the same parent in MDE data: https://falconforce.nl/falconfriday-malicious-scheduled-tasks-0xff0b/ , https://threathunt.blog/hunting-for-malicious-scheduled-tasks/). Microsoft documents that from Windows 10 1703 services are split into their own svchost on client SKUs with more than 3.5 GB RAM, and stay grouped on smaller systems (https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring). A grouped host has `-k netsvcs` without `-s`, so that case is matched as netsvcs_shared. No Microsoft Learn page was found that names the Task Scheduler child-process parent; the svchost/taskeng parent is from the community sources above. ProcessRollup2 has no parent command line field, which is why the join is there. A boot-time svchost is usually older than 7 days, so on long-running servers most hits will be svchost_unconfirmed.

The argument check strips the first token of the command line (quoted or not) and then requires that what is left has no `.py`, `.pyw`, `.pyc`, `.pyz` or `.zip` token and no `-c`/`-m` option (a single dash, letters, ending in c or m, which also covers flag bundles like `-Bc`). Interpreter options with no script, such as `-X utf8` or `-u`, still alert, because sitecustomize runs with them. `-c` and `-m` are treated as near-misses: they run code named on the command line, legitimate tools use them, and there is a fixture for each. The cost is a bypass: `pythonw.exe -c pass` also loads sitecustomize. S5PIVOT's and VIPERTUNNEL's hooks only act when argc is 1, so the reported samples would not use it, but a variant could.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| `pythonw.exe -c pass` or `-m somemodule` | -c/-m excluded on purpose | Known bypass. The reported hooks need argc 1, so the observed samples would not use it. |
| Interpreter copied outside ProgramData / Users\Public (for example C:\PerfLogs, a user profile, Program Files) | Folder scope | Known gap. Kept narrow to the reported folders. |
| Option glued to a value containing c or m, for example `-Ximporttime` | Treated like -c/-m | Rare. No alert. |
| Task action runs cmd.exe or a .bat that then starts python | Parent is not Task Scheduler | Known gap. Covered partly by existing cmd/LOLBin task rules. |
| `-S` passed so site is not imported | Then no hook runs either | Not a bypass of the technique. Would still alert, since -S is an option with no script. |
| Interpreter renamed | Image-name regex only | Known gap (fixture knowngap_renamed_interpreter). No public ProcessRollup2 original-file-name field was confirmed for this rule. |

## Unverified
- How often the svchost parent is inside the 7-day join window in real tenants.
- Whether `!ParentCmdLine=*` behaves as "field absent" after a left join with no match (same pattern as merged DAC-CS-0252).
- FP rate for non-Schedule svchost parents that fall into svchost_unconfirmed.
- Query not run on the platform. telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0253/. Each has `"synthetic": true` and a `result` that says "not run". There is no LogScale runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_join_schedule_service | yes | would alert | match |
| malicious_join_miss_unconfirmed | yes | would alert | match |
| malicious_taskeng_parent | yes | would alert | match |
| benign_anaconda_allusers_script | no | no alert | match |
| near_miss_module_flag | no | no alert | match |
| near_miss_join_other_service | no | no alert | match |
| knowngap_renamed_interpreter | yes | no alert (known gap) | known gap |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | Payload never on the command line | bare `pythonw.exe` | Key on parent + folder + absence of a script argument |
| 2 | Must | ProcessRollup2 has no parent command line, so `-s Schedule` cannot be checked directly | svchost parent | Left join to the parent's ProcessRollup2; drop only on a confirmed non-Schedule parent |
| 3 | Must | Boot-time svchost is outside any practical join window | join miss | Keep and label svchost_unconfirmed instead of dropping |
| 4 | Should | Falcon image paths use `\Device\HarddiskVolumeN\` | `\Device\HarddiskVolume3\ProgramData\...` | Path regex accepts device and drive forms |
| 5 | Should | Quoted first token | `"C:\Users\Public\rt01\python.exe"` | Quoted-token regex in replace() |

## Reviewer status
pending
