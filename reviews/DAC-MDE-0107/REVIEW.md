# REVIEW - DAC-MDE-0107 MDE: Task Scheduler starts python.exe or pythonw.exe from ProgramData or Users\Public with no script

## Attribution
Clean-room behavioural rule written from public sources opened on 23 Nov 2026 (IST):
- https://hexastrike.com/resources/blog/threat-intelligence/s5pivot-a-python-backconnect-proxy-hidden-inside-a-qilin-ransomware-intrusion/
- https://labs.infoguard.ch/posts/slithering_through_the_noise/
- https://docs.python.org/3/library/site.html
- https://docs.python.org/3/using/windows.html
- https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring
- https://reinject.vercel.app/en/posts/windows-security/persistence/windows_schedule_task_internal/
- https://falconforce.nl/falconfriday-malicious-scheduled-tasks-0xff0b/
- https://threathunt.blog/hunting-for-malicious-scheduled-tasks/
- https://www.anaconda.com/docs/getting-started/advanced-install/multi-user
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
New defender rule DAC-MDE-0107 on DeviceProcessEvents. Image is python.exe or pythonw.exe by FileName or ProcessVersionInfoOriginalFileName (so a renamed copy still matches). FolderPath starts with `<drive>:\ProgramData\` or `<drive>:\Users\Public\`. Parent is taskeng.exe, or svchost.exe whose command line has `-s Schedule`, or a shared `netsvcs` host with no `-s`. ProcessCommandLine must be present and must have no script argument (see below). Columns are from the Microsoft Learn DeviceProcessEvents page. No CrowdStrike or Splunk query in this PR; DAC-CS-0253 and DAC-WIN-0366 are separate PRs.

## ATT&CK
T1053.005 (Scheduled Task), T1546.018 (Event Triggered Execution: Python Startup Hooks), T1059.006 (Python). Tactics persistence, execution, privilege-escalation (T1053.005 lists all three). The rule sees the task launch; the startup hook is why a bare launch matters, so T1546.018 is tagged even though the hook file itself is not in the query.

## False-positive check (before writing the query)
- Anaconda/Miniconda "All Users" installs go to `C:\ProgramData\Anaconda` or Anaconda3 by default (https://www.anaconda.com/docs/getting-started/advanced-install/multi-user). So "any python from ProgramData" was dropped as too noisy. Scheduled jobs on those installs pass a script (`.py`) or `-m module`, and those are excluded. No public source was found of Anaconda or Miniconda registering a task that runs a bare interpreter. The conda folders are not allowlisted, because the post says the same hook works in any standard CPython, including conda.
- Python-based agents under ProgramData: they start through a script or `-m`, so they are excluded by the argument check. A tool that relies on `.pth` or sitecustomize on purpose and starts with only interpreter options would alert; no public example was found.
- A bare interpreter launched with no stdin has nothing to run and exits, so a legitimate task has no reason to do it. The FP rate is not measured.

## Why this shape
Scheduled-task processes start under the svchost.exe instance hosting the Schedule service (`svchost.exe -k netsvcs -p -s Schedule`), and under taskeng.exe on older Windows (https://reinject.vercel.app/en/posts/windows-security/persistence/windows_schedule_task_internal/; FalconForce and threathunt.blog show the same parent in MDE data: https://falconforce.nl/falconfriday-malicious-scheduled-tasks-0xff0b/ , https://threathunt.blog/hunting-for-malicious-scheduled-tasks/). Microsoft documents that from Windows 10 1703 services are split into their own svchost on client SKUs with more than 3.5 GB RAM, and stay grouped on smaller systems (https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring). A grouped host has `-k netsvcs` without `-s`, so that case is matched as netsvcs_shared. No Microsoft Learn page was found that names the Task Scheduler child-process parent; the svchost/taskeng parent is from the community sources above.

The argument check strips the first token of the command line (quoted or not) and then requires that what is left has no `.py`, `.pyw`, `.pyc`, `.pyz` or `.zip` token and no `-c`/`-m` option (a single dash, letters, ending in c or m, which also covers flag bundles like `-Bc`). Interpreter options with no script, such as `-X utf8` or `-u`, still alert, because sitecustomize runs with them. `-c` and `-m` are treated as near-misses: they run code named on the command line, legitimate tools use them, and there is a fixture for each. The cost is a bypass: `pythonw.exe -c pass` also loads sitecustomize. S5PIVOT's and VIPERTUNNEL's hooks only act when argc is 1, so the reported samples would not use it, but a variant could.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| `pythonw.exe -c pass` or `-m somemodule` | -c/-m excluded on purpose | Known bypass. The reported hooks need argc 1, so the observed samples would not use it. |
| Interpreter copied outside ProgramData / Users\Public (for example C:\PerfLogs, a user profile, Program Files) | Folder scope | Known gap. Kept narrow to the reported folders. |
| Option glued to a value containing c or m, for example `-Ximporttime` | Treated like -c/-m | Rare. No alert. |
| Task action runs cmd.exe or a .bat that then starts python | Parent is not Task Scheduler | Known gap. Covered partly by existing cmd/LOLBin task rules. |
| `-S` passed so site is not imported | Then no hook runs either | Not a bypass of the technique. Would still alert, since -S is an option with no script. |
| Interpreter renamed | FileName check | Covered by ProcessVersionInfoOriginalFileName, unless the version resource is stripped. |

## Unverified
- Exact InitiatingProcessCommandLine text for the Schedule host across Windows builds. Community sources show `svchost.exe -k netsvcs -p -s Schedule`; older builds may hide `-s Schedule` (reinject).
- Whether FolderPath in DeviceProcessEvents always carries the drive-letter form (not a device path).
- FP rate on servers with conda or vendor Python under ProgramData.
- Query not run on the platform. telemetry_validated false.

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0107/. Each has `"synthetic": true` and a `result` that says "not run". There is no Advanced Hunting runner in this repo. As a supplement, the rule's logic was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_bare_pythonw_programdata_schedule | yes | would alert | match |
| malicious_quoted_python_users_public | yes | would alert | match |
| malicious_shared_netsvcs_host | yes | would alert | match |
| malicious_renamed_interpreter_ofn | yes | would alert | match |
| malicious_interpreter_option_only | yes | would alert | match |
| benign_anaconda_allusers_script | no | no alert | match |
| near_miss_module_flag | no | no alert | match |
| near_miss_c_flag | no | no alert | match |
| near_miss_explorer_parent | no | no alert | match |
| near_miss_other_svchost_service | no | no alert | match |
| near_miss_program_files | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | A command-line-only check misses this, because the payload is never on the command line | `pythonw.exe` (bare) | Key on parent + folder + absence of a script argument |
| 2 | Must | `has ".py"` style checks treat `pythonw.exe` itself as a script hit | `C:\ProgramData\x\pythonw.exe` | Strip the first token before looking for script tokens |
| 3 | Must | Quoted interpreter paths with spaces break a split-on-space first token | `"C:\Users\Public\rt 01\python.exe"` | First-token regex handles a quoted token |
| 4 | Should | svchost hosts many services; any svchost parent would include DcomLaunch and others | `svchost.exe -k DcomLaunch -p` | Require `-s Schedule`, or a grouped netsvcs host with no `-s` |
| 5 | Should | Low-RAM hosts group services, so `-s Schedule` is absent | `svchost.exe -k netsvcs -p` | netsvcs_shared branch |
| 6 | Should | Renamed interpreter | `svcupd.exe` with OriginalFileName pythonw.exe | Match ProcessVersionInfoOriginalFileName |
| 7 | Should | Empty command line would look like a bare interpreter | missing ProcessCommandLine | `isnotempty(ProcessCommandLine)` |

## Reviewer status
pending
