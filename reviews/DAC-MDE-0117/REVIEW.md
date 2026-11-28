# REVIEW - DAC-MDE-0117 MDE: sqlservr or mysqld starts a shell

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 11 groups many service parents and many tools with a 5-distinct-commands threshold; this rule is narrower (database engines and shells only) and fires on one event. SigmaHQ rules are cited as prior art for patterns and false positives, not converted. No query text was copied.
- ThreatDefence Hunt 11 (sqlservr.exe, mysqld among the service processes) and Hunt 21: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- DeviceProcessEvents schema: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table
- xp_cmdshell (Microsoft Learn: 'Spawns a Windows command shell'; 'The Windows process spawned by xp_cmdshell has the same security rights as the SQL Server service account'): https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
- AhnLab ASEC, MySQL UDF abuse ('MySQL does not support direct OS commands such as xp_cmdshell. It can, however, use ... User-defined Function (UDF) to ultimately allow threat actors to execute commands'): https://asec.ahnlab.com/en/58878/
- LevelBlue SpiderLabs MySQL UDF honeypot write-up: https://www.levelblue.com/blogs/spiderlabs-blog/honeypot-recon-mysql-malware-infection-via-user-defined-functions-udf/
- SigmaHQ 869b9ca7-9ea2-4a5a-8325-e80e62f75445 (Suspicious Child Process Of SQL Server; DATEV optional filter): https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mssql_susp_child_process.yml
- SigmaHQ d55b793d-f847-4eea-b59a-5ab09908ac90 (Veeam SQL instance children, FIN7): https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_mssql_veaam_susp_child_processes.yml
- SigmaHQ c61daa90-3c1e-4f18-af62-8f288b5c9aaf (mysqld writing executable files, UDF abuse): https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.yml
- ATT&CK v19.2: T1505.001 SQL Stored Procedures (persistence; detection notes mention xp_cmdshell and UDF), T1059.003, T1059.001, T1059.004, T1190.

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H11 was Partial: PHP / httpd / w3wp (DAC-CS-0245, DAC-MDE-0096) and Java / Tomcat (DAC-CS-0252, DAC-MDE-0106) are covered; sqlservr, mysqld, nginx and node are not. No rule on main mentioned sqlservr or mysqld.

## After
New defender rule DAC-MDE-0117: database engine parent, shell child, Windows and Linux names. nginx and node are left out: both legitimately start shells in some deployments (build hooks, npm scripts) and no source opened on this pass rates that noise.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| UDF runs the payload directly with ShellExecute (no shell) | T1505.001 | https://www.levelblue.com/blogs/spiderlabs-blog/honeypot-recon-mysql-malware-infection-via-user-defined-functions-udf/ | yes | medium | known gap | Child would be the payload exe, not a shell. A 'database engine starts any non-engine binary' variant needs a baseline of normal engine children (SqlDumper, etc.). |
| SQL Agent job (CmdExec step) instead of xp_cmdshell | T1053 / T1505.001 | https://asec.ahnlab.com/en/58878/ | yes | high | dropped | Parent is SQLAGENT.EXE, which runs scheduled batch jobs normally. Benign fixture covers it. |
| CLR stored procedure or OLE Automation (sp_OACreate) | T1505.001 | https://asec.ahnlab.com/en/58878/ | partly | unknown | known gap | May run code in-process or start other binaries; no shell child guaranteed. |
| Write a web shell from the database (INTO OUTFILE) instead of running a shell | T1505.003 | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_mysqld_uncommon_file_creation.yml | yes, different table | medium | out of scope | File-event rule (ThreatDefence Hunt 13 / web-root drops) is a separate gap. |
| Renamed shell binary | T1036 | https://attack.mitre.org/techniques/T1036/ | yes | unknown | known gap | FileName match only. |

## Unverified ideas
- MariaDB on Windows binary name (mariadbd.exe) appearing in DeviceProcessEvents; included because it is the Windows form of the mariadbd name, not seen on a sample.
- Postgres (postgres spawning sh via COPY ... PROGRAM). No source opened on this pass.
- Real-world xp_cmdshell prevalence; not measured.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0117/ (synthetic, not run).

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_xp_cmdshell_whoami | yes | alert | match |
| malicious_mysqld_linux_udf_bash | yes | alert | match |
| malicious_sqlservr_powershell_download | yes | alert | match |
| benign_sqlagent_job_cmd | no | no alert | match |
| near_miss_sqlservr_spawns_sqldumper | no | no alert | match |
| near_miss_mysqld_safe_starts_mysqld | no | no alert | match |

CI validate: see PR checks. Not run in Advanced Hunting.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | A 5-distinct-commands threshold (Hunt 11) misses a single careful xp_cmdshell call | one `cmd.exe /c whoami` | Alert on one event; engines rarely start shells |
| 2 | Windows-only names miss Linux MySQL | mysqld -> bash | Linux names (mysqld, mariadbd, sh, bash, dash, zsh) included |
| 3 | Case differences in image names | SQLSERVR.EXE | `in~` |
| 4 | Excluding Veeam outright would hide FIN7-style abuse | sqlservr -sVEEAMSQL2016 -> cmd | VeeamInstance flag column only |
| 5 | mysqld_safe wrapper shells are parents of mysqld, not children | bash -> mysqld | Direction enforced (engine must be the initiating process) |

## Reviewer status
- pending human approval
