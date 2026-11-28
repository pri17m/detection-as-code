# REVIEW - DAC-MDE-0119 MDE: script file written into a web root by a web server, database engine or shell under them

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 13 is the starting shape (script extension + web-root path + not a deployment tool); this rule inverts it to an allowlist of suspicious writers so it does not depend on listing every deploy tool, and it does not match the file names GTIG published. No query text was copied.
- Google Threat Intelligence Group, ARTEX and Friends (MySQL general_log_file set to a web-accessible .jsp, then `SELECT '<% ... %>'`; incrementing shell names): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence Hunt 13 ('A script file created by mysqld, sqlservr.exe, java or w3wp.exe itself deserves attention first'): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- DeviceFileEvents schema (ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName): https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table
- ATT&CK v19.2 T1505.003 Web Shell (persistence): https://attack.mitre.org/techniques/T1505/003/

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H13 was a Gap: no rule on main matched script files written under a web root.

## After
New defender rule DAC-MDE-0119. Script extension, web-root path class, and writer class (web server / app runtime, database engine, or a shell whose parent is one of those). Bulk writes of 25+ files in 10 minutes by a web server are dropped as deploys; database-engine and shell writers always alert.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Web shell with a non-script extension that the server is configured to execute (.txt via handler mapping, .war, .config) | T1505.003 | https://attack.mitre.org/techniques/T1505/003/ | yes | high | known gap | Would need per-server handler config; .config / web.config edits are a separate rule idea. |
| Drop outside a standard web root (custom site path such as D:\Sites\app) | T1505.003 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | n/a | known gap | Path list is the standard defaults only. Add site roots per environment. |
| Pad the drop with 25+ junk files from the web server process | T1505.003 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | low | known gap | Bulk exemption only applies to web-server writers; a deliberate pad would hide it. Database and shell writers are not exempt. |
| Write via a deployment channel (Kudu, FTP publishing, msdeploy) with stolen publishing credentials | T1505.003 / T1078.004 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | partly | medium | out of scope | Writer is a deploy tool, not a web server. Covered by the first-seen Kudu/FTP publishing rule in this batch, not here. |
| Rename an existing file to .aspx | T1505.003 | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table | yes | low | covered | FileRenamed is in scope. |
| Postgres COPY ... TO a web root | T1505.003 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | low | covered | postgres is in the engine list (not seen on a sample). |

## FP check
Expected benign hits: CMS plugin installs that write a few .php files, small Tomcat hot deploys, ASP.NET CMSs that write views. Normal publishing by msdeploy/git/rsync does not match because those writers are not in the list. Volume not measured; no tenant data used.

## Unverified ideas
- Whether MDE records MySQL general_log writes as FileModified on every SQL statement or only on file create (affects how many rows one shell attempt produces).
- Exact FolderPath content (folder only per Learn, or folder plus file name as seen in many hunting examples); the regex works either way, not confirmed on a sample.
- Whether node or nginx write script files in real web roots often enough to need their own threshold.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0119/ (synthetic, not run).

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_mysqld_general_log_writes_jsp | yes | alert | match |
| malicious_w3wp_upload_writes_aspx | yes | alert | match |
| malicious_cmd_under_w3wp_echoes_aspx | yes | alert | match |
| benign_msdeploy_publish | no | no alert | match |
| benign_tomcat_war_expansion | no | no alert | match |
| near_miss_w3wp_writes_aspx_outside_web_root | no | no alert | match |

CI validate: see PR checks. Not run in Advanced Hunting.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Deploy-tool exclusion list (Hunt 13) lets any unlisted writer fire, including robocopy, Octopus or custom deploy agents | robocopy.exe writing 200 .aspx | Inverted to a suspicious-writer allowlist |
| 2 | A web server writing scripts is not always a shell: WAR expansion writes many JSPs | java writing 60 .jsp | Bulk exemption for web-server writers only |
| 3 | Shell under w3wp writing the file is missed if only the direct writer is checked | cmd.exe (parent w3wp) -> status2.aspx | InitiatingProcessParentFileName checked for shells |
| 4 | `has_any` on backslash paths is term-based and fragile | FolderPath `C:\inetpub\wwwroot` | Anchored regex with both separators |
| 5 | Matching published shell names (cl1217.jsp etc.) is an IOC and rots | q7731.jsp | No file-name match; names only appear in FileSample |

## Reviewer status
- pending human approval
