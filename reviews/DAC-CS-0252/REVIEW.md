# REVIEW - DAC-CS-0252 Falcon: Java or Tomcat service-account process starts cmd or PowerShell

## Attribution
Clean-room behavioural rule written from public sources opened on 19 Nov 2026 (IST). Field names were taken only from CrowdStrike public material, not from any work tenant or console:

- https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Use%20Join%20on%20Two%20Scoped%20Events.md
- https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/ProcessRollup2%20Curation.md
- https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Using%20correlate%28%29%20to%20hunt%20process%20lineage.md
- https://library.humio.com/crowdstrike-query-language/functions-join.html
- Behavioural sources shared with DAC-MDE-0106: Tomcat Windows service howto, ATT&CK T1190 / T1059.003 / T1059.001, Fortinet CVE-2022-26134, VulnCheck CVE-2023-22527. SigmaHQ cited for reference only (dff1e1cc-d3fd-47c8-bfc2-aeb878a754c0, 8202070f-edeb-4d31-a010-a26c72ac5600, 1ddaa9a4-eb0b-4398-a9fe-7b018f9e23db).

No detections.ai content, no employer data, no CrowdStrike console or Events Data Dictionary from a work tenant. Fixtures are synthetic. The rule does not use process names, service names, PIDs or paths from a process-tree screenshot that was shown while the MDE companion was scoped.

## As-is (new)
No Falcon rule on main at 70057c70 mentioned java.exe, javaw.exe, tomcat or Confluence. Closest coverage:
- DAC-CS-0245 / DAC-CS-0211: PHP, IIS, nginx or httpd parents spawning a shell. The parent list does not include Java or Tomcat.
- DAC-CS-0084: rare cmd/powershell parent. Rarity-based, not a fixed Java/Tomcat parent list, and it does not look at the account SID.
- DAC-CS-0111 / 0113 / 0114: `join()` of NetworkConnect to ProcessRollup2 on ContextProcessId / TargetProcessId, not a parent-account join.
- DAC-MDE-0106 (open PR #132, not on main when this was written): the Defender companion this rule is meant to match.

## After
New crowdstrike rule DAC-CS-0252 on ProcessRollup2. Companion to DAC-MDE-0106. The child is cmd.exe, powershell.exe or pwsh.exe (`ImageFileName`). The parent name is read from `ParentBaseFileName` on the child event (`java.exe`, `javaw.exe`, `prunsrv.exe`, or `tomcat` plus optional digits plus `.exe`). The parent account is not on the child event. Public community queries join the parent's ProcessRollup2 with `field=[aid, ParentProcessId], key=[aid, TargetProcessId]`. That pattern is used here as a left join (`mode=left`, `start=7d`) so a long-running service whose start event is outside the main window can still be enriched when the parent event is in the last 7 days. The subquery is limited to java/tomcat/prunsrv image names or a `//RS//` command line, to keep the join set smaller than the default 100,000-row subquery limit.

When the join does not return a parent UserSid, the rule falls back to the child's `UserSid` in S-1-5-19 or S-1-5-20. That covers the normal first hop, where the shell inherits the service token, and does not require the parent's start event to be in the window. `//RS//` on a renamed procrun binary is only visible when the join returns `ParentCmdLine`. ProcessRollup2 is not treated as having a native ParentCommandLine field; that name was not confirmed in the public sources opened for this review.

## Field sources
| Field | Role | Public source |
|---|---|---|
| `#event_simpleName=ProcessRollup2`, `event_platform=Win`, `aid`, `ImageFileName`, `CommandLine`, `ParentBaseFileName`, `ParentProcessId`, `TargetProcessId`, `ComputerName` | Child event and join keys | logscale-community-content ProcessRollup2 Curation, Use Join on Two Scoped Events, correlate() process lineage |
| `UserSid` | Account SID of the process the ProcessRollup2 event describes (the child on the main event; the parent on the joined event) | ProcessRollup2 Curation.md groups ProcessRollup2 by `UserSid` and only then joins UserIdentity for `UserName` (the comment says UserName / ComputerName may be absent on FDR, not that UserSid is missing) |
| `UserName` | Output / enrichment only, not used as the account gate | correlate() include lists; Curation.md notes it may be absent on FDR |
| Parent account and parent command line | Left join, parent fields renamed to `ParentUserSid`, `ParentUserName`, `ParentImageFileName`, `ParentCmdLine` before `include=` | Use Join on Two Scoped Events.md (`key=[aid, TargetProcessId], field=[aid, ParentProcessId]`); join() docs for `mode=left`, `start=`, `include=` |

## ATT&CK v19.2
T1190, T1059.003, T1059.001. Tactics initial-access, execution. Same tagging as DAC-MDE-0106. T1685 is not tagged; this rule does not key on Defender tamper.

## Existing overlap in this repo
See As-is. DAC-CS-0084 may fire on the same shell if the parent is rare, but it will not say that the parent was a Java service account.

## Bypass / gap table
| Bypass | Why | Mitigation / status |
|---|---|---|
| Service runs as a custom account or as SYSTEM | Account filter is only S-1-5-19 and S-1-5-20 | Known gap, same as DAC-MDE-0106 |
| First child is not cmd, powershell or pwsh | Child filter | Known gap |
| Renamed procrun binary, join missed, no `//RS//` on the child event | `//RS//` is only on the parent command line, which comes from the join | Known gap. ParentBaseFileName still catches java / tomcat[0-9]* / prunsrv when the name is not changed |
| Parent is NETWORK SERVICE, child is already SYSTEM, and the parent event is outside the 7d join window | Child-SID fallback requires the child to still hold the service SID | Known gap. The fallback is for the first hop, not the later privilege-change hop |
| tomcat9w.exe (the GUI monitor) | Parent regex is `^(java\|javaw\|prunsrv\|tomcat[0-9]*)\.exe$` | Intended |
| Join subquery exceeds the default 100,000-row limit in a large estate | `join()` limit | Subquery is pre-filtered; limit and `start=7d` are unmeasured starting points |
| Jenkins path not available because the join missed | Path exclusion uses joined `ParentImageFileName` | Documented FP |

## Unverified
- Whether every Falcon tenant and pipeline (NG-SIEM live vs FDR) always fills `UserSid` on ProcessRollup2. The public Curation query treats it as present.
- Whether `start=7d` is long enough for typical Tomcat uptime, and whether the subquery stays under the join row limit.
- ImageFileName prefix (`\Device\HarddiskVolumeN\` vs `C:\`). The regexes are anchored at the file name, not the drive prefix.
- Query not run in LogScale or NG-SIEM. telemetry_validated false.
- In-the-wild exploitation of CVE-2026-114938. The CVE is confirmed in public advisories (see DAC-MDE-0106 REVIEW); it is not used as match logic here and is not in CISA KEV as of the 19 Nov 2026 catalog fetch used for that review.

## Tests
Synthetic fixtures under tests/cases/DAC-CS-0252/. Each has `"synthetic": true` and a `result` that says "not run". There is no LogScale runner in this repo. As a supplement, the rule's logic (including the left join on aid + ParentProcessId / TargetProcessId) was mirrored in Python and applied to the fixture events. That checks the logic only, not the query language.

| Fixture | Expect alert | Mirror check | Result |
|---|---|---|---|
| malicious_tomcat9_join_parent_sid | yes | would alert | match |
| malicious_java_child_fallback | yes | would alert | match |
| malicious_renamed_procrun_rs | yes | would alert | match |
| benign_interactive_java_user | no | no alert | match |
| near_miss_w3wp_networkservice | no | no alert | match |
| near_miss_tomcat9w_monitor | no | no alert | match |
| near_miss_jenkins_path | no | no alert | match |

## Ponytail findings (applied before PR)
| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Must | ProcessRollup2 `UserSid` is the child process, not the parent | Parent tomcat9.exe as NETWORK SERVICE, child already SYSTEM | Left-join the parent's ProcessRollup2 on aid + ParentProcessId / TargetProcessId and gate on `ParentUserSid` when the join hits |
| 2 | Must | An inner join drops the first hop when the service started before the search window | tomcat9.exe started 30 days ago, cmd.exe started today, no parent event | `mode=left` and a child-`UserSid` fallback only when `ParentUserSid` is empty |
| 3 | Must | An unfiltered 7-day ProcessRollup2 subquery can hit the join row limit and silently drop parents | Busy estate, default limit 100000 | Restrict the subquery to java/javaw/prunsrv/tomcat[0-9]* or `//RS//` |
| 4 | Must | A locale-dependent UserName gate fails when the name is not English, and UserName may be absent on FDR | UserName empty, UserSid still S-1-5-20 | Gate on UserSid / ParentUserSid, not UserName |
| 5 | Should | Native ParentCommandLine was not confirmed in the public sources opened here | Using an unconfirmed field | Use joined `ParentCmdLine` (parent `CommandLine`) only |
| 6 | Should | `endswith tomcat.exe` misses tomcat9.exe; `tomcat9w.exe` is the GUI monitor | `tomcat9.exe` / `tomcat9w.exe` | Parent regex `^(java\|javaw\|prunsrv\|tomcat[0-9]*)\.exe$` |

## Reviewer status
pending
