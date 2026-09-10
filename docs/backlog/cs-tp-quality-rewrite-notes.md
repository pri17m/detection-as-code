# TP-quality rewrite notes (course correction)

**Deliverable path:** `/workspace/dac-crowdstrike/tp-rewrite/` (TDE absorbs onto `feat/cs-query-hub-processrollup`).
**Scope this pass:** DAC-CS-0063 … DAC-CS-0089 (**27**). Enhance/` DAC-CS-0001+` **deferred** (steering). No DAC-CS-0090+.
**Tag:** `tp-rewrite` (+ `tp-quality-v2`). `telemetry_validated: false`. SAFE ESNs only.

## Gate summary
- Zero stubs with only `ImageFileName=*` / `CommandLine=*` wildcards
- Every query has ≥1 concrete ImageFileName / CommandLine / ParentBaseFileName (or ESN-appropriate) predicate
- No Splunk `index=`; no `splitString(..., index=N)`
- Joins use aid + ContextProcessId → TargetProcessId (or AuthenticationId for UserIdentity/UserLogon)
- Still-weak count: **0**

## IDs rewritten (27)

| ID | Query-Hub source | ESN coverage | Port / defer notes |
| --- | --- | --- | --- |
| DAC-CS-0063 | `LOLBin_Msiexec.yml` | ProcessRollup2,ProcessBlocked | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0064 | `Lateral_Movement_Detection.yml` | NetworkConnectIP4,ProcessRollup2,UserIdentity | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0065 | `unauthorized_rmm_tool_usage.yml` | ProcessRollup2,SyntheticProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0066 | `applications_with_plaintext_passwords.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0067 | `cve_2025_53770___sharepoint_toolshell.yml` | ProcessRollup2 | NewScriptWritten/WebScriptFileWritten deferred; kept w3wp→cmd and cmd→powershell ToolShell CommandLine predicates on PR2 |
| DAC-CS-0068 | `cve_2026_32202_windows_shell.yml` | ProcessRollup2 | SMB* ESNs (THIN) deferred; rewritten on ProcessRollup2 net use/ADMIN$/C$/IPC$ + shell-from-services predicates |
| DAC-CS-0069 | `chromium_based_browser_hunting_via_dll_load.yml` | ClassifiedModuleLoad,ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0070 | `count_windows_discovery_commands.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0071 | `DNS_Resolutions_from_Browser_Processes.yml` | ProcessRollup2,DnsRequest | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0072 | `dns_staging_detection_clickfix_inspired_nslookup_execution.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0073 | `Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0074 | `Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml` | ProcessRollup2,SyntheticProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0075 | `edrchoker_qos_policy_abuse_targeting_edr_av_processes.yml` | ProcessRollup2,RegGenericValue | WmiCreateProcess (THIN) and Reg*Update (CAUTION) dropped; used ProcessRollup2 + RegGenericValue (SAFE) |
| DAC-CS-0076 | `External_Connectons_with_Process.yml` | NetworkConnectIP4,ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0077 | `Crowdstrike_Falcon_0day_Privilege_Escalation_Vulnerability_FalconFlank.yml` | ProcessRollup2 | NamedPipeDetectInfo/NewExecutableWritten (CAUTION) deferred; PR2 Flanker/bcrypt CommandLine/ImageFileName predicates retained |
| DAC-CS-0078 | `find_openclaw_on_endpoints.yml` | ProcessRollup2 | FileWritten (CAUTION) deferred; PR2 install/gateway CommandLine predicates retained |
| DAC-CS-0079 | `jar_file_executed_from_appdata.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0080 | `leaknet_campaign_deno_runtime_klist_suspicious_execution_detection.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0081 | `mongodb_processes_on_windows___linux_hosts__cve_2025_14847_.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0082 | `overnight-post-rdp-activity.yml` | ProcessRollup2,UserLogon | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0083 | `ROKRAT_Malware_APT_37.yml` | ProcessRollup2,DnsRequest | *Written (CAUTION) deferred; PR2 SHA256 + mspaint parent + DnsRequest DomainName predicates retained |
| DAC-CS-0084 | `Rare_Windows_Shell_Parent.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0085 | `remote_port_forwarding_via_plink_unauthorized_rdp_tunneling_detection.yml` | ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0086 | `Rust_Build_Toolchain_Spawning_Interpreter_or_Downloader.yml` | ProcessRollup2,SyntheticProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0087 | `snowman.yml` | ProcessRollup2,NetworkConnectIP4,NetworkConnectIP6 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0088 | `systems_initiating_connections_to_a_high_number_of_ports.yml` | NetworkConnectIP4,ProcessRollup2 | Direct QH port (shortened analytics kept discriminating predicates) |
| DAC-CS-0089 | `the_gentlemen_raas_custom_backdoors_and_evolving_tactics.yml` | ProcessRollup2 | RegGenericValueUpdate/SuspiciousRegAsepUpdate/NewExecutableWritten deferred; PR2 TTP case retained |

## ESN coverage beyond ProcessRollup2

| ESN | Used in |
| --- | --- |
| ProcessBlocked | DAC-CS-0063 (LOLBin Msiexec OR) |
| SyntheticProcessRollup2 | DAC-CS-0065, 0074, 0086 |
| NetworkConnectIP4 | DAC-CS-0064, 0076, 0087, 0088 |
| NetworkConnectIP6 | DAC-CS-0087 |
| UserIdentity | DAC-CS-0064 |
| UserLogon | DAC-CS-0082 (LogonType=10 RDP join) |
| DnsRequest | DAC-CS-0071, 0083 |
| ClassifiedModuleLoad | DAC-CS-0069 |
| RegGenericValue | DAC-CS-0075 |

## Intentionally deferred (not still-weak)

| Source ESN / pattern | Why | Affected IDs |
| --- | --- | --- |
| SMB* Etw / brute-force share | THIN per AUTHORING-STATUS | DAC-CS-0068 |
| FirewallSetRule | THIN (enhance DAC-CS-0010 deferred this pass) | — |
| NamedPipeDetectInfo / NewExecutableWritten / *FileWritten / NewScriptWritten | CAUTION | DAC-CS-0067, 0077, 0078, 0083, 0089 |
| WmiCreateProcess / Reg*Update | THIN / CAUTION | DAC-CS-0075, 0089 |

## Sample before → after

### DAC-CS-0063 (gold LOLBin Msiexec)
**Before:** `#event_simpleName=ProcessRollup2` only + msiexec/http (sketch comment).
**After:**
```
in(#event_simpleName, values=["ProcessRollup2","ProcessBlocked"])
| event_platform=Win and ImageFileName=/msiexec.exe/i and CommandLine=/http/i
| groupBy([aid, ComputerName, ImageFileName, CommandLine, ParentBaseFileName], function=count())
```

### DAC-CS-0084 (previously weak — analytics-only, no concrete ImageFileName)
**Before:** IsChild case/groupBy rarity without forcing shell ImageFileName filter.
**After:**
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell|cmd|pwsh)\.exe$/i
| !in(field=ParentBaseFileName, values=["explorer.exe","cmd.exe","powershell.exe","pwsh.exe","services.exe","svchost.exe","userinit.exe","winlogon.exe"], ignoreCase=true)
| table([aid, ComputerName, ParentBaseFileName, ImageFileName, CommandLine, ParentProcessId, TargetProcessId, SHA256HashData])
| groupBy([ParentBaseFileName, SHA256HashData], function=[count(ComputerName, distinct=true, as=HostCount), collect([aid, ImageFileName, CommandLine], limit=10)])
| HostCount<5
| sort(HostCount, order=asc)
```

## Out of scope / blockers
- Enhance set (11 files) **not** rewritten this pass — await TDE absorb of tp-rewrite/
- DAC-CS-0090+ all-ESN expansion **not** authored
- No GitHub push
- Blockers: none for the 27; deferred ESN predicates documented above (not counted as still-weak)

