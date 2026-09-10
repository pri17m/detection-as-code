# Query-Hub ProcessRollup Title Backlog (Wave D)

- Generated: 2026-09-10 12:40 IST
- Source: ByteRay-Labs/Query-Hub `queries/` (CQL Hub) + derived ProcessRollup2-family intents
- Future stub IDs: **DAC-CS-0063+** (do not reuse 0001–0062)
- Scope: titles only — **no YAML** in this wave plan
- Telemetry matrix: **FOUND** → `/workspace/dac-crowdstrike-telemetry/rollup_fields.json` (+ `EventSimpleName-inventory.csv`)
- Deduped against: box `/workspace/dac-phase1/detections/crowdstrike/` (DAC-CS-0013…0062) + `gh` main `detections/crowdstrike/` (DAC-CS-0001…0062)
- Kept titles: **58** | Dedupe/quality drops: **21**

## Inventory header (Query-Hub map)

| Path | Contents |
|---|---|
| `queries/` | ~182 YAML files; one CQL query each (`name`, `cql`, `mitre_ids`, `tags`, `log_sources`, `cs_required_modules`) |
| `lookup-files/` | CSV lookups (IP ranges, LOLBAS context, npm IOCs, etc.) |
| `.github/` | Validate + publish automation to cql-hub.com |

Organization: **flat** `queries/*.yml` (not per-vendor folders). CrowdStrike/Falcon/CQL is the whole repo. ProcessRollup family appears in ~59 queries via `#event_simpleName=ProcessRollup2` / `SyntheticProcessRollup2` / `ProcessBlocked`.

EventSimpleName→field docs in Query-Hub: **none** (contributing.md covers YAML schema only). Local Telemetry Researcher matrix supplies ProcessRollup field usage counts.

### ProcessRollup validated fields (local matrix)

Path: `/workspace/dac-crowdstrike-telemetry/rollup_fields.json`

**ProcessRollup2** (top fields by Query-Hub usage): `CommandLine`, `FileName`, `ImageFileName`, `ComputerName`, `UserName`, `ParentBaseFileName`, `CmdLower`, `RemoteAddressIP4`, `RemotePort`, `ScriptContent`, `SHA256HashData`, `UserSid`, `TargetProcessId`, `TargetFileName`, `OriginalFilename`, `ParentImageFileName`, `GrandParentBaseFileName`, `ParentProcessId`, `MD5HashData`, `SignInfoFlags`, … (75 keys total; some are query-local aliases).

**SyntheticProcessRollup2**: `FileName`, `ImageFileName`, `CommandLine`, `SHA256HashData`, `UserName`, `ComputerName`, `ParentImageFileName`, `RMMTool`.

Also: `/workspace/dac-crowdstrike-telemetry/EventSimpleName-inventory.csv` (ProcessRollup2 hits≈84 across Query-Hub corpus).

### Existing DAC-CS coverage (gap context)

- Remote main: **DAC-CS-0001…0062** (62 files). 0001–0012 are starter IOA/CQL candidates (encoded PS, Office→shell, regsvr32, mshta, rundll32, schtasks, sc, vssadmin, wevtutil, netsh firewall off, certutil, bitsadmin).
- Box stubs: **DAC-CS-0013…0062** (50 YAML). Style: `query.crowdstrike` **Custom IOA / boolean Falcon sketches** (CONTAINS / IN), **not** Next-Gen SIEM CQL pipes. Sourcetype: `falcon:process`. README: experimental IOA sketches for Platform absorb.
- Gap for Wave D: convert/extend toward **ProcessRollup2-first CQL** where IOA is weak; fill LOLBin/discovery/RMM/ClickFix/supply-chain themes **not** already titled in 0001–0062.

## Proposed Wave D / Query-Hub themes (titles only)

1. LOLBin ProcessRollup gaps (msiexec HTTP, rundll32 UNC ordinal, cmstp)
2. Parent/child anomalies (rare shell parent, non-shell→shell, browser→shell, Outlook→LOLBin)
3. Discovery & recon clustering (utility burst, AD toolset cluster, overnight post-RDP)
4. ClickFix / social-engineering staging (nslookup DNS staging, explorer paste chains, InstallFix macOS)
5. Remote access & tunneling (unauthorized RMM, plink/ssh port-forward)
6. Supply-chain / build-tool abuse (Rust/cargo, npm/pip/go spawn, Notepad++ children, Deno user-path)
7. Shadow AI / MCP agent runtimes
8. Credential exposure in CommandLine (plaintext password, net use/cmdkey)
9. Defense evasion clusters (firewall rule add, EDRCHOKER QoS, recovery-inhibition multi-tool, service-stop cluster)
10. Campaign packs (Charon, Gentlemen RaaS, Snowman, ROKRAT, SharePoint ToolShell)
11. Process↔network enrichment (external connect join, DNS from browsers, high port diversity, lateral movement ports)
12. Masquerade / side-load (OriginalFilename mismatch, DLL side-loading)

## Backlog table (DAC-CS-0063+ candidates)

| # | Proposed title | MITRE | EventSimpleName filter | Key fields | Query-Hub source |
|---:|---|---|---|---|---|
| 1 | Falcon: msiexec remote HTTP/HTTPS payload fetch | T1218.007 | `ProcessRollup2,ProcessBlocked` | CommandLine, ImageFileName, FileName, event_platform | `LOLBin_Msiexec.yml` |
| 2 | Falcon: non-shell application spawning cmd or PowerShell | T1059 | `ProcessRollup2` | ParentBaseFileName, FileName, aid, ComputerName, event_platform | `applications_spawning_cmd_or_powershell.yml` |
| 3 | Falcon: rare parent of cmd/powershell/pwsh | — | `ProcessRollup2` | CommandLine, FileName, aid, ComputerName, SHA256HashData, TargetProcessId, ParentProcessId, event_platform | `Rare_Windows_Shell_Parent.yml` |
| 4 | Falcon: rundll32 remote UNC DLL ordinal execution | T1218.011, T1105 | `ProcessRollup2` | CommandLine, ParentBaseFileName, FileName, UserName, ComputerName | `Rundll32_Remote_UNC_DLL_Ordinal_Execution.yml` |
| 5 | Falcon: Java/javaw executing JAR from AppData | T163 | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid, SHA256HashData | `jar_file_executed_from_appdata.yml` |
| 6 | Falcon: discovery/admin utility burst (whoami/net/nltest/sc) | — | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid, event_platform | `Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml` |
| 7 | Falcon: HTTP(S) to raw public IP in process CommandLine | T1105, T1059, T1071.001 | `ProcessRollup2,SyntheticProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, aid, ComputerName, GrandParentBaseFileName, TargetProcessId, ParentProcessId, event_platform, RawProcessId, ContextProcessId | `Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml` |
| 8 | Falcon: Rust build toolchain spawning interpreter or downloader | T1195.002, T1059 | `ProcessRollup2,SyntheticProcessRollup2` | CommandLine, ParentBaseFileName, FileName, UserName, ComputerName | `Rust_Build_Toolchain_Spawning_Interpreter_or_Downloader.yml` |
| 9 | Falcon: ClickFix-style nslookup DNS staging execution | T1071.004, T1059.001, T1204.002 | `ProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, ComputerName | `dns_staging_detection_clickfix_inspired_nslookup_execution.yml` |
| 10 | Falcon: shadow MCP server via node/python/npx/uv/docker | T1059, T1059.006 | `ProcessRollup2` | CommandLine, FileName, UserName, aid, ComputerName | `shadow_mcp_server_activity_via_common_runtime_interpreters.yml` |
| 11 | Falcon: unauthorized RMM/remote access tool execution | T1219 | `ProcessRollup2,SyntheticProcessRollup2` | CommandLine, ImageFileName, FileName, UserName, aid, ComputerName | `unauthorized_rmm_tool_usage.yml` |
| 12 | Falcon: plink remote port-forward to RDP (3389) | T1572, T1021.004 | `ProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, aid, ComputerName | `remote_port_forwarding_via_plink_unauthorized_rdp_tunneling_detection.yml` |
| 13 | Falcon: PowerShell command-length anomaly vs host baseline | T1059.001, T1027.010 | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid | `Hunting_Powershell_Command_Length_Anomaly.yml` |
| 14 | Falcon: process correlated with firewall rule addition | — | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid, TargetProcessId, ContextProcessId | `Firewall_Rule_Additions.yml` |
| 15 | Falcon: PowerShell CommandHistory correlated to process tree | T1059.001 | `CommandHistory,ProcessRollup2` | ImageFileName, ParentBaseFileName, FileName, aid, ComputerName, TargetProcessId, event_platform, RawProcessId | `Command_History_with_Process_Tree.yml` |
| 16 | Falcon: multi-tool discovery clustering on single host | — | `ProcessRollup2` | CommandLine, ParentBaseFileName, FileName, aid, ComputerName, ParentProcessId, event_platform | `Frequency_Analysis_via_Program_Clustering.yml` |
| 17 | Falcon: Windows discovery command execution count | — | `ProcessRollup2` | CommandLine, FileName, UserName, event_platform | `count_windows_discovery_commands.yml` |
| 18 | Falcon: plaintext password in process CommandLine | T1552 | `ProcessRollup2` | CommandLine, FileName, aid, ComputerName, event_platform | `applications_with_plaintext_passwords.yml` |
| 19 | Falcon: headless Chromium remote-debugging (macOS) | T1219, T1113 | `ProcessRollup2,SyntheticProcessRollup2` | CommandLine, ParentBaseFileName, FileName, UserName, aid, ComputerName, event_platform | `Headless_Chromium_Remote_Debugging_on_macOS.yml` |
| 20 | Falcon: InstallFix social-engineering pattern (macOS) | T1140, T1059.004 | `ProcessRollup2` | CommandLine, UserName, aid, ComputerName, TargetProcessId, event_platform | `installfix_on_macos.yml` |
| 21 | Falcon: macOS LaunchAgent/LaunchDaemon persistence | T1543.001, T1543.004 | `ProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, ComputerName, event_platform | `macOS_Persistence_via_Launch_Agents_and_Launch_Daemons.yml` |
| 22 | Falcon: overnight post-RDP discovery and staging activity | T1021.001, T1033, T1087.001, T1087.002, T1069.001, T1069.002, T1057, T1049, T1082, T1016, T1059.001, T1059.003, T1105, T1048, T1560.001, T1567 | `ProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, aid, ComputerName, SHA256HashData, OriginalFilename, GrandParentBaseFileName, event_platform | `overnight-post-rdp-activity.yml` |
| 23 | Falcon: EDRCHOKER QoS policy abuse targeting EDR/AV | T1562, T1562.001 | `ProcessRollup2` | CommandLine, ParentBaseFileName, FileName, ComputerName | `edrchoker_qos_policy_abuse_targeting_edr_av_processes.yml` |
| 24 | Falcon: Deno runtime from user-writable path (LeakNet-style) | T1204.001, T1059 | `ProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, aid, ComputerName, SHA256HashData, TargetProcessId, ContextProcessId | `leaknet_campaign_deno_runtime_klist_suspicious_execution_detection.yml` |
| 25 | Falcon: SharePoint ToolShell post-exploit process chain | T1190, T1620 | `ProcessRollup2` | CommandLine, ParentBaseFileName, FileName, aid, ComputerName, TargetProcessId, ParentProcessId, event_platform, ContextProcessId | `cve_2025_53770___sharepoint_toolshell.yml` |
| 26 | Falcon: OpenClaw agent runtime on endpoints | T1059 | `ProcessRollup2` | CommandLine, ImageFileName, FileName, UserName, aid, ComputerName | `find_openclaw_on_endpoints.yml` |
| 27 | Falcon: Snowman campaign process indicators | — | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid, ComputerName, TargetProcessId, ContextProcessId | `snowman.yml` |
| 28 | Falcon: Gentlemen RaaS precursor and defense-evasion cluster | T1059.001, T1562.001, T1490, T1070.004, T1082 | `ProcessRollup2,SyntheticProcessRollup2` | CommandLine, ParentBaseFileName, FileName, UserName, ComputerName, MD5HashData, OriginalFilename | `the_gentlemen_raas_custom_backdoors_and_evolving_tactics.yml` |
| 29 | Falcon: Charon ransomware process correlation | — | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid, ComputerName, SHA256HashData, OriginalFilename, TargetProcessId, ParentProcessId, ContextProcessId | `Charon_Ransomware_Detection_and_Correlation.yml` |
| 30 | Falcon: ROKRAT APT37 process and DNS indicators | — | `*ProcessRollup2,DnsRequest,*Written` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, ComputerName, SHA256HashData | `ROKRAT_Malware_APT_37.yml` |
| 31 | Falcon: Notepad++ supply-chain suspicious child processes | — | `Processrollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, SHA256HashData, OriginalFilename | `notepad_plus_plus_supply_chain_attack.yml` |
| 32 | Falcon: process launched from Outlook with URL arguments | T1566 | `ProcessRollup2` | CommandLine, ImageFileName, FileName, aid, MD5HashData, TargetProcessId, ParentProcessId | `Hunt_links_opened_from_Outlook.yml` |
| 33 | Falcon: external network connect enriched with ProcessRollup | — | `ProcessRollup2` | CommandLine, ImageFileName, FileName, UserName, aid, ComputerName, TargetProcessId, ContextProcessId | `External_Connectons_with_Process.yml` |
| 34 | Falcon: DNS resolutions attributed to browser processes | — | `ProcessRollup2` | FileName, UserName, aid, ComputerName, TargetProcessId, event_platform, ContextProcessId | `DNS_Resolutions_from_Browser_Processes.yml` |
| 35 | Falcon: host initiating connections to high port diversity | T1595, T1046 | `ProcessRollup2` | CommandLine, FileName, UserName, aid, ComputerName, TargetProcessId, ContextProcessId | `systems_initiating_connections_to_a_high_number_of_ports.yml` |
| 36 | Falcon: DLL side-loading via co-written EXE/DLL masquerade | T1574.001 | `ProcessRollup2` | CommandLine, ImageFileName, ParentBaseFileName, FileName, UserName, aid, ComputerName, SHA256HashData, OriginalFilename, TargetProcessId, ParentProcessId, ContextProcessId | `Dll-Side_Loading_Detection_Query.yml` |
| 37 | Falcon: lateral movement remote ports with process context | T1021.001, T1021.002, T1135 | `ProcessRollup2` | CommandLine, ImageFileName, FileName, UserName, aid, RawProcessId | `Lateral_Movement_Detection.yml` |
| 38 | Falcon: Chromium browser unusual DLL load hunt | — | `ProcessRollup2` | ImageFileName, FileName, aid, ComputerName, TargetProcessId | `chromium_based_browser_hunting_via_dll_load.yml` |
| 39 | Falcon: msiexec quiet install from user-writable path | T1218.007 | `ProcessRollup2,ProcessBlocked` | ImageFileName, CommandLine, event_platform | `(derived) msiexec user-writable` |
| 40 | Falcon: browsers spawning cmd or PowerShell | T1059 | `ProcessRollup2` | ParentBaseFileName, FileName, CommandLine | `(derived) browser shell` |
| 41 | Falcon: AD discovery toolset cluster (nltest/net/whoami/systeminfo) | T1087, T1069, T1016 | `ProcessRollup2` | FileName, CommandLine, aid, ComputerName | `(derived) AD discovery cluster` |
| 42 | Falcon: AnyDesk/TeamViewer/ScreenConnect first-seen on host | T1219 | `ProcessRollup2,SyntheticProcessRollup2` | ImageFileName, FileName, SHA256HashData, ComputerName | `(derived) RMM first-seen` |
| 43 | Falcon: ssh or plink reverse/local port-forward indicators | T1572 | `ProcessRollup2` | ImageFileName, CommandLine, ParentBaseFileName | `(derived) ssh/plink tunnel` |
| 44 | Falcon: node/python spawning with MCP or agent server flags | T1059.006 | `ProcessRollup2` | FileName, CommandLine, UserName | `(derived) MCP/agent` |
| 45 | Falcon: ClickFix LOLBin paste execution chain from explorer | T1204, T1059.003 | `ProcessRollup2` | ParentBaseFileName, ImageFileName, CommandLine | `(derived) ClickFix chain` |
| 46 | Falcon: script interpreter executing from AppData/Temp/Downloads | T1059 | `ProcessRollup2` | ImageFileName, CommandLine, FileName | `(derived) interpreters user path` |
| 47 | Falcon: package manager or build tool spawning shell/downloader | T1195.002, T1059 | `ProcessRollup2,SyntheticProcessRollup2` | ParentBaseFileName, FileName, CommandLine | `(derived) build tool supply chain` |
| 48 | Falcon: PowerShell IEX/DownloadString via CommandHistory join | T1059.001 | `CommandHistory,ProcessRollup2` | CommandLine, ImageFileName, aid | `(derived) CommandHistory IEX` |
| 49 | Falcon: netsh advfirewall rule add by unusual process path | T1562.004 | `ProcessRollup2` | ImageFileName, CommandLine | `(derived) netsh firewall add` |
| 50 | Falcon: LOLBin making external network connection (join) | T1105, T1071 | `ProcessRollup2` | ImageFileName, CommandLine, aid | `(derived) LOLBin external connect` |
| 51 | Falcon: recovery inhibition utility cluster (bcdedit+wbadmin+vssadmin) | T1490 | `ProcessRollup2` | FileName, CommandLine, ComputerName | `(derived) recovery wipe cluster` |
| 52 | Falcon: defense-evasion service stop cluster before ransomware | T1489, T1562.001 | `ProcessRollup2` | ImageFileName, CommandLine, ParentBaseFileName | `(derived) service stop cluster` |
| 53 | Falcon: nslookup/Resolve-DnsName to uncommon external nameserver | T1071.004 | `ProcessRollup2` | ImageFileName, CommandLine, ParentBaseFileName | `(derived) nslookup staging` |
| 54 | Falcon: net use or cmdkey with password in CommandLine | T1552, T1021 | `ProcessRollup2` | FileName, CommandLine, UserName | `(derived) net use password` |
| 55 | Falcon: Outlook spawning mshta/powershell/cmd with http args | T1566.001, T1059 | `ProcessRollup2` | ParentBaseFileName, ImageFileName, CommandLine | `(derived) Outlook LOLBin` |
| 56 | Falcon: wmic /node remote process or OS discovery | T1047, T1021 | `ProcessRollup2,ProcessBlocked` | ImageFileName, CommandLine | `(derived) wmic remote` |
| 57 | Falcon: cmstp INF proxy execution | T1218.003 | `ProcessRollup2` | ImageFileName, CommandLine | `(derived) cmstp` |
| 58 | Falcon: ImageFileName vs OriginalFilename mismatch | T1036.003 | `ProcessRollup2` | ImageFileName, OriginalFilename, SHA256HashData | `(derived) OriginalFilename mismatch` |

## Dedupe / quality drops

| Dropped title / source | Reason |
|---|---|
| `LOLBin_Certutil.yml` — Falcon: certutil URL/http download or decode | DAC-CS-0011,0057 |
| `LOLBin_Mshta.yml` — Falcon: mshta HTA/script execution | DAC-CS-0004,0035 |
| `LOLBin_Regsvr32.yml` — Falcon: regsvr32 scrobj.dll scriptlet | DAC-CS-0003 |
| `LOLBin_Rundll32.yml` — Falcon: rundll32 from Office/scripting parents | DAC-CS-0005,0014 |
| `LOLBin_WMIC.yml` — Falcon: wmic.exe broad LOLBin | DAC-CS-0038 |
| `Suspicious_PowerShell_Execution.yml` — Falcon: suspicious PowerShell encoded/unusual parent | DAC-CS-0001,0034 |
| `Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml` — Falcon: PowerShell EncodedCommand decode | DAC-CS-0001 |
| `Detect_and_Decode_Base64-Encoded_PowerShell_Commands-http.yml` — Falcon: PowerShell encoded HTTP cradle | DAC-CS-0001,0034 |
| `Credential_Dumping_Detection.yml` — Falcon: credential dump tool cmdline | DAC-CS-0013-0020,0015 |
| `hunting_bitsadmin_usage.yml` — Falcon: bitsadmin abuse | DAC-CS-0012,0030 |
| `ransomware_precursors.yml` — Falcon: ransomware precursor utilities | DAC-CS-0008,0047,0048,0049 |
| `applications_spawning_cmd_or_powershell.yml_OFFICE_ONLY` — Falcon: Office spawning cmd/powershell | DAC-CS-0002,0033 — covered; kept broader non-shell variant instead |
| `hunt_command_line.yml` — Hunt for specific Command Line Activity | low-value hunt helper / CVE scoping / non-detection-priority |
| `hunt_filename.yml` — Hunt for a file name | low-value hunt helper / CVE scoping / non-detection-priority |
| `processes_specific_host.yml` — Find processes that only ran a few of times on a specific host | low-value hunt helper / CVE scoping / non-detection-priority |
| `Decode_SignInfoFlags.yml` — Decode SignInfoFlags | low-value hunt helper / CVE scoping / non-detection-priority |
| `mongodb_processes_on_windows___linux_hosts__cve_2025_14847_.yml` — MongoDB Processes on Windows & Linux Hosts (CVE-2025-14847) | low-value hunt helper / CVE scoping / non-detection-priority |
| `cve_2025_59287___wsus_identification_vulnerability_query.yml` — CVE-2025-59287 - WSUS Identification+Vulnerability Query | low-value hunt helper / CVE scoping / non-detection-priority |
| `cve_2025_59287_vulnerable_wsus_servers_identification.yml` — CVE-2025-59287 vulnerable WSUS servers identification | low-value hunt helper / CVE scoping / non-detection-priority |
| `cve_2026_32202_windows_shell.yml` — CVE-2026-32202 - Windows Shell | low-value hunt helper / CVE scoping / non-detection-priority |
| `Crowdstrike_Falcon_0day_Privilege_Escalation_Vulnerability_FalconFlank.yml` — FalconFlank Exploit Artifacts (Named Pipe and Dropped DLL) | low-value hunt helper / CVE scoping / non-detection-priority |

## Next steps

1. Telemetry check: confirm required fields for each backlog row against `rollup_fields.json` before authoring.
2. Author stubs starting **DAC-CS-0063** as ProcessRollup2-oriented `query.crowdstrike` (prefer CQL-shaped filters where pack allows; keep IOA boolean only when Custom IOA is the delivery target).
3. Do **not** push to GitHub from Detection Engineer — Platform absorbs.

