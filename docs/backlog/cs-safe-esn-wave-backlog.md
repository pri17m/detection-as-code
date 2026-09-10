# SAFE ESN expansion wave backlog (DAC-CS-0090+)

**Path:** `/workspace/dac-crowdstrike/safe-esn/`  
**Gate:** AUTHORING-STATUS.md SAFE only (mass YAML)  
**Tags:** `safe-esn-wave`, `tp-quality-v2`  
**telemetry_validated:** false  

**Count:** 48 rules (`DAC-CS-0090` … `DAC-CS-0137`)

| ID | Title | MITRE | ESNs | QH source |
| --- | --- | --- | --- | --- |
| DAC-CS-0090 | Suspicious Scheduled Task Creation | T1053, T1053.005 | `ScheduledTaskRegistered` | `suspicious_scheduled_task_creation.yml` |
| DAC-CS-0091 | Hidden Scheduled Task Registration | T1053.005 | `ScheduledTaskRegistered` | `hidden_scheduled_tasks.yml` |
| DAC-CS-0092 | Scheduled Task with ComHandler Action | T1053.005, T1546 | `ScheduledTaskRegistered` | `tasks_scheduled_with_ComHandler.yml` |
| DAC-CS-0093 | Scheduled Task Highest Privileges RunLevel | T1053.005 | `ScheduledTaskRegistered` | `tasks_scheduled_by_run_level.yml` |
| DAC-CS-0094 | Scheduled Task Logon Trigger | T1053.005 | `ScheduledTaskRegistered` | `logon_events.yml` |
| DAC-CS-0095 | Scheduled Task Boot/Startup Trigger | T1053.005 | `ScheduledTaskRegistered` | `startup_events.yml` |
| DAC-CS-0096 | Remotely Registered Scheduled Task | T1053.005, T1021 | `ScheduledTaskRegistered` | `suspicious_scheduled_task_creation.yml` |
| DAC-CS-0097 | Failed User Logon Thresholding | T1110, T1110.001 | `UserLogonFailed2` | `Failed_User_Logon_Thresholding.yml` |
| DAC-CS-0098 | Failed and Successful User Logon Correlation | T1110, T1078 | `UserLogon, UserLogonFailed2` | `Failed_and_Successful_User_Logon_Events.yml` |
| DAC-CS-0099 | Remote Interactive Logons (RDP) | T1021.001 | `UserIdentity` | `remote_interactive_logons__rdp_.yml` |
| DAC-CS-0100 | Built-in Administrator RID-500 Logon | T1078, T1078.001 | `UserLogon` | `Honey_Token_Account_Logon.yml` |
| DAC-CS-0101 | Generic Shared Account Logon Usage | T1078 | `UserLogon` | `detection_of_generic_user_account_usage.yml` |
| DAC-CS-0102 | Admin Interactive or RDP Logon Details | T1078, T1021.001 | `UserLogon` | `user_logon_details__time__type__location__last_password_change_.yml` |
| DAC-CS-0103 | Network Logon Type 3 via UserIdentity | T1021.002, T1078 | `UserIdentity` | `remote_interactive_logons__rdp_.yml` |
| DAC-CS-0104 | DNS over HTTPS Provider Resolutions | T1071.004, T1568 | `DnsRequest` | `DoH_traffic.yml` |
| DAC-CS-0105 | GenAI Service DNS Usage | T1048, T1071.004 | `DnsRequest` | `GenAI_Usage.yml` |
| DAC-CS-0106 | RMM Tool DNS Resolutions | T1219, T1219.002 | `DnsRequest` | `detect_rmm_dns.yml` |
| DAC-CS-0107 | GenAI DNS from Non-Browser Processes | T1071.004, T1059 | `DnsRequest` | `detection_of_dns_requests_to_ai_related_domains.yml` |
| DAC-CS-0108 | Suspicious DNS from Scripting Engines | T1071.004, T1059 | `DnsRequest, ProcessRollup2` | `DNS_Resolutions_from_Browser_Processes.yml` |
| DAC-CS-0109 | C2 Beaconing Cadence on NetworkConnectIP4 | T1071, T1571, T1041 | `NetworkConnectIP4` | `c2_beaconing_detection.yml` |
| DAC-CS-0110 | Rare Remote Ports in Network Connections | T1571, T1046 | `NetworkConnectIP4` | `Bottom_10_Percent_of_NetworkConnct_Port_Values.yml` |
| DAC-CS-0111 | Tor-Associated Port Egress NetworkConnectIP4 | T1090.003, T1571 | `NetworkConnectIP4, ProcessRollup2` | `connections_to_tor_exit_nodes.yml` |
| DAC-CS-0112 | Scripting Engine Outbound NetworkConnectIP4 | T1071, T1059 | `NetworkConnectIP4, ProcessRollup2` | `External_Connectons_with_Process.yml` |
| DAC-CS-0113 | NetworkConnectIP6 External Egress with Process | T1071, T1571 | `NetworkConnectIP6, ProcessRollup2` | `snowman.yml` |
| DAC-CS-0114 | LOLBin Outbound NetworkConnectIP4 | T1071, T1218 | `NetworkConnectIP4, ProcessRollup2` | `External_Connectons_with_Process.yml` |
| DAC-CS-0115 | PowerShell Downloads via CommandHistory | T1059.001, T1105 | `CommandHistory` | `Powershell_Downloads.yml` |
| DAC-CS-0116 | Encoded or Obfuscated CommandHistory | T1059.001, T1027 | `CommandHistory` | `Command_History_with_Process_Tree.yml` |
| DAC-CS-0117 | CommandHistory with Process Tree Join | T1059.001 | `CommandHistory, ProcessRollup2` | `Command_History_with_Process_Tree.yml` |
| DAC-CS-0118 | ScriptControlScanV2 BitsTransfer Download | T1197, T1105 | `ScriptControlScanV2` | `hunting_bitsadmin_usage.yml` |
| DAC-CS-0119 | ScriptControlScanV2 WebClient Download Cradle | T1059.001, T1105 | `ScriptControlScanV2` | `Powershell_Downloads.yml` |
| DAC-CS-0120 | ScriptControlScanV2 AMSI Bypass Patterns | T1562.001, T1059.001 | `ScriptControlScanV2` | `Suspicious_PowerShell_Execution.yml` |
| DAC-CS-0121 | Suspicious ASEP Registry via RegGenericValue | T1547.001, T1112, T1546.008, T1546.010 | `RegGenericValue` | `Suspicious_Registry_Modifications.yml` |
| DAC-CS-0122 | ClickFix-style RunMRU Interpreter via RegGenericValue | T1204, T1059 | `RegGenericValue` | `clickfix_run_dialog_command_detection.yml` |
| DAC-CS-0123 | Security Service Disable via RegGenericValue | T1562.001, T1112 | `RegGenericValue` | `Suspicious_Registry_Modifications.yml` |
| DAC-CS-0124 | BYOVD Known Vulnerable DriverLoad | T1068, T1014 | `DriverLoad` | `byovd_driver_load_with_edr_av_process_termination_medusa_ransomware.yml` |
| DAC-CS-0125 | DriverLoad from User-Writable Path | T1014, T1068 | `DriverLoad` | `byovd_driver_load_with_edr_av_process_termination_medusa_ransomware.yml` |
| DAC-CS-0126 | ClassifiedModuleLoad Original Filename Mismatch | T1036, T1574.002 | `ClassifiedModuleLoad` | `Dll-Side_Loading_Detection_Query.yml` |
| DAC-CS-0127 | ClassifiedModuleLoad MOTW or Unusual Extension | T1553.005, T1574 | `ClassifiedModuleLoad` | `Dll-Side_Loading_Detection_Query.yml` |
| DAC-CS-0128 | ClassifiedModuleLoad from Temp or AppData | T1574.001, T1574.002 | `ClassifiedModuleLoad, ProcessRollup2` | `Dll-Side_Loading_Detection_Query.yml` |
| DAC-CS-0129 | ClassifiedModuleLoad into Signed Microsoft Binary from User Path | T1574.001 | `ClassifiedModuleLoad` | `Dll-Side_Loading_Detection_Query.yml` |
| DAC-CS-0130 | ProcessBlocked Certutil Download Pattern | T1105, T1140 | `ProcessBlocked, ProcessRollup2` | `LOLBin_Certutil.yml` |
| DAC-CS-0131 | ProcessBlocked Mshta Remote Pattern | T1218.005 | `ProcessBlocked, ProcessRollup2` | `LOLBin_Mshta.yml` |
| DAC-CS-0132 | Credential Dump Tools with UserIdentity Join | T1003.001, T1003.002 | `ProcessRollup2, UserIdentity, SyntheticProcessRollup2` | `Credential_Dumping_Detection.yml` |
| DAC-CS-0133 | NetworkConnectIP4 Join SyntheticProcessRollup2 Rare Hash | T1071, T1036 | `NetworkConnectIP4, ProcessRollup2, SyntheticProcessRollup2` | `External_Connectons_with_Process.yml` |
| DAC-CS-0134 | UserLogonFailed2 Password Spray Across Hosts | T1110.003 | `UserLogonFailed2` | `Failed_User_Logon_Thresholding.yml` |
| DAC-CS-0135 | Scheduled Task PowerShell Encoded Download | T1053.005, T1059.001 | `ScheduledTaskRegistered` | `suspicious_scheduled_task_creation.yml` |
| DAC-CS-0136 | DnsRequest Suspicious Long Subdomain | T1071.004, T1568.002 | `DnsRequest` | `DoH_traffic.yml` |
| DAC-CS-0137 | NetworkConnectIP4 High RemotePort from Interpreters | T1571, T1071 | `NetworkConnectIP4, ProcessRollup2` | `c2_beaconing_detection.yml` |

## Skipped (CAUTION / THIN)

| ESN / pattern | Why skipped |
| --- | --- |
| FirewallSetRule | CAUTION — not mass YAML this wave |
| MotwWritten | CAUTION — sparse QH (1 query) |
| CreateService | CAUTION — sparse corpus |
| FileWritten / PeFileWritten / NewExecutableWritten | CAUTION — corpus-observed only |
| RegGenericValueUpdate / AsepValueUpdate / RegSystemConfigValueUpdate | CAUTION — prefer RegGenericValue (DAC-CS-0121/0122 SAFE ports) |
| TerminateProcess (BYOVD join) | THIN — BYOVD kept DriverLoad-only (DAC-CS-0124) |
| SMB* / WmiCreateProcess / Idp* / SSO* | THIN / UNSAFE per AUTHORING-STATUS |
| Tor exit-node CSV match() | Lookup not TP-runnable fleet-wide — Tor-port egress instead (DAC-CS-0111) |
| identify_shadow_saas.yml lookup | Lookup-dependent — skipped |
| OsVersionInfo / SensorHeartbeat / InstalledBrowserExtension | Inventory-ish; weak as standalone TP IOA |

## Dedup notes vs DAC-CS-0001–0089

- Skipped re-authoring titles already present (DNS Resolutions from Browser Processes, External Connections with Process, High Number of Ports, Chromium DLL load, Overnight Post-RDP, Snowman, Lateral Movement, Unauthorized RMM, EDRCHOKER, ROKRAT, LeakNet, Gentlemen RaaS, etc.).
- New intents focus on ScheduledTaskRegistered pack, UserLogon*/UserIdentity auth, DnsRequest DoH/GenAI/RMM, NetworkConnect beaconing/Tor-ports/interpreter egress, CommandHistory/ScriptControlScanV2, RegGenericValue ASEP/ClickFix SAFE port, DriverLoad BYOVD, ClassifiedModuleLoad classifications, ProcessBlocked LOLBin twins, SPR2 joins.

## ESN coverage counts

| ESN | Rules referencing |
| --- | ---: |
| `ProcessRollup2` | 12 |
| `ScheduledTaskRegistered` | 8 |
| `NetworkConnectIP4` | 7 |
| `DnsRequest` | 6 |
| `ClassifiedModuleLoad` | 4 |
| `UserLogon` | 4 |
| `CommandHistory` | 3 |
| `RegGenericValue` | 3 |
| `ScriptControlScanV2` | 3 |
| `UserIdentity` | 3 |
| `UserLogonFailed2` | 3 |
| `DriverLoad` | 2 |
| `ProcessBlocked` | 2 |
| `SyntheticProcessRollup2` | 2 |
| `NetworkConnectIP6` | 1 |
