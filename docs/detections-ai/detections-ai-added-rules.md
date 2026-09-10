# detections.ai rules added to DaC (DAC-CS-0138+)

Count: **63** unique rules authored under `/workspace/dac-crowdstrike/detections-ai-gaps-yaml/`.

| ID | Rule name | ESN | Source |
|---|---|---|---|
| DAC-CS-0138 | Falcon: Malicious NPM Package Browsing Activity | DnsRequest | https://detections.ai/rules/0199befe-8e76-72bf-af47-3f51c8b94c05 |
| DAC-CS-0139 | Falcon: Shai Hulud Compromised NPM packages and versions - ALL | DnsRequest | https://detections.ai/rules/019ab716-96e7-751c-b747-f816f20ed4fe |
| DAC-CS-0140 | Falcon: Hunting Crowdstrike ScriptControl | ScriptControlScanV2 | https://detections.ai/rules/019efe55-194e-73a8-af71-766e6749f3b5 |
| DAC-CS-0141 | Falcon: Potential ClickFix FileFix Execution | ProcessRollup2 | https://detections.ai/rules/019f0481-73d7-77c9-82bc-ba8a5b974b46 |
| DAC-CS-0142 | Falcon: Malicious Browser Extensions | ProcessRollup2 | https://detections.ai/rules/019f12ea-b27c-7734-a1ed-15c28e04edd4 |
| DAC-CS-0143 | Falcon: MyBB Limited ACP Privilege Escalation to Full Admin (CVE-2026-46331) | ProcessRollup2 | https://detections.ai/rules/019f14ee-4eb8-7329-bd4a-d06744578ab9 |
| DAC-CS-0144 | Falcon: LegionLoader Bulk SharePoint/OneDrive Access via M365 Copilot Organizational Perm… | ProcessRollup2 | https://detections.ai/rules/019f1762-676a-7230-8d9a-08c3f29c4c58 |
| DAC-CS-0145 | Falcon: Velvet Ant Nginx FastCGI Proxy-Chain Pivoting to Isolated Internal Hosts | ProcessRollup2 | https://detections.ai/rules/019f1a46-7349-716b-8f02-cd2ab21ffad9 |
| DAC-CS-0146 | Falcon: ServiceNow Unauthenticated API Data Exfiltration via Guest User on /api/now/ Endp… | ProcessRollup2 | https://detections.ai/rules/019f1a58-da43-7200-a78b-a4cf13ba04e6 |
| DAC-CS-0147 | Falcon: klist.exe Advanced Kerberos Subcommands – Recon via sessions, -li, get, purge | ProcessRollup2 | https://detections.ai/rules/019f1ed9-2b98-77d5-b86e-0910f06c9f9d |
| DAC-CS-0148 | Falcon: LLMjacking - Stolen API Key Use Against LLM Provider Endpoints | ProcessRollup2 | https://detections.ai/rules/019f1ed9-4cc8-726f-a066-6e8fc84c8346 |
| DAC-CS-0149 | Falcon: Dump de hives do Registro (SECURITY / SAM / SYSTEM) via reg.exe save | ProcessRollup2 | https://detections.ai/rules/019f4281-1ae8-7070-ae06-35be6bb53039 |
| DAC-CS-0150 | Falcon: Potential Residential Proxy Usage (CrowdStrike Falcon) | NetworkConnectIP4 | https://detections.ai/rules/019f4b48-e3bb-7469-850a-cdf309ba3418 |
| DAC-CS-0151 | Falcon: Storm-1175 - Medusa - WDigest Enablement Followed by LSASS Credential Dumping | RegGenericValue | https://detections.ai/rules/019f6686-cb9c-71cc-a35c-86ea0070897f |
| DAC-CS-0152 | Falcon: Miasma: node.exe Enumerating Security Tools or Reading EDR Registry Keys Pre-Payl… | ProcessRollup2 | https://detections.ai/rules/019f679f-180c-7638-862e-de2dc2487c26 |
| DAC-CS-0153 | Falcon: Outbound WebDAV request to Stealth Falcon campaign staging directory | NetworkConnectIP4 | https://detections.ai/rules/019f860e-53d0-772f-948f-44106fa78f85 |
| DAC-CS-0154 | Falcon: Known Stealth Falcon WebDAV Delivery-Lab Staging Artifact Written to Disk | NetworkConnectIP4 | https://detections.ai/rules/019f861c-aba1-7124-9c16-296cae59572c |
| DAC-CS-0155 | Falcon: Stealth Falcon Loader Pool Db Png Idat Payload | ProcessRollup2 | https://detections.ai/rules/019f8623-ce33-718b-9340-6cc6a65104f6 |
| DAC-CS-0156 | Falcon: Credential access via netsh | ProcessRollup2 | https://detections.ai/rules/019fcd08-2a90-730f-aa12-63112fb0bf9f |
| DAC-CS-0157 | Falcon: Mirage Kitten NightLedger Backdoor: DLL Search-Order Hijack | ProcessRollup2 | https://detections.ai/rules/019fd24b-ca22-74ed-b7f6-4cf0d59010cd |
| DAC-CS-0158 | Falcon: Mirage Kitten NightLedger Screenshot Capture from Hijacked DLL Context | ProcessRollup2 | https://detections.ai/rules/019fd250-8b9a-71ca-81ef-ed6c6af7c741 |
| DAC-CS-0159 | Falcon: Mirage Kitten NightLedger Logical Drive Enumeration from DLL Context | ProcessRollup2 | https://detections.ai/rules/019fd254-2c75-7498-96eb-89eacc1e8fdd |
| DAC-CS-0160 | Falcon: Mirage Kitten NightLedger NetSetup.log Targeted Collection for AD Reconnaissance | ProcessRollup2 | https://detections.ai/rules/019fd258-8dc4-72b8-97b2-eee9c208339e |
| DAC-CS-0161 | Falcon: Pre-execution EDR/AV process check (CrowdStrike/Sophos) followed by stealthy msed… | ProcessRollup2 | https://detections.ai/rules/019fd292-ad4e-707d-a06f-d5fff5e0a60c |
| DAC-CS-0162 | Falcon: OGC Filter SQL Injection Attempt Against GeoServer (CVE-2023-25158 class) | ClassifiedModuleLoad | https://detections.ai/rules/01a0146f-2131-760f-bba6-1ddee49e98a7 |
| DAC-CS-0163 | Falcon: GeoServer jsonArrayContains SQLi exploitation (GHSA-mqjf-5f49-2fjh) | ProcessRollup2 | https://detections.ai/rules/01a0146f-5045-73ed-9486-b5f940939349 |
| DAC-CS-0164 | Falcon: Extracting FIles (e.g. SAM and SYSTEM) With 7-Zip | ProcessRollup2 | https://detections.ai/rules/01a01c14-6da2-7613-a2d2-81e71e366ad9 |
| DAC-CS-0165 | Falcon: Large Volume Data Write to External USB Device | ProcessRollup2 | https://detections.ai/rules/01a05a9e-d003-70c8-b2f7-5376b3d606b3 |
| DAC-CS-0166 | Falcon: Rapid Network Connection After Remote Access Software Installation | ProcessRollup2 | https://detections.ai/rules/01a05aa1-695f-75ec-80f8-5b2f7d7b0351 |
| DAC-CS-0167 | Falcon: Suspicious PowerShell/CMD Execution Linked to Bot Interaction Keywords | ProcessRollup2 | https://detections.ai/rules/01a05ab3-b3e3-72ff-af59-2d862458ff31 |
| DAC-CS-0168 | Falcon: Direct Access to Container Environment Variables | ProcessRollup2 | https://detections.ai/rules/01a05c16-38bd-772b-b61b-18b1ec80bd50 |
| DAC-CS-0169 | Falcon: Crypto mining preparation through MSR write access | ProcessRollup2 | https://detections.ai/rules/01a05c17-c726-756e-b951-557ed0dbdf27 |
| DAC-CS-0170 | Falcon: Shell-based secret discovery with text-processing tools | ProcessRollup2 | https://detections.ai/rules/01a05c18-2b94-7015-81c1-8ddeed5bc7bb |
| DAC-CS-0171 | Falcon: Suspicious Child Processes Spawned by AI Gateway | ProcessRollup2 | https://detections.ai/rules/01a05c18-baa8-721e-a8d1-2986a4f84cee |
| DAC-CS-0172 | Falcon: FalconFlank: CrowdStrike Falcon Macro-Remediation DLL Sideload LPE | ClassifiedModuleLoad | https://detections.ai/rules/01a07c1e-8548-76ef-aa78-362a7f9d9421 |
| DAC-CS-0173 | Falcon: CrowdStrike Falcon Exclusion Policy Modification Outside Management Channel | ProcessRollup2 | https://detections.ai/rules/01a07c1e-8260-762b-a849-0198c7fc55f8 |
| DAC-CS-0174 | Falcon: Falcon Remediation Process Loads Attacker DLL During Quarantine Action | ProcessRollup2 | https://detections.ai/rules/01a07c1e-82b3-74df-bbbd-1575de58a6b6 |
| DAC-CS-0175 | Falcon: FalconFlank Exploit Execution Triggering Elevated SYSTEM conhost.exe | ProcessRollup2 | https://detections.ai/rules/01a07c1e-838e-7598-af05-70ad365928ef |
| DAC-CS-0176 | Falcon: FalconFlank: SYSTEM child process from Falcon sensor after unsigned DLL load | ProcessRollup2 | https://detections.ai/rules/01a07c1e-84ef-72ad-8c02-61948b50eb43 |
| DAC-CS-0177 | Falcon: TeamCity server spawns unexpected child process (CVE-2026-63077) | ProcessRollup2 | https://detections.ai/rules/01a0729d-0016-7326-bf74-2263bc02fcd7 |
| DAC-CS-0178 | Falcon: Potential Unauthorized Access to Sensitive System Files | ProcessRollup2 | https://detections.ai/rules/01a078a6-726c-75b8-85f1-25e10eedf3cf |
| DAC-CS-0179 | Falcon: Linux Web Server Process Spawning Web Shell Post-Exploitation Utilities | ProcessRollup2 | https://detections.ai/rules/01a079f2-9a78-7089-bf88-2397e8f01381 |
| DAC-CS-0180 | Falcon: T1222 icacls/takeown or chmod/chown Weakening AV-EDR Directory Permissions | ProcessRollup2 | https://detections.ai/rules/01a080f8-e8e8-7215-a45b-6c345344000b |
| DAC-CS-0181 | Falcon: Trojanized pub.dev Package Resolution: universal_file_viewer / surveyjs_flutter | DnsRequest | https://detections.ai/rules/01a084fe-bde5-7158-b81a-14d18c9b47af |
| DAC-CS-0182 | Falcon: CVE-2026-69730 Windows DNS Server RCE Vulnerability | DnsRequest | https://detections.ai/rules/01a0885d-dd3c-77b5-bcc5-8fa556cd3f55 |
| DAC-CS-0183 | Falcon: ShadowPad Injects into wmpnetwk.exe to Unhook Network Monitoring APIs | ClassifiedModuleLoad | https://detections.ai/rules/01a089d0-24f4-7452-8230-cf0b98dea1ad |
| DAC-CS-0184 | Falcon: Chromium Secure Preferences super_mac Forgery for Extension Persistence | ProcessRollup2 | https://detections.ai/rules/01a089d0-97c7-713c-958e-cda15d27a296 |
| DAC-CS-0185 | Falcon: Shai-Hulud full npm compromise | DnsRequest | https://detections.ai/rules/0f5b020b-343b-48c4-bfbd-e04449892657 |
| DAC-CS-0186 | Falcon: Malicious NPM Package Version Download | DnsRequest | https://detections.ai/rules/4a60d4d7-71c6-47df-96de-5d2942af1fc6 |
| DAC-CS-0187 | Falcon: EDR/AV Process Termination via taskkill.exe or sc.exe | ProcessRollup2 | https://detections.ai/rules/019f1a60-05fb-725d-965d-f6d8cc9e3308 |
| DAC-CS-0188 | Falcon: Infostealer browser credential access from suspicious paths (multi-file) | ProcessRollup2 | https://detections.ai/rules/01a08592-67b0-775c-b1eb-85cc39bf06ae |
| DAC-CS-0189 | Falcon: Security Software Discovery via Command Line | ProcessRollup2 | https://detections.ai/rules/01a078a4-73a3-74bc-a527-ff0885b87224 |
| DAC-CS-0190 | Falcon: Miasma node.exe Spawning wmic/PowerShell for Security Tool Enumeration | ProcessRollup2 | https://detections.ai/rules/019f0589-7fcd-77d5-a536-e23d04765d2e |
| DAC-CS-0191 | Falcon: lambsys cryptominer security tool disablement and log deletion post-deployment | ProcessRollup2 | https://detections.ai/rules/019f0572-0e91-7374-950c-6ffebe1efc55 |
| DAC-CS-0192 | Falcon: lambsys Cryptominer Security Tool Disablement and Firewall Flush on Linux | ProcessRollup2 | https://detections.ai/rules/019f0aa7-b38d-7519-83a0-9b6dec59edd3 |
| DAC-CS-0193 | Falcon: Notepad.exe Executing Markdown from WindowsApps (Excluding Specific Version) - Cr… | ProcessRollup2 | https://detections.ai/rules/019da375-1f98-7754-88d4-1460aa12b4f4 |
| DAC-CS-0194 | Falcon: MLTBackdoor DLL Execution via Rundll32 | ProcessRollup2 | https://detections.ai/rules/019ead53-4555-76ef-a8b1-20fff3eb1c49 |
| DAC-CS-0195 | Falcon: Crowdstrike CQL - Suspicious Network Connection by Clawbot/Moltbot/Openclaw | NetworkConnectIP4 | https://detections.ai/rules/019cb93c-cf1e-71da-8c2b-6af5657d7906 |
| DAC-CS-0196 | Falcon: Suspicious Commands Executed via Run Dialog | ProcessRollup2 | https://detections.ai/rules/019da379-6b15-7059-9734-79afa029e861 |
| DAC-CS-0197 | Falcon: Despair EDR Killer | ProcessRollup2 | https://detections.ai/rules/019da376-453c-775d-b4bd-dd6d51acf9e2 |
| DAC-CS-0198 | Falcon: Fake VPN to Steal Credentials (dwmapi.dll and inspector.dll) | ProcessRollup2 | https://detections.ai/rules/019da377-fe73-7506-b7b3-c0fd07477fb3 |
| DAC-CS-0199 | Falcon: CVE-2026-33829 Windows Snipping Tool Vulnerability | ProcessRollup2 | https://detections.ai/rules/019d9f46-3194-7636-a92d-c03b935245f9 |
| DAC-CS-0200 | Falcon: Potential CVE-2023-25157 Exploitation Attempt | ProcessRollup2 | https://detections.ai/rules/019a5a75-94c4-7688-b648-23a3d04b036e |

## Inventory names (unique titles assigned)

- `DAC-CS-0138` — Malicious NPM Package Browsing Activity
- `DAC-CS-0139` — Shai Hulud Compromised NPM packages and versions - ALL
- `DAC-CS-0140` — Hunting Crowdstrike ScriptControl
- `DAC-CS-0141` — Potential ClickFix FileFix Execution
- `DAC-CS-0142` — Malicious Browser Extensions
- `DAC-CS-0143` — MyBB Limited ACP Privilege Escalation to Full Admin (CVE-2026-46331)
- `DAC-CS-0144` — LegionLoader Bulk SharePoint/OneDrive Access via M365 Copilot Organizational Permissions
- `DAC-CS-0145` — Velvet Ant Nginx FastCGI Proxy-Chain Pivoting to Isolated Internal Hosts
- `DAC-CS-0146` — ServiceNow Unauthenticated API Data Exfiltration via Guest User on /api/now/ Endpoints
- `DAC-CS-0147` — klist.exe Advanced Kerberos Subcommands – Recon via sessions, -li, get, purge
- `DAC-CS-0148` — LLMjacking - Stolen API Key Use Against LLM Provider Endpoints
- `DAC-CS-0149` — Dump de hives do Registro (SECURITY / SAM / SYSTEM) via reg.exe save
- `DAC-CS-0150` — Potential Residential Proxy Usage (CrowdStrike Falcon)
- `DAC-CS-0151` — Storm-1175 - Medusa - WDigest Enablement Followed by LSASS Credential Dumping
- `DAC-CS-0152` — Miasma: node.exe Enumerating Security Tools or Reading EDR Registry Keys Pre-Payload
- `DAC-CS-0153` — Outbound WebDAV request to Stealth Falcon campaign staging directory
- `DAC-CS-0154` — Known Stealth Falcon WebDAV Delivery-Lab Staging Artifact Written to Disk
- `DAC-CS-0155` — Stealth Falcon Loader Pool Db Png Idat Payload
- `DAC-CS-0156` — Credential access via netsh
- `DAC-CS-0157` — Mirage Kitten NightLedger Backdoor: DLL Search-Order Hijack
- `DAC-CS-0158` — Mirage Kitten NightLedger Screenshot Capture from Hijacked DLL Context
- `DAC-CS-0159` — Mirage Kitten NightLedger Logical Drive Enumeration from DLL Context
- `DAC-CS-0160` — Mirage Kitten NightLedger NetSetup.log Targeted Collection for AD Reconnaissance
- `DAC-CS-0161` — Pre-execution EDR/AV process check (CrowdStrike/Sophos) followed by stealthy msedge.exe stealth-flag launch
- `DAC-CS-0162` — OGC Filter SQL Injection Attempt Against GeoServer (CVE-2023-25158 class)
- `DAC-CS-0163` — GeoServer jsonArrayContains SQLi exploitation (GHSA-mqjf-5f49-2fjh)
- `DAC-CS-0164` — Extracting FIles (e.g. SAM and SYSTEM) With 7-Zip
- `DAC-CS-0165` — Large Volume Data Write to External USB Device
- `DAC-CS-0166` — Rapid Network Connection After Remote Access Software Installation
- `DAC-CS-0167` — Suspicious PowerShell/CMD Execution Linked to Bot Interaction Keywords
- `DAC-CS-0168` — Direct Access to Container Environment Variables
- `DAC-CS-0169` — Crypto mining preparation through MSR write access
- `DAC-CS-0170` — Shell-based secret discovery with text-processing tools
- `DAC-CS-0171` — Suspicious Child Processes Spawned by AI Gateway
- `DAC-CS-0172` — FalconFlank: CrowdStrike Falcon Macro-Remediation DLL Sideload LPE
- `DAC-CS-0173` — CrowdStrike Falcon Exclusion Policy Modification Outside Management Channel
- `DAC-CS-0174` — Falcon Remediation Process Loads Attacker DLL During Quarantine Action
- `DAC-CS-0175` — FalconFlank Exploit Execution Triggering Elevated SYSTEM conhost.exe
- `DAC-CS-0176` — FalconFlank: SYSTEM child process from Falcon sensor after unsigned DLL load
- `DAC-CS-0177` — TeamCity server spawns unexpected child process (CVE-2026-63077)
- `DAC-CS-0178` — Potential Unauthorized Access to Sensitive System Files
- `DAC-CS-0179` — Linux Web Server Process Spawning Web Shell Post-Exploitation Utilities
- `DAC-CS-0180` — T1222 icacls/takeown or chmod/chown Weakening AV-EDR Directory Permissions
- `DAC-CS-0181` — Trojanized pub.dev Package Resolution: universal_file_viewer / surveyjs_flutter
- `DAC-CS-0182` — CVE-2026-69730 Windows DNS Server RCE Vulnerability
- `DAC-CS-0183` — ShadowPad Injects into wmpnetwk.exe to Unhook Network Monitoring APIs
- `DAC-CS-0184` — Chromium Secure Preferences super_mac Forgery for Extension Persistence
- `DAC-CS-0185` — Shai-Hulud full npm compromise
- `DAC-CS-0186` — Malicious NPM Package Version Download
- `DAC-CS-0187` — EDR/AV Process Termination via taskkill.exe or sc.exe
- `DAC-CS-0188` — Infostealer browser credential access from suspicious paths (multi-file)
- `DAC-CS-0189` — Security Software Discovery via Command Line
- `DAC-CS-0190` — Miasma node.exe Spawning wmic/PowerShell for Security Tool Enumeration
- `DAC-CS-0191` — lambsys cryptominer security tool disablement and log deletion post-deployment
- `DAC-CS-0192` — lambsys Cryptominer Security Tool Disablement and Firewall Flush on Linux
- `DAC-CS-0193` — Notepad.exe Executing Markdown from WindowsApps (Excluding Specific Version) - CrowdStrike Version
- `DAC-CS-0194` — MLTBackdoor DLL Execution via Rundll32
- `DAC-CS-0195` — Crowdstrike CQL - Suspicious Network Connection by Clawbot/Moltbot/Openclaw
- `DAC-CS-0196` — Suspicious Commands Executed via Run Dialog
- `DAC-CS-0197` — Despair EDR Killer
- `DAC-CS-0198` — Fake VPN to Steal Credentials (dwmapi.dll and inspector.dll)
- `DAC-CS-0199` — CVE-2026-33829 Windows Snipping Tool Vulnerability
- `DAC-CS-0200` — Potential CVE-2023-25157 Exploitation Attempt
