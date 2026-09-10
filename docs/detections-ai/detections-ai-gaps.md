# detections.ai → DAC-CS gap analysis (Community CS/CQL)

## Scope
- Inventory: `detections-ai-inventory.jsonl` (**81** unique URLs)
- Our pack: `dac-cs-inventory.tsv` (**137** DAC-CS rules through 0137)
- Browse: CrowdStrike pages 1–3 + CQL pages 1–3 only (site reports ~849 CS / 38 CQL)
- Method: title fuzzy match (SequenceMatcher + token Jaccard). **Not** query-body diff yet (detail opens deferred for low-profile).
- Next IDs: **DAC-CS-0138+**

## Summary
| Bucket | Count |
|---|---|
| Likely already covered (title match ≥0.72) | 0 |
| Possible overlap (0.45–0.72) | 9 |
| Likely gaps (weak/no title match) | 72 |

- Of likely gaps: **49** CQL/unknown (port priority), **20** KQL (needs rewrite to CQL), **3** other.

## Priority candidates for DAC-CS-0138+ (CQL / unknown first)

Title-only; open detail + confirm SAFE ESN + visible CQL before YAML. Propose IDs in order.

### 1. DAC-CS-0138 — Notepad.exe Executing Markdown from WindowsApps (Excluding Specific Version) - CrowdStrike Version
- URL: https://detections.ai/rules/019da375-1f98-7754-88d4-1460aa12b4f4
- Tags: CQL; CrowdStrikers; ProcessRollup2; event_simpleName
- Author: Lightkun Yagami @lightkun_CrowdStriker
- Closest existing: DAC-CS-0079 (0.233) — Falcon: JAR files executed from %AppData%
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 2. DAC-CS-0139 — LegionLoader Bulk SharePoint/OneDrive Access via M365 Copilot Organizational Permissions
- URL: https://detections.ai/rules/019f1762-676a-7230-8d9a-08c3f29c4c58
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0021 (0.246) — Falcon: browser credential store access from scripting engine
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 3. DAC-CS-0140 — ServiceNow Unauthenticated API Data Exfiltration via Guest User on /api/now/ Endpoints
- URL: https://detections.ai/rules/019f1a58-da43-7200-a78b-a4cf13ba04e6
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0027 (0.259) — Falcon: service create with user-writable ImagePath
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 4. DAC-CS-0141 — Mirage Kitten NightLedger NetSetup.log Targeted Collection for AD Reconnaissance
- URL: https://detections.ai/rules/019fd258-8dc4-72b8-97b2-eee9c208339e
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0110 (0.253) — Falcon: Rare Remote Ports in Network Connections
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 5. DAC-CS-0142 — Trojanized pub.dev Package Resolution: universal_file_viewer / surveyjs_flutter
- URL: https://detections.ai/rules/01a084fe-5ec4-745f-8dac-d1426a57d037
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0071 (0.242) — Falcon: DNS Resolutions from Browser Processes
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 6. DAC-CS-0143 — Trojanized pub.dev Package Resolution: universal_file_viewer / surveyjs_flutter
- URL: https://detections.ai/rules/01a084fe-bde5-7158-b81a-14d18c9b47af
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0071 (0.242) — Falcon: DNS Resolutions from Browser Processes
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 7. DAC-CS-0144 — Storm-1175 - Medusa - WDigest Enablement Followed by LSASS Credential Dumping
- URL: https://detections.ai/rules/019f6686-cb9c-71cc-a35c-86ea0070897f
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0021 (0.232) — Falcon: browser credential store access from scripting engine
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 8. DAC-CS-0145 — klist.exe Advanced Kerberos Subcommands – Recon via sessions, -li, get, purge
- URL: https://detections.ai/rules/019f1ed9-2b98-77d5-b86e-0910f06c9f9d
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0122 (0.245) — Falcon: ClickFix-style RunMRU Interpreter via RegGenericValue
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 9. DAC-CS-0146 — Crowdstrike CQL - Suspicious Network Connection by Clawbot/Moltbot/Openclaw
- URL: https://detections.ai/rules/019cb93c-cf1e-71da-8c2b-6af5657d7906
- Tags: CQL; CrowdStrike; network connection; endpoint hunting
- Author: Leo Arm @WhatDoesKmean
- Closest existing: DAC-CS-0110 (0.314) — Falcon: Rare Remote Ports in Network Connections
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 10. DAC-CS-0147 — Known Stealth Falcon WebDAV Delivery-Lab Staging Artifact Written to Disk
- URL: https://detections.ai/rules/019f8612-b2f3-724a-9927-2b47ef5f2d21
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0124 (0.271) — Falcon: BYOVD Known Vulnerable DriverLoad
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 11. DAC-CS-0148 — Known Stealth Falcon WebDAV Delivery-Lab Staging Artifact Written to Disk
- URL: https://detections.ai/rules/019f861c-6907-74c8-ae5b-01da6948b67f
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0124 (0.271) — Falcon: BYOVD Known Vulnerable DriverLoad
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 12. DAC-CS-0149 — Known Stealth Falcon WebDAV Delivery-Lab Staging Artifact Written to Disk
- URL: https://detections.ai/rules/019f861c-aba1-7124-9c16-296cae59572c
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0124 (0.271) — Falcon: BYOVD Known Vulnerable DriverLoad
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 13. DAC-CS-0150 — OGC Filter SQL Injection Attempt Against GeoServer (CVE-2023-25158 class)
- URL: https://detections.ai/rules/01a0146f-2131-760f-bba6-1ddee49e98a7
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0081 (0.256) — Falcon: MongoDB Processes on Windows & Linux Hosts (CVE-2025-14847)
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 14. DAC-CS-0151 — Velvet Ant Nginx FastCGI Proxy-Chain Pivoting to Isolated Internal Hosts
- URL: https://detections.ai/rules/019f1a46-7349-716b-8f02-cd2ab21ffad9
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0056 (0.24) — Falcon: suspicious outbound from scripting engines
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 15. DAC-CS-0152 — Chromium Secure Preferences super_mac Forgery for Extension Persistence
- URL: https://detections.ai/rules/01a089d0-97c7-713c-958e-cda15d27a296
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0006 (0.251) — Falcon: schtasks persistence
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 16. DAC-CS-0153 — Linux Web Server Process Spawning Web Shell Post-Exploitation Utilities
- URL: https://detections.ai/rules/01a079f2-9a78-7089-bf88-2397e8f01381
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0002 (0.315) — Falcon: Office spawning shell
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 17. DAC-CS-0154 — Mirage Kitten NightLedger Screenshot Capture from Hijacked DLL Context
- URL: https://detections.ai/rules/019fd250-8b9a-71ca-81ef-ed6c6af7c741
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0137 (0.259) — Falcon: NetworkConnectIP4 High RemotePort from Interpreters
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 18. DAC-CS-0155 — Suspicious PowerShell/CMD Execution Linked to Bot Interaction Keywords
- URL: https://detections.ai/rules/01a05ab3-b3e3-72ff-af59-2d862458ff31
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0001 (0.322) — Falcon: PowerShell encoded command
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 19. DAC-CS-0156 — ShadowPad Injects into wmpnetwk.exe to Unhook Network Monitoring APIs
- URL: https://detections.ai/rules/01a089d0-24f4-7452-8230-cf0b98dea1ad
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0110 (0.264) — Falcon: Rare Remote Ports in Network Connections
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 20. DAC-CS-0157 — Dump de hives do Registro (SECURITY / SAM / SYSTEM) via reg.exe save
- URL: https://detections.ai/rules/019f3e50-d67e-77bf-9cbb-354680e433e1
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0123 (0.35) — Falcon: Security Service Disable via RegGenericValue
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 21. DAC-CS-0158 — Dump de hives do Registro (SECURITY / SAM / SYSTEM) via reg.exe save
- URL: https://detections.ai/rules/019f4281-1ae8-7070-ae06-35be6bb53039
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0123 (0.35) — Falcon: Security Service Disable via RegGenericValue
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 22. DAC-CS-0159 — Mirage Kitten NightLedger Logical Drive Enumeration from DLL Context
- URL: https://detections.ai/rules/019fd254-2c75-7498-96eb-89eacc1e8fdd
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0060 (0.253) — Falcon: unsigned DLL load by signed Microsoft binary from user path
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 23. DAC-CS-0160 — MyBB Limited ACP Privilege Escalation to Full Admin (CVE-2026-46331)
- URL: https://detections.ai/rules/019f14ee-4eb8-7329-bd4a-d06744578ab9
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0093 (0.217) — Falcon: Scheduled Task Highest Privileges RunLevel
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 24. DAC-CS-0161 — Outbound WebDAV request to Stealth Falcon campaign staging directory
- URL: https://detections.ai/rules/019f860e-53d0-772f-948f-44106fa78f85
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0056 (0.296) — Falcon: suspicious outbound from scripting engines
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 25. DAC-CS-0162 — GeoServer jsonArrayContains SQLi exploitation (GHSA-mqjf-5f49-2fjh)
- URL: https://detections.ai/rules/01a0146f-5045-73ed-9486-b5f940939349
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0101 (0.255) — Falcon: Generic Shared Account Logon Usage
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 26. DAC-CS-0163 — Rapid Network Connection After Remote Access Software Installation
- URL: https://detections.ai/rules/01a05aa1-695f-75ec-80f8-5b2f7d7b0351
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0110 (0.341) — Falcon: Rare Remote Ports in Network Connections
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 27. DAC-CS-0164 — TeamCity server spawns unexpected child process (CVE-2026-63077)
- URL: https://detections.ai/rules/01a0729d-0016-7326-bf74-2263bc02fcd7
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0076 (0.263) — Falcon: External Connectons with Process
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 28. DAC-CS-0165 — LLMjacking - Stolen API Key Use Against LLM Provider Endpoints
- URL: https://detections.ai/rules/019f1ed9-4cc8-726f-a066-6e8fc84c8346
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0078 (0.282) — Falcon: Find OpenClaw on Endpoints
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 29. DAC-CS-0166 — Fake VPN to Steal Credentials (dwmapi.dll and inspector.dll)
- URL: https://detections.ai/rules/019da377-fe73-7506-b7b3-c0fd07477fb3
- Tags: CQL; CrowdStrikers; DLL sideload; credential theft
- Author: Lightkun Yagami @lightkun_CrowdStriker
- Closest existing: DAC-CS-0018 (0.353) — Falcon: credential dump DLL load into unusual process
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 30. DAC-CS-0167 — Mirage Kitten NightLedger Backdoor: DLL Search-Order Hijack
- URL: https://detections.ai/rules/019fd24b-ca22-74ed-b7f6-4cf0d59010cd
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0060 (0.236) — Falcon: unsigned DLL load by signed Microsoft binary from user path
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 31. DAC-CS-0168 — Potential Unauthorized Access to Sensitive System Files
- URL: https://detections.ai/rules/01a078a6-726c-75b8-85f1-25e10eedf3cf
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0065 (0.346) — Falcon: Unauthorized RMM Tool Usage
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 32. DAC-CS-0169 — Shell-based secret discovery with text-processing tools
- URL: https://detections.ai/rules/01a05c18-2b94-7015-81c1-8ddeed5bc7bb
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0017 (0.358) — Falcon: suspicious SAM/SECURITY hive access tools
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 33. DAC-CS-0170 — Shai Hulud Compromised NPM packages and versions - ALL
- URL: https://detections.ai/rules/019ab716-96e7-751c-b747-f816f20ed4fe
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0077 (0.249) — Falcon: FalconFlank Exploit Artifacts (Named Pipe and Dropped DLL)
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 34. DAC-CS-0171 — Crypto mining preparation through MSR write access
- URL: https://detections.ai/rules/01a05c17-c726-756e-b951-557ed0dbdf27
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0088 (0.306) — Falcon: Systems Initiating Connections to a High Number of Ports
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 35. DAC-CS-0172 — Extracting FIles (e.g. SAM and SYSTEM) With 7-Zip
- URL: https://detections.ai/rules/01a01c14-6da2-7613-a2d2-81e71e366ad9
- Tags: CQL; CrowdStrike LogScale; ProcessRollup2; SAM/SYSTEM
- Author: Lightkun Yagami @lightkun_CrowdStriker
- Closest existing: DAC-CS-0076 (0.307) — Falcon: External Connectons with Process
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 36. DAC-CS-0173 — Direct Access to Container Environment Variables
- URL: https://detections.ai/rules/01a05c16-38bd-772b-b61b-18b1ec80bd50
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0074 (0.317) — Falcon: Detection of External Direct IP Usage in CommandLine Windows and Mac
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 37. DAC-CS-0174 — Suspicious Child Processes Spawned by AI Gateway
- URL: https://detections.ai/rules/01a05c18-baa8-721e-a8d1-2986a4f84cee
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0013 (0.305) — Falcon: LSASS process access by non-EDR
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 38. DAC-CS-0175 — Large Volume Data Write to External USB Device
- URL: https://detections.ai/rules/01a05a9e-d003-70c8-b2f7-5376b3d606b3
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0113 (0.293) — Falcon: NetworkConnectIP6 External Egress with Process
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 39. DAC-CS-0176 — Stealth Falcon Loader Pool Db Png Idat Payload
- URL: https://detections.ai/rules/019f8623-ce33-718b-9340-6cc6a65104f6
- Tags: CQL/Falcon candidate
- Author: —
- Closest existing: DAC-CS-0024 (0.33) — Falcon: Startup folder payload drop
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

### 40. DAC-CS-0177 — Potential CVE-2023-25157 Exploitation Attempt
- URL: https://detections.ai/rules/019a5a75-94c4-7688-b648-23a3d04b036e
- Tags: Sigma; CrowdStrikers; CQL_FILTER; web exploitation
- Author: SigmaHQ Detections @sigmaHQ
- Closest existing: DAC-CS-0067 (0.336) — Falcon: CVE-2025-53770 - SharePoint ToolShell
- Status: **candidate** — needs detail query + Telemetry SAFE ESN check

## KQL / Falcon-EDR titled gaps (rewrite to TP CQL — lower priority)

- [Pre-execution EDR/AV process check (CrowdStrike/Sophos) followed by stealthy msedge.exe stealth-flag launch](https://detections.ai/rules/019fd292-ad4e-707d-a06f-d5fff5e0a60c) — tags: KQL; CrowdStrike Falcon EDR; EDR check; Edgecution — closest DAC-CS-0013 (0.227)
- [lambsys cryptominer security tool disablement and log deletion post-deployment](https://detections.ai/rules/019f0572-0e91-7374-950c-6ffebe1efc55) — tags: KQL; CrowdStrike; security tool disablement; log deletion — closest DAC-CS-0044 (0.246)
- [FalconFlank: SYSTEM child process from Falcon sensor after unsigned DLL load](https://detections.ai/rules/01a0667c-555b-709d-b892-cc9e8a09a83e) — tags: KQL; CrowdStrike Falcon EDR; Falcon; unsigned DLL — closest DAC-CS-0069 (0.324)
- [FalconFlank: SYSTEM child process from Falcon sensor after unsigned DLL load](https://detections.ai/rules/01a07c1e-84ef-72ad-8c02-61948b50eb43) — tags: KQL; CrowdStrike Falcon EDR; Falcon; unsigned DLL; SYSTEM child — closest DAC-CS-0069 (0.324)
- [CrowdStrike Falcon Exclusion Policy Modification Outside Management Channel](https://detections.ai/rules/01a0667b-f6b8-7128-8b1e-f2e1b3fb47d7) — tags: KQL; CrowdStrike Falcon EDR; CrowdStrike; Falcon — closest DAC-CS-0028 (0.292)
- [CrowdStrike Falcon Exclusion Policy Modification Outside Management Channel](https://detections.ai/rules/01a07c1e-8260-762b-a849-0198c7fc55f8) — tags: KQL; CrowdStrike Falcon EDR; CrowdStrike; Falcon — closest DAC-CS-0028 (0.292)
- [T1222 icacls/takeown or chmod/chown Weakening AV-EDR Directory Permissions](https://detections.ai/rules/01a080f9-2d53-75ca-a2b4-663a0461e3f4) — tags: KQL; CrowdStrike Falcon EDR; T1222; EDR tamper — closest DAC-CS-0075 (0.25)
- [T1222 icacls/takeown or chmod/chown Weakening AV-EDR Directory Permissions](https://detections.ai/rules/01a080f9-2d56-771e-889b-2a02e6d80f51) — tags: KQL; CrowdStrike Falcon EDR; T1222; EDR tamper — closest DAC-CS-0075 (0.25)
- [T1222 icacls/takeown or chmod/chown Weakening AV-EDR Directory Permissions](https://detections.ai/rules/01a080f9-2d63-750a-a461-34b5f3db1f99) — tags: KQL; CrowdStrike Falcon EDR; T1222; EDR tamper — closest DAC-CS-0075 (0.25)
- [T1222 icacls/takeown or chmod/chown Weakening AV-EDR Directory Permissions](https://detections.ai/rules/01a080f8-e8e8-7215-a45b-6c345344000b) — tags: KQL; CrowdStrike Falcon EDR; T1222; EDR tamper — closest DAC-CS-0075 (0.25)
- [Falcon Remediation Process Loads Attacker DLL During Quarantine Action](https://detections.ai/rules/01a0667c-0abb-706a-9eca-aa23373e5f00) — tags: KQL; CrowdStrike Falcon EDR; Falcon remediation; DLL — closest DAC-CS-0038 (0.298)
- [Falcon Remediation Process Loads Attacker DLL During Quarantine Action](https://detections.ai/rules/01a07c1e-82b3-74df-bbbd-1575de58a6b6) — tags: KQL; CrowdStrike Falcon EDR; Falcon remediation; DLL — closest DAC-CS-0038 (0.298)
- [Miasma node.exe Spawning wmic/PowerShell for Security Tool Enumeration](https://detections.ai/rules/019f0589-7fcd-77d5-a536-e23d04765d2e) — tags: KQL; CrowdStrike; node.exe; wmic; PowerShell — closest DAC-CS-0033 (0.367)
- [FalconFlank Exploit Execution Triggering Elevated SYSTEM conhost.exe](https://detections.ai/rules/01a0667c-2df0-71ae-8074-8d2bf5c849a6) — tags: KQL; CrowdStrike Falcon EDR; FalconFlank; conhost; SYSTEM — closest DAC-CS-0077 (0.357)
- [FalconFlank Exploit Execution Triggering Elevated SYSTEM conhost.exe](https://detections.ai/rules/01a07c1e-838e-7598-af05-70ad365928ef) — tags: KQL; CrowdStrike Falcon EDR; FalconFlank; conhost; SYSTEM — closest DAC-CS-0077 (0.357)
- [FalconFlank: CrowdStrike Falcon Macro-Remediation DLL Sideload LPE](https://detections.ai/rules/01a06672-8e32-75dd-b661-7bb5f459bd0e) — tags: KQL; CrowdStrike Falcon EDR; FalconFlank; DLL sideload — closest DAC-CS-0077 (0.361)
- [FalconFlank: CrowdStrike Falcon Macro-Remediation DLL Sideload LPE](https://detections.ai/rules/01a07c1e-8548-76ef-aa78-362a7f9d9421) — tags: KQL; CrowdStrike Falcon EDR; FalconFlank; DLL sideload — closest DAC-CS-0077 (0.361)
- [EDR/AV Process Termination via taskkill.exe or sc.exe](https://detections.ai/rules/019f1a60-29a2-77b9-b673-c10374b0eee0) — tags: KQL; CrowdStrike; EDR/AV tamper; taskkill; sc.exe — closest DAC-CS-0013 (0.339)
- [EDR/AV Process Termination via taskkill.exe or sc.exe](https://detections.ai/rules/019f1a60-05fb-725d-965d-f6d8cc9e3308) — tags: KQL; CrowdStrike; EDR/AV tamper; taskkill; sc.exe — closest DAC-CS-0013 (0.339)
- [Security Software Discovery via Command Line](https://detections.ai/rules/01a078a4-73a3-74bc-a527-ff0885b87224) — tags: KQL; CrowdStrike; security product discovery — closest DAC-CS-0123 (0.416)

## Possible overlaps (manual review)

- CVE-2026-69730 Windows DNS Server RCE Vulnerability ↔ DAC-CS-0068 `Falcon: CVE-2026-32202 - Windows Shell` (score 0.485) — https://detections.ai/rules/01a0885d-dd3c-77b5-bcc5-8fa556cd3f55
- CVE-2026-33829 Windows Snipping Tool Vulnerability ↔ DAC-CS-0068 `Falcon: CVE-2026-32202 - Windows Shell` (score 0.487) — https://detections.ai/rules/019d9f46-3194-7636-a92d-c03b935245f9
- MLTBackdoor DLL Execution via Rundll32 ↔ DAC-CS-0005 `Falcon: rundll32 suspicious execution` (score 0.46) — https://detections.ai/rules/019ead53-97f7-756d-9d88-3c1c3a9477ee
- MLTBackdoor DLL Execution via Rundll32 ↔ DAC-CS-0005 `Falcon: rundll32 suspicious execution` (score 0.46) — https://detections.ai/rules/019ead53-4555-76ef-a8b1-20fff3eb1c49
- Potential ClickFix FileFix Execution ↔ DAC-CS-0072 `Falcon: DNS Staging Detection: ClickFix-Inspired nslookup Execution` (score 0.455) — https://detections.ai/rules/019f0481-73d7-77c9-82bc-ba8a5b974b46
- Infostealer browser credential access from suspicious paths (multi-file) ↔ DAC-CS-0021 `Falcon: browser credential store access from scripting engine` (score 0.542) — https://detections.ai/rules/01a08592-7fcd-7448-86e2-3c539243395a
- Infostealer browser credential access from suspicious paths (multi-file) ↔ DAC-CS-0021 `Falcon: browser credential store access from scripting engine` (score 0.542) — https://detections.ai/rules/01a08592-7fcb-73bb-b78c-1fb7797f5ca2
- Infostealer browser credential access from suspicious paths (multi-file) ↔ DAC-CS-0021 `Falcon: browser credential store access from scripting engine` (score 0.542) — https://detections.ai/rules/01a08592-7fa0-706e-95b0-11d5a48e261a
- Infostealer browser credential access from suspicious paths (multi-file) ↔ DAC-CS-0021 `Falcon: browser credential store access from scripting engine` (score 0.542) — https://detections.ai/rules/01a08592-67b0-775c-b1eb-85cc39bf06ae

## Likely covered (skip unless query body differs)


## Notes
- Full CS catalog (~849) not inventoried; only first 3 list pages + CQL (38).
- No YAML authored in this pass.
- DE does not push; ping TDE after YAML batch.