---
title: "P0 Audit-Policy / Logging Prerequisites — Phase 1"
phase: 1
last_updated: 2026-09-10
status: draft
scope: "Expand audit prerequisites for the 12 Phase-1 P0 techniques only"
source_pack: "dac-phase1-windows-ad-attack-pack.md"
constraint: "Defensive only — prerequisites and collection; no attack steps"
---

# P0 Audit-Policy Prerequisites (Phase 1)

**Audience:** DaC Platform Engineer (enablement) + Threat Detection Engineer (consume Event IDs)  
**Purpose:** Explicit audit-policy / logging prerequisites so the telemetry referenced in the Phase-1 Windows+AD pack **exists** before P0 rules are marked covered.  
**P0 set:** T1003.001, T1003.003, T1003.006, T1558.003, T1558.004, T1550.002, T1021.002, T1078.002, T1059.001, T1649, T1547.001, T1053.005

---

## Quick reference matrix

| ID | Technique | DC-only vs everywhere | Critical Security / AD policy | Critical Sysmon |
| --- | --- | --- | --- | --- |
| T1003.001 | LSASS Memory | Everywhere (endpoints + servers) | Process Creation (+cmdline) helpful | **10** (LSASS-scoped), **1** |
| T1003.003 | NTDS | **DC-only** | Object Access / file SACLs on ntds.dit | **1**, **11** (dit copies) |
| T1003.006 | DCSync | **DC-only** | Directory Service Access → **4662** | Optional correlate **1**/3 |
| T1558.003 | Kerberoasting | **DC-only** (ticket ops) | Kerberos Service Ticket Operations → **4769** | Optional **1** (weak) |
| T1558.004 | AS-REP Roasting | **DC-only** | Kerberos Authentication Service → **4768** | — |
| T1550.002 | Pass the Hash | Everywhere (auth events denser on targets/DCs) | Logon → **4624/4648** | Optional **10** join on source |
| T1021.002 | SMB/Admin Shares | Member servers + DCs (share); sources everywhere | File Share / Detailed File Share → **5140/5145**; System **7045** | **1**, **13**, optional **17/18** |
| T1078.002 | Domain Accounts | Everywhere + DC account/group mgmt | Logon; Account Logon; Account/Group Management | — (identity baseline) |
| T1059.001 | PowerShell | Everywhere | Process Creation +cmdline; **PowerShell 4103/4104** | **1** |
| T1649 | Auth Certificates | **CA + DCs** | CA AuditFilter + Certification Services → **4886–4888**; **4768** PKINIT | **3** scoped (certsrv) |
| T1547.001 | Run Keys / Startup | Everywhere | Optional registry auditing **4657** | **12/13/14**, **11** Startup |
| T1053.005 | Scheduled Task | Everywhere | Other Object Access (task) → **4698/4699/4702** | **1** (`schtasks`) |

---

## Per-technique prerequisites

### T1003.001 — OS Credential Dumping: LSASS Memory

| Field | Detail |
| --- | --- |
| **Technique name** | OS Credential Dumping: LSASS Memory |
| **Required Windows audit policy / subcategories** | **Audit Process Creation** (Success) + GPO **Include command line in process creation events** → Security **4688**. Optional: Object Access on LSASS handle (**4656/4663**) — rare; Sysmon preferred. |
| **Required Sysmon events / config notes** | **EID 10** ProcessAccess with **include** on TargetImage `lsass.exe` (access masks of interest filtered in analytics, not as a reason to disable collection). **EID 1** ProcessCreate for dump-adjacent LOLBins / unusual parents. Optional **EID 7** ImageLoad (noisy — heavy filter). Collect **4/16/255** so LSASS-related tamper is visible. |
| **DC-only vs everywhere** | **Everywhere** (workstations and servers). Highest value on Tier-0 and admin workstations. |
| **Failure mode if missing** | **Silent blind spot:** No ProcessAccess telemetry → LSASS scrapes/dumps invisible except brittle process-name rules. Without EID 1/4688 cmdline, supporting process context also weak. |

---

### T1003.003 — OS Credential Dumping: NTDS

| Field | Detail |
| --- | --- |
| **Technique name** | OS Credential Dumping: NTDS |
| **Required Windows audit policy / subcategories** | **Audit File System** / Object Access with **SACLs** on `%SystemRoot%\NTDS\ntds.dit` (and related NTDS paths) → **4656/4663**. **Audit Process Creation** (+cmdline) → **4688**. Ensure System / VSS-related operational visibility as available in estate. |
| **Required Sysmon events / config notes** | **EID 1** on Domain Controllers for `vssadmin`, `ntdsutil`, `wbadmin`, `diskshadow` and unusual parents. **EID 11** FileCreate for `ntds.dit` / `*.dit` copies off expected NTDS paths. Optional **EID 15** if ADS copies are in scope. |
| **DC-only vs everywhere** | **DC-only** (and any host holding IFM/media copies — treat those as Tier-0). |
| **Failure mode if missing** | **Silent blind spot:** Offline AD database theft produces no file or process trail on DCs; catastrophic credential exposure without SOC signal. |

---

### T1003.006 — OS Credential Dumping: DCSync

| Field | Detail |
| --- | --- |
| **Technique name** | OS Credential Dumping: DCSync |
| **Required Windows audit policy / subcategories** | Advanced Audit Policy → **DS Access** → **Directory Service Access** (Success) on Domain Controllers → Security **4662**. Ensure Properties/GUID fields for replication rights are retained in the forwarding pipeline (do not drop large binary/GUID fields). Maintain allowlists for legitimate DC machine accounts and known sync service accounts. |
| **Required Sysmon events / config notes** | Not strictly required for the core 4662 analytic. Optional: **EID 1** / scoped **EID 3** on source hosts for correlation after a 4662 hit. |
| **DC-only vs everywhere** | **DC-only** for 4662 generation; correlation may use member-server/workstation logons (**4624**). |
| **Failure mode if missing** | **Silent blind spot:** Replication-rights credential theft with **no** LSASS or ntds.dit file touch — rules exist in content but never fire; false “covered” status. |

---

### T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

| Field | Detail |
| --- | --- |
| **Technique name** | Steal or Forge Kerberos Tickets: Kerberoasting |
| **Required Windows audit policy / subcategories** | On DCs: **Account Logon** → **Audit Kerberos Service Ticket Operations** (Success, and Failure if used for related analytics) → Security **4769**. Retain TicketEncryptionType, ServiceName, Status, Account_Name, Client_Address in the schema. |
| **Required Sysmon events / config notes** | Optional **EID 1** for known roasting tool names — **weak**; prefer behavioral 4769 (RC4 `0x17`, burst distinct SPNs). Do not treat Sysmon as a substitute for 4769. |
| **DC-only vs everywhere** | **DC-only** (Kerberos TGS events). |
| **Failure mode if missing** | **Silent blind spot:** Mass TGS requests for service accounts blend into normal Kerberos; roasting succeeds without SOC visibility. Tool-name-only rules give false confidence. |

---

### T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting

| Field | Detail |
| --- | --- |
| **Technique name** | Steal or Forge Kerberos Tickets: AS-REP Roasting |
| **Required Windows audit policy / subcategories** | On DCs: **Account Logon** → **Audit Kerberos Authentication Service** (Success/Failure as needed) → Security **4768**. Preserve PreAuthType / TicketEncryptionType fields. Supporting: **Audit User Account Management** → **4738** (and Directory changes if used) when monitoring flips of “Do not require Kerberos preauthentication.” |
| **Required Sysmon events / config notes** | None required for core AS-REP analytic. |
| **DC-only vs everywhere** | **DC-only** for 4768; account-management events on DCs. |
| **Failure mode if missing** | **Silent blind spot:** TGTs without pre-auth for misconfigured accounts are invisible; offline cracking of privileged/service accounts goes undetected. |

---

### T1550.002 — Use Alternate Authentication Material: Pass the Hash

| Field | Detail |
| --- | --- |
| **Technique name** | Use Alternate Authentication Material: Pass the Hash |
| **Required Windows audit policy / subcategories** | **Audit Logon** (Success) → Security **4624** (need LogonType, AuthenticationPackage, KeyLength, TargetUserName, IpAddress/Workstation). **Audit Logon** / explicit creds → **4648** on source where available. Failure logons (**4625**) support spray→PtH chains but are secondary for this ID. |
| **Required Sysmon events / config notes** | Optional but high value: **EID 10** LSASS access on **source** host for join to subsequent Type 3 NTLM logons (pack correlation). **EID 1** on source for tooling context. |
| **DC-only vs everywhere** | **Everywhere** that records network logons (member servers, DCs, file servers). Baselining needs broad 4624 collection. |
| **Failure mode if missing** | **Silent blind spot:** NTLM network logons with PtH characteristics indistinguishable from missing data; lateral movement after dump looks like normal service auth if fields or volume are incomplete. |

---

### T1021.002 — Remote Services: SMB/Windows Admin Shares

| Field | Detail |
| --- | --- |
| **Technique name** | Remote Services: SMB/Windows Admin Shares |
| **Required Windows audit policy / subcategories** | **Object Access** → **Audit File Share** and **Audit Detailed File Share** (Success) on servers exposing Admin$/C$/IPC$ → **5140**, **5145**. **Audit Logon** → **4624** Type 3 preceding share access. Service install: System log **7045** and/or Security **4697** where available. |
| **Required Sysmon events / config notes** | **EID 1** for remote service binaries / `PSEXESVC`-class patterns. **EID 13** service ImagePath registry. Optional **EID 17/18** named pipes for PsExec-class fidelity. |
| **DC-only vs everywhere** | Share auditing on **servers** (member + DC); process/registry on **targets**; logon events on targets. Sources: everywhere. |
| **Failure mode if missing** | **Silent blind spot:** Admin$ / C$ staging and service-based lateral movement without file-share or service-install events; detections fragment to weak process names only. |

---

### T1078.002 — Valid Accounts: Domain Accounts

| Field | Detail |
| --- | --- |
| **Technique name** | Valid Accounts: Domain Accounts |
| **Required Windows audit policy / subcategories** | **Audit Logon** (Success/Failure) → **4624/4625**; **4648** where explicit creds matter. On DCs: **Kerberos Authentication Service** / **Service Ticket Operations** → **4768/4769**. **Audit Security Group Management** / **User Account Management** → **4728/4732/4756**, **4720/4738**, etc., for privilege-context changes. |
| **Required Sysmon events / config notes** | Not primary. Identity **baselines** (Tier-0 first-seen host, unusual LogonType) are required analytic inputs — Platform/IAM must supply Tier-0 group lists. |
| **DC-only vs everywhere** | Logons **everywhere**; Kerberos + group/account management on **DCs**. |
| **Failure mode if missing** | **Silent blind spot:** Almost all AD intrusions eventually look like valid users — without broad logon + identity tier context, anomaly analytics cannot run; “valid account” abuse is invisible by definition. |

---

### T1059.001 — Command and Scripting Interpreter: PowerShell

| Field | Detail |
| --- | --- |
| **Technique name** | Command and Scripting Interpreter: PowerShell |
| **Required Windows audit policy / subcategories** | **Audit Process Creation** (Success) + **Include command line in process creation events** → **4688**. Separately (not classic “audit subcategory” but mandatory): enable **PowerShell Module Logging** and **PowerShell Script Block Logging** via administrative templates / GPO → Microsoft-Windows-PowerShell/Operational **4103**, **4104**. |
| **Required Sysmon events / config notes** | **EID 1** for `powershell.exe` / `pwsh.exe` with CommandLine (`-enc`, `-nop`, `-w hidden`, download cradles) and parent-child (e.g. Office → PowerShell). |
| **DC-only vs everywhere** | **Everywhere** (workstations + servers). DCs especially for AD enumeration scripts. |
| **Failure mode if missing** | **Silent blind spot:** Encoded and in-memory PowerShell post-exploitation reduced to process image name; script-block and module content never reaches SIEM — high false negative rate for AD abuse via PowerShell. |

---

### T1649 — Steal or Forge Authentication Certificates

| Field | Detail |
| --- | --- |
| **Technique name** | Steal or Forge Authentication Certificates |
| **Required Windows audit policy / subcategories** | On **Certification Authority**: set **CA AuditFilter** (hardened estates often use full filter e.g. **127**) and enable **Certification Services** related audit so CA Security records **4886** (request), **4887** (issued), **4888** (denied); collect optional **4890/4891**. Forward CA Security log centrally. On **DCs**: **Audit Kerberos Authentication Service** → **4768** with PreAuthType **16** (PKINIT) / cert fields retained. Optional: IIS `/certsrv/` logs if web enrollment is enabled. |
| **Required Sysmon events / config notes** | Scoped **EID 3** NetworkConnect for `certsrv.exe` unexpected LDAP/SMB egress (relay/chase scenarios). |
| **DC-only vs everywhere** | **CA hosts + DCs** (and IIS enrollment servers if used). Not a workstation-everywhere control. |
| **Failure mode if missing** | **Silent blind spot:** AD CS abuse (privileged template issuance, SAN≠requester, PKINIT TGTs) completely invisible while password-focused rules look “green” — under-monitored domain auth path. |

---

### T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

| Field | Detail |
| --- | --- |
| **Technique name** | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **Required Windows audit policy / subcategories** | Optional: **Audit Registry** / Object Access with SACLs on Run key paths → Security **4657**. Not sufficient alone in most estates — Sysmon is the practical primary. |
| **Required Sysmon events / config notes** | **EID 12/13/14** for `...\Run`, `RunOnce`, `Winlogon\Shell` / `Userinit`. **EID 11** FileCreate for Startup folder writes. Filter known updater allowlists in analytics. |
| **DC-only vs everywhere** | **Everywhere** (persistence on workstations and servers). |
| **Failure mode if missing** | **Silent blind spot:** Classic Run-key / Startup persistence installs without registry or file telemetry; only coarse process rules remain. |

---

### T1053.005 — Scheduled Task/Job: Scheduled Task

| Field | Detail |
| --- | --- |
| **Technique name** | Scheduled Task/Job: Scheduled Task |
| **Required Windows audit policy / subcategories** | **Object Access** → audit subcategory covering scheduled task operations (commonly surfaced as task creation/change events) → Security **4698** (created), **4699** (deleted), **4702** (updated). Enable **Microsoft-Windows-TaskScheduler/Operational** collection (**106/140/141/200/201** as available). **Audit Process Creation** (+cmdline) → **4688**. Correlate remote creates with **4624** Type 3. |
| **Required Sysmon events / config notes** | **EID 1** for `schtasks.exe` `/create` / XML register and unusual At/task host binaries. |
| **DC-only vs everywhere** | **Everywhere**; remote task create correlation needs logons on targets. |
| **Failure mode if missing** | **Silent blind spot:** Persistence / priv-esc / remote task execution via Scheduled Tasks leaves no 4698/TaskScheduler trail; SYSTEM LOLBin tasks go unnoticed. |

---

## Platform enablement checklist (P0 gate)

Use before flipping any P0 analytic to `enabled` in DaC:

1. [ ] DCs: Directory Service Access (4662) + Kerberos AS/TGS (4768/4769) + Logon  
2. [ ] DCs: ntds.dit SACLs + Sysmon 1/11 on DCs (T1003.003)  
3. [ ] CA: AuditFilter + Certification Services → 4886–4888 centrally; DC 4768 PreAuthType 16  
4. [ ] Estate-wide: Logon 4624/4625/4648; Process Creation + cmdline 4688  
5. [ ] Estate-wide: Sysmon minimum **1, 10 (LSASS), 11, 12/13, 3 scoped, 4/16/255**  
6. [ ] Estate-wide: PowerShell **4103/4104**  
7. [ ] Servers: Detailed File Share 5145 + System 7045  
8. [ ] Estate-wide: Scheduled task 4698/4699/4702 (+ TaskScheduler Operational)  
9. [ ] Identity: Tier-0 / jump-host / DC-sync / SPN / no-preauth allowlist feeds for baselining  

---

## Sourcetype placeholders (collection targets)

- `WinEventLog:Security`
- `WinEventLog:System`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational`
- `XmlWinEventLog:Microsoft-Windows-TaskScheduler/Operational`
- CA Security log (host-specific; map to Security sourcetype or dedicated CA sourcetype — do not hardcode index)

---

*Defensive collection prerequisites only. Verify events arrive in SIEM before measuring Phase-1 P0 coverage. Last updated 2026-09-10.*
