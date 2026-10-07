---
title: "MITRE ATT&CK Coverage Gaps — Phase 1 (Windows Host + AD)"
phase: 1
last_updated: 2026-09-10
status: draft
audience: ["Threat Detection Engineer", "DaC Platform Engineer", "SOC"]
scope: "Windows host + Active Directory; Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement"
repo_target: "content/mitre/gaps.md"
source_pack: "dac-phase1-windows-ad-attack-pack.md"
---

# MITRE ATT&CK Coverage Gaps — Phase 1

**Purpose:** Document where public Sigma Windows packs and early-stage DaC content leave blind spots for this project’s Phase 1 (Windows Host + AD). Actionable for rule authors and for Platform to enable audit/telemetry before rules can fire.

**Constraint:** Defensive only — collection, policy names, and analytic coverage. No attack procedures.

**ATT&CK IDs:** Aligned to Phase-1 pack (verified Sep 2026). Do not invent conflicting technique IDs.

---

## 1. Sigma Windows pack coverage gaps (Phase-1 themes)

Public SigmaHQ Windows packs typically cover process-creation LOLBins, simple Run-key persistence, basic LSASS ProcessAccess, Event Log clear, and tool-name rules. For an AD-centric SOC, the following themes are **weak, noisy, or missing** — and are Phase-1 backlog priorities.

| # | Gap theme | Affected ATT&CK IDs | Blind-spot risk if unaddressed | Detection / content recommendation |
| --- | --- | --- | --- | --- |
| G1 | **Behavioral Kerberos** (4769/4768 thresholds, RC4 baselining, SPN allowlists) | T1558.003, T1558.004, T1558.001 (P1), T1550.003 (P1) | Kerberoasting / AS-REP roasting and ticket abuse look like normal ticket traffic; mass SPN requests and PreAuthType=0 succeed silently | Prefer Security 4769 (TicketEncryptionType `0x17`, burst `dc(ServiceName)`) and 4768 (PreAuthType `0`) over tool-name rules; maintain SPN and no-preauth inventories |
| G2 | **DCSync 4662 quality** (replication GUID mapping, DS Access dependency, DC/`$` allowlists) | T1003.006 | Domain-equivalent credential theft via replication rights with **no** LSASS/NTDS file touch — classic silent AD compromise | Require Directory Service Access on DCs; map Properties to replication GUIDs; exclude known DC machine accounts / sync SvcAccts; optional join to 4624 source ≠ DC |
| G3 | **AD CS / T1649** (CA AuditFilter unset; ESC-class issue/SAN/PKINIT underrepresented) | T1649 | Certificate-based domain auth without passwords; PKINIT TGTs and privileged template issuance go unseen | Enable CA `AuditFilter` + Certification Services audit; alert 4886/4887 on privileged templates / SAN≠requester; 4768 PreAuthType **16** vs smartcard baseline |
| G4 | **Valid Accounts / PtH baselining** (Tier-0 first-seen host, spray→success, NTLM Type 3 KeyLength 0) | T1078.002, T1550.002, T1110.003 (P1) | Post-compromise “looks like” a valid user; PtH blends with service NTLM; foothold after spray missed | Entity baselines for Tier-0; 4624 LogonType 3 + AuthenticationPackage NTLM anomalies; correlate 4625/4771 → 4624 success; join PtH to prior Sysmon 10 on source |
| G5 | **GPO / SYSVOL + Admin$ LM correlation** | T1484.001 (P1), T1021.002 | Domain-wide persistence via GPO/scripts; PsExec-class Admin$ write + service install fragmented across rules | Pair 5136/5137 (DS Changes) + Sysmon 11 on SYSVOL Policies; correlate 5145 Admin$/C$ writes with 7045 / Sysmon service ImagePath and Type 3 logon |
| G6 | **Telemetry prerequisites undocumented** | All P0–P2 in pack (esp. T1003.006, T1003.003, T1649, T1059.001, T1484.001) | Rules deployed before audit/Sysmon/CA policy → **silent coverage holes** (false sense of “covered”) | Gate rule “enabled” on prereq checklist (this doc §2–§3); Platform owns enablement; Detection owns rule logic |
| G7 | **Remote LM fidelity** (WinRM/WMI/RDP allowlists) | T1021.006 (P1), T1047 (P1), T1021.001 (P1), T1021.002 | Scripted remoting and interactive RDP blend with admin work; incomplete Admin$ chains | `wsmprovhost`/`WmiPrvSE` unusual children (Sysmon 1); RDP Type 10 jump-host allowlists; Admin$ + pipe (17/18) + 7045 correlation |
| G8 | **Token / privileged logon chains without identity tier** | T1134.001 (P1), T1078.002 | 4672 floods and token opens lack Tier-0 context; Sigma alone cannot express entity models | Enrich with Tier-0 group membership; baseline Special Logon; correlate Type 9 / multi-process token access with identity risk |
| G9 | **NTDS / VSS access quality on DCs** | T1003.003 | Offline AD database theft if SACLs / process+file telemetry missing on DCs | SACL on `ntds.dit`; Sysmon 1 for VSS/ntdsutil/wbadmin/diskshadow + EID 11 `*.dit` copies; non-backup-account allowlist |
| G10 | **PowerShell depth** (4103/4104 assumed; cmdline-only rules brittle) | T1059.001 | Encoded / IEX / ADSI mass enum missed if only 4688 or process name collected | Require Module + Script Block logging; pair 4104 tokens with Sysmon 1 parent-child (Office→powershell) |
| G11 | **Tamper canaries under-scoped** | T1562.001 (P1) | AV/EDR/Sysmon/audit disable precedes ransomware; pack analytics go dark first | Collect Sysmon 4/16/255, Security 1102, 4719; alert policy/service stop especially on DCs |

**Repo note:** Treat the Phase‑1 pack as backlog/planning. Coverage metrics should not be interpreted as production readiness; prioritize sourcetype‑portable content and avoid hardcoded `index=` in shared detections.

---

## 2. Audit / telemetry prerequisites (Platform operationalize)

Enable these **before** marking related analytics “covered.” Structured for DaC Platform Engineer ownership; Detection Engineer consumes Event IDs listed in the Phase-1 pack.

### 2.1 Directory Service Access / Changes (DCs)

| Prerequisite | Microsoft / policy focus | Key Event IDs | Unlocks techniques |
| --- | --- | --- | --- |
| **Directory Service Access** | Advanced Audit Policy → DS Access → Directory Service Access (Success, and Failure where useful) | **4662** (replication GUID Properties for DCSync) | T1003.006 |
| **Directory Service Changes** | Advanced Audit Policy → DS Access → Directory Service Changes | **5136**, **5137** (GPO / object create-modify) | T1484.001, T1098 (attr changes) |
| Object SACLs | SACLs on Domain/GPO objects as needed for 4662/5136 quality | 4662, 5136/5137 | T1003.006, T1484.001 |
| NTDS file SACLs (DC) | Object Access / file SACLs on `%SystemRoot%\NTDS\ntds.dit` | **4656/4663** | T1003.003 |

**Failure mode:** DCSync and GPO rules never fire; NTDS file access invisible.

### 2.2 CA AuditFilter + Certification Services audit (AD CS)

| Prerequisite | What to enable | Key Event IDs | Unlocks |
| --- | --- | --- | --- |
| **CA AuditFilter** | Set CA audit filter appropriately (commonly full **127** in hardened guidance) | Feeds CA Security log volume | T1649 |
| **Certification Services** audit subcategory | Advanced audit for Certification Services; collect CA **Security** log centrally | **4886** (request), **4887** (issued), **4888** (denied); optional **4890/4891** | T1649 |
| Optional IIS | `/certsrv/` web enrollment logs if web enrollment enabled | Web/IIS | T1649 (ESC8 surface) |
| Correlate on DCs | Kerberos TGT with PKINIT | **4768** PreAuthType **16** | T1649 |

**Failure mode:** Entire AD CS abuse surface is a blind spot despite process rules elsewhere.

### 2.3 Sysmon minimum (pack-aligned)

| Event ID | Role | Config notes |
| --- | --- | --- |
| **1** | ProcessCreate | Everywhere; include CommandLine |
| **10** | ProcessAccess | **LSASS-scoped** includes (TargetImage `lsass.exe`); filter known EDR/AV |
| **11** | FileCreate | Scoped — Startup, SYSVOL Policies, `*.dit` / sensitive paths on DCs |
| **12 / 13** | Registry | Run / RunOnce / Winlogon / Services ImagePath |
| **3** | NetworkConnect | **Scoped** — certsrv unexpected egress, SMB/LDAP sweeps, WinRM ports |
| **4 / 16 / 255** | Service state / Config / Error | Tamper canaries (T1562.001) |

Optional but useful later: 7 (ImageLoad, heavy filter), 15, 17/18 (pipes for PsExec-class). Prefer SwiftOnSecurity / sysmon-modular–class configs with environment-specific includes.

**Failure mode:** LSASS dump, Run-key persistence, Admin$/SYSVOL file drops, and tamper go dark or rely on incomplete Security-only telemetry.

### 2.4 Security audit subcategories for P0

| Advanced Audit subcategory (Microsoft names) | Scope | Key Event IDs | Primary P0 consumers |
| --- | --- | --- | --- |
| **Logon** (Success/Failure) | Everywhere (denser servers) | 4624, 4625, 4648 | T1550.002, T1078.002, T1021.002 |
| **Kerberos Authentication Service** | DCs | 4768, 4771 | T1558.004, T1649, T1110.003 |
| **Kerberos Service Ticket Operations** | DCs (Success+Failure) | 4769, 4770 | T1558.003 |
| **Credential Validation** | DCs / authenticating servers | 4776 | Spray / NTLM validation (P1 support) |
| **Process Creation** + **Include command line in process creation events** | Everywhere | 4688 | T1059.001, T1053.005, dump tooling |
| **Other Object Access Events** / **File Share** / **Detailed File Share** | File/member servers + DCs as needed | 5140, 5145 | T1021.002 |
| **Other Object Access Events** (Scheduled Task) | Everywhere | 4698, 4699, 4702 | T1053.005 |
| **Audit Policy Change** | Everywhere (esp. DCs) | 4719 | T1562.001 (support) |
| **User Account Management** / **Security Group Management** | DCs | 4720–4738, 4728, 4732, 4756 | T1078.002 context, T1098 |
| **Directory Service Access / Changes** | DCs | 4662, 5136, 5137 | T1003.006, T1484.001 |
| **System** log service install | Everywhere | 7045 (and 4697 where available) | T1021.002, T1543.003 |

### 2.5 PowerShell 4103 / 4104

| Setting | Channel / Event IDs | Unlocks |
| --- | --- | --- |
| **Module Logging** | Microsoft-Windows-PowerShell/Operational **4103** | T1059.001 depth |
| **Script Block Logging** | **4104** | Encoded/IEX/ADSI/DirectorySearcher analytics |
| Pair with | Sysmon 1 / 4688 CommandLine | Parent-child + cmdline correlation |

**Failure mode:** PowerShell post-exploitation reduced to process name noise; AD enumeration and cradles missed.

---

## 3. Gap → ATT&CK → blind-spot → enablement map

| Gap ID | ATT&CK IDs | Blind-spot risk if prereq missing | Recommended enablement (high-level) |
| --- | --- | --- | --- |
| G1 | T1558.003, T1558.004 | Roasting / ticket anomalies invisible or un baselined | Kerberos Authentication Service + Service Ticket Operations on DCs; collect 4768/4769; maintain SPN / no-preauth inventories |
| G2 | T1003.006 | DCSync silent | Directory Service Access on DCs; 4662 with replication GUID field mapping; DC/`$`/sync allowlists |
| G3 | T1649 | Cert theft/forge + PKINIT blind | CA AuditFilter; Certification Services audit; central CA Security (4886–4888); 4768 PreAuthType 16 |
| G4 | T1078.002, T1550.002 | Valid-account & PtH anomalies un baselined | Logon Success/Failure everywhere; Tier-0 identity list; NTLM Type 3 baselining; optional LSASS 10 join |
| G5 | T1484.001, T1021.002 | GPO/SYSVOL & Admin$ LM chains incomplete | DS Changes 5136/5137; Sysmon 11 on SYSVOL; Detailed File Share 5145; System 7045; Sysmon 13 Services |
| G6 | (all pack) | False “covered” status | Prereq gate in DaC CI / content frontmatter `telemetry_prereqs`; Platform checklist before rule enable |
| G7 | T1021.001/006, T1047, T1021.002 | Remoting LM blends with IT | Sysmon 1 for wsmprovhost/WmiPrvSE; WinRM/TS operational channels; share+service correlation; jump-host allowlists |
| G8 | T1134.001, T1078.002 | Token/priv logon without tier context | Special Logon 4672 baselining; Sysmon 10 scoped; Tier-0 enrichment (not Sigma-alone) |
| G9 | T1003.003 | NTDS theft on DC invisible | File SACLs on ntds.dit; Sysmon 1+11 on DCs; backup-account allowlist |
| G10 | T1059.001 | Script-block blind | PowerShell Module + Script Block Logging (4103/4104); cmdline in 4688 |
| G11 | T1562.001 | Defenses disabled before detection | Sysmon 4/16/255; 1102; 4719; service stop monitoring on DCs |

---

## 4. Suggested content layout (when scaffold lands)

Target path in repo: `content/mitre/gaps.md` (this file is the draft).

```
content/mitre/
  gaps.md          ← this document
  techniques/      ← optional per-ID cards later
```

Frontmatter fields used above: `title`, `phase`, `last_updated`, `status`, plus optional `audience`, `scope`, `repo_target`, `source_pack`.

---

## 5. Ownership cheat sheet

| Role | Owns |
| --- | --- |
| **DaC Platform Engineer** | Advanced Audit Policy GPO, Sysmon config deploy, CA AuditFilter, PowerShell logging, central collection of listed channels/sourcetypes |
| **Threat Detection Engineer** | Sigma/SPL logic, allowlists (SPN, Tier-0, jump hosts, DC sync accounts), baselining thresholds, ATT&CK mapping in rules |
| **SOC** | Validate Event IDs arriving; report silent holes when prereqs lag rule deploys |

---

## 6. Phase-1 related gaps (non-Sigma-pack but in scope)

| Item | Notes |
| --- | --- |
| Identity tier model | Required for T1078.002 / T1134.001 quality; not expressible in raw Sigma alone |
| Sourcetype portability | Use placeholders (`WinEventLog:Security`, `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, PowerShell/TaskScheduler/WMI/TS channels) — do not hardcode indexes |
| P1 stretch after P0 telemetry | Golden Ticket (T1558.001), PtT (T1550.003), GPO (T1484.001), RDP/WinRM/WMI — depend on same Kerberos/Logon/Sysmon baseline |
| Measure “covered” only after prereqs | Per pack appendix: verify audit policy and Sysmon before coverage metrics |

---

*Draft for Detection-as-Code Phase 1 — intended for `content/mitre/gaps.md`. Last updated 2026-09-10. Status: draft.*


## 2026-10-07 enhancement pass

- Remapped revoked ATT&CK v19 IDs (T1562* and T1070.001) onto T1685/T1686/T1688/T1689/T1690.
- Filled logic-less Splunk stubs with EventCode/Image anchors and classic/XML coalesce. telemetry_validated remains false.
- Paired unambiguous CloudTrail eventName filters with eventSource.
- Added DAC-WIN-0339/0340/0341 and DAC-AWS-0061.
