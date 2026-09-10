# Windows → Splunk Telemetry Pack (DaC)

**Owner:** Telemetry Researcher  
**Repo:** https://github.com/pri17m/detection-as-code  
**Audience:** Detection Engineer / Threat Detection Engineer  
**Date:** 2026-09-10  
**Companion:** `config/sourcetype_map.yaml` (canonical CI allowlist)

## 0. Hard rules

1. **Sourcetype-first:** Detections MUST constrain with `sourcetype=…` or an approved sourcetype macro.  
2. **Never hardcode `index=`** in rule bodies. Optional index macros live in org config (`org.example.yaml`).  
3. **Allowlist only:** Every sourcetype string used in a rule must appear in `config/sourcetype_map.yaml` `allowed_sourcetypes` (after macro expansion). CI rejects others.  
4. Prefer **search macros** (`windows_security`, `windows_sysmon`, …) over listing every compound/collapsed variant inline.

---

## 1. Authoritative Splunk sourcetypes (Windows)

Influenced by **Splunk Add-on for Microsoft Windows** (≥5.0 splits classic vs XML) and **Splunk Add-on for Sysmon**.

| Channel | Preferred (XML) | Classic / alternate | TA ≥5 collapsed form | Notes |
| --- | --- | --- | --- | --- |
| Security | `XmlWinEventLog:Security` | `WinEventLog:Security` | `sourcetype=XmlWinEventLog` + `source=XmlWinEventLog:Security` (or `WinEventLog` + `source=WinEventLog:Security`) | Auth, account mgmt, process (4688), audit clear (1102) |
| System | `XmlWinEventLog:System` | `WinEventLog:System` | same pattern with `:System` | Service install **7045** |
| PowerShell Operational | `XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | collapsed + source `*Microsoft-Windows-PowerShell/Operational` | **4103** module, **4104** script block |
| PowerShell classic | `XmlWinEventLog:Windows PowerShell` | `WinEventLog:Windows PowerShell` | collapsed + source `*Windows PowerShell` | Engine **400/403/600** |
| Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `WinEventLog:Microsoft-Windows-Sysmon/Operational` (fields weaker) | `XmlWinEventLog` + source `*Microsoft-Windows-Sysmon/Operational` | Also legacy `sysmon`, `sysmon:*` |
| WMI (legacy) | — | `WMI:WinEventLog:Security` / `:System` | — | Prefer WinEventLog inputs; document as `source` pattern only |

**Macro keys (preferred in rules):**  
`windows_security` · `windows_system` · `windows_powershell_operational` · `windows_powershell_classic` · `windows_sysmon`

**Org index macros (optional, org override):**  
`windows_security_index` · `windows_system_index` · `windows_powershell_index` · `windows_sysmon_index`

### Example org.example.yaml placeholders

```yaml
# org.example.yaml — index macros ONLY (never bake these into shared rules)
macros:
  windows_security_index: "index=wineventlog"
  windows_system_index: "index=wineventlog"
  windows_powershell_index: "index=wineventlog"
  windows_sysmon_index: "index=sysmon"
```

---

## 2. Critical Event IDs — required fields + common variants

**Convention:**  
- **Native** = Windows / Sysmon field as commonly extracted by Splunk Windows/Sysmon TAs from XML/`<Data Name=…>`.  
- **CIM / TA aliases** = normalized names often present after Windows TA / CIM mappings.  
- Rules SHOULD OR native + common aliases when both appear in the wild, or document a single preferred field after org field validation.

### 2.1 Security / System

| EventCode | Intent | Required / high-value fields (native) | Common variants / aliases |
| --- | --- | --- | --- |
| **4624** | Successful logon | `EventCode`, `Logon_Type` / `LogonType`, `TargetUserName`, `TargetDomainName`, `IpAddress` / `Source_Network_Address`, `WorkstationName`, `ProcessName`, `AuthenticationPackageName`, `LogonProcessName`, `TargetUserSid` | CIM: `user`, `src_user`, `src`, `dest`, `app`, `signature_id` (=EventCode) |
| **4625** | Failed logon | same as 4624 + `FailureReason` / `Status` / `SubStatus` | `user`, `src`, `dest`, `reason` |
| **4648** | Explicit creds | `SubjectUserName`, `SubjectDomainName`, `TargetUserName`, `TargetDomainName`, `TargetServerName`, `ProcessName`, `IpAddress | `sri_user`, `user`, `dest`, `process` |
| **4672** | Special privileges | `SubjectUserName`, `SubjectDomainName`, `PrivilegeList`, `SubjectUserSid` | `user`, `privilege` |
| **4688** | Process create (Security) | `New_Process_Name` / `NewProcessName`, `Creator_Process_Name` / `ParentProcessName` / `CreatorProcessName`, `TokenElevationType, `SubjectUserName, `CommandLine (if audit policy enabled) | CIM: `process`, `parent_process`, `process_name, `parent_process_name`, `user`, `cmdline` |
| **4698** | Scheduled task created | `TaskName`, `SubjectUserName, `SubjectDomainName`, `TaskContent` / XML body fields when parsed | `user`, `object`, `command (from task XML — often needs rex) |
| **4720** | User account created | `TargetUserName`, `TargetDomainName`, `SubjectUserName`, `SubjectDomainName`, `SamAccountName` | `user`, `src_user`, `dest` |
| **4728** | Member added to global group | `MemberName, `MemberSid, `TargetUserName (group), `TargetDomainName`, `SubjectUserName | `user` (member), `group`, `src_user` |
| **4732** | Member added to local group | same pattern as 4728 | same |
| **4756** | Member added to universal group | same pattern as 4728 | same |
| **4768** | TGT requested (AS) | `TargetUserName`, `TargetDomainName, `ServiceName`, `IpAddress, `TicketOptions`, `Status`, `TicketEncryptionType` | `user`, `src`, `dest` |
| **4769** | Service ticket (TGS) | `TargetUserName, `TargetDomainName`, `ServiceName`, `IpAddress , `TicketOptions`, `Status`, `TicketEncryptionType` | Kerberoast hunts: `ServiceName, `TicketEncryptionType`, `user`, `src` |
| **4771** | Pre-auth failed | `TargetUserName`, `TargetDomainName, `IpAddress, `Status` | `user`, `src` |
| **4776** | NTLM credential validation | `TargetUserName`, `Workstation`, `Status` / `Error_Code` | `user`, `src`, `dest` |
| **1102** | Audit log cleared | `SubjectUserName`, `SubjectDomainName`, `SubjectUserSid` | `user`; often sparse — host + EventCode may be enough |
| **7045** (System) | Service installed | `ServiceName`, `ImagePath` / `ServiceFileName`, `ServiceType`, `StartType`, `AccountName` / `ServiceAccount` | `service, `service_name, `process`, `user` |

**Field-name pitfalls (Security):** Classic channel often uses spaces/`Account_Name`; XML & modern TA prefers `TargetUserName` / `SubjectUserName`. Always validate with `| fieldsummary` on the org’s sourcetype before locking a rule.

### 2.2 Sysmon

Prefer `EventCode` (TA extracts from `<EventID>`). Native Sysmon names below are usually stable across XML.

| EventCode | Intent | Required / high-value fields | CIM / TA aliases (when present) |
| --- | --- | --- | --- |
| **1** | Process create | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`, `ProcessGuid`, `ParentProcessGuid`, `ProcessId, `ParentProcessId, `Hashes, `OriginalFileName`, `Company`, `Description`, `Product`, `IntegrityLevel`, `CurrentDirectory`, `LogonGuid` | `process`, `process_name, `parent_process`, `parent_process_name`, `cmdline, `parent_process_id`, `process_id`, `user`, `process_hash` |
| **3** | Network connect | `Image`, `User`, `Protocol`, `Initiated, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `SourceHostname`, `DestinationHostname, `ProcessGuid` | `src`, `dest`, `src_port`, `dest_port`, `process`, `user`, `transport` |
| **7** | Image loaded | `Image`, `ImageLoaded`, `Signed, `Signature, `SignatureStatus`, `ProcessGuid, `User` | `process`, `file_name`, `file_path`, `user` |
| **10** | Process access | `SourceImage`, `TargetImage`, `GrantedAccess`, `SourceProcessGuid, `TargetProcessGuid`, `SourceUser`, `TargetUser` | `process`, `dest_process`, `user`; LSASS hunts need `TargetImage` + `GrantedAccess` |
| **11** | File create | `Image`, `TargetFilename`, `User`, `ProcessGuid, `CreationUtcTime` | `process`, `file_path`, `file_name`, `user` |
| **13** | Registry value set | `Image`, `TargetObject`, `Details`, `EsoneType`, `User`, `ProcessGuid` | `process`, `registry_path`, `registry_value_name`, `registry_value_data`, `user` |
| **22** | DNS query | `Image`, `QueryName`, `QueryResults`, `QueryStatus`, `User`, `ProcessGuid` | `process`, `query`, `dest`, `user` |

---

## 3. Org-portability pattern

```spl
# GOOD — sourcetype macro + EventCode + fields (no index=)
`windows_security` EventCode=4624 Logon_Type=10
| table _time host TargetUserName IpAddress WorkstationName

# GOOD — optional org index macro ONLY if org wires it
`windows_security_index` `windows_security` EventCode=4625

# BAD — hardcoded index (CI reject)
index=wineventlog sourcetype=WinEventLog:Security EventCode=4624

# BAD — sourcetype not on allowlist
sourcetype=WinEventLog:Application EventCode=1000
```

Sigma / rule YAML should reference **macro keys or allowlisted sourcetype strings** from `config/sourcetype_map.yaml`, never org index names.

---

## 4. Telemetry validation checklist (rule authors)

Before merging a Windows Splunk detection:

1. **Allowlist:** Every `sourcetype=` (after macro expand) ∈ `config/sourcetype_map.yaml` → `allowed_sourcetypes`.  
2. **No hardcoded `index=`** in shared rule body; index only via org macro if required.  
3. **Channel match:** EventCode belongs on the chosen channel (e.g. 7045 → System; 4104 → PowerShell Operational; Sysmon 1 → Sysmon).  
4. **Field presence:** Run `| fieldsummary` / `| dedup` sample on 24h of the target sourcetype; confirm every filter/field used exists (or OR aliases).  
5. **Alias coverage:** If org still has classic `Account_Name` style, include OR with `TargetUserName`/`SubjectUserName` (or document org-normalized only).  
6. **CommandLine / enrichhment:** For 4688, confirm command-line process auditing is enabled org-wide; else prefer Sysmon 1.  
7. **XML vs classic:** Prefer XML sourcetypes; if classic-only sites exist, use the channel macro (covers both).  
8. **Sysmon version:** Fields like `OriginalFileName`, `ParentCommandLine` need sufficiently new Sysmon + XML render (`renderXml=true`).  
9. **Baseline false positives:** Spot-check `| stats count by <key fields>` for noisy defaults (e.g. 4624 LogonType 3).  
10. **MITRE + data gap:** If required field missing in telemetry, file a **data gap** (don’t ship a blind rule).  
11. **Unit sample:** Attach or cite at least one anonymized raw event (or bot SV fixture) proving field names.  
12. **CI dry-run:** Local/CI sourcetype linter clean; macro names resolve.

---

## 5. Repo placement (greenfield)

Repo currently has README only. Recommended paths:

- `config/sourcetype_map.yaml` — canonical allowlist (this pack)  
- `docs/telemetry/windows-splunk.md` — this document  
- `config/org.example.yaml` — index macro placeholders only  

## 6. Uncertainties / gaps

- Exact WEF/`ForwardedEvents` sourcetype strings vary by org (`XmlWinEventLog:ForwardedEvents` vs custom); not in first allowlist — add when WEF is in scope.  
- Collapsed `WinEventLog` / `XmlWinEventLog` alone are allowlisted so TA≥5 sites work, but rules using them **must** also filter `source=` or EventCode carefully to avoid cross-channel bleed.  
- CIM alias availability depends on TA version (Windows TA field mapping changed across releases; Sysmon TA 10.6.2 → 1.0.1 renamed/removed several fields). Org validation (checklist #4) is mandatory.  
- Private repo empty — no existing macros to reconcile yet.

