# Windows→Splunk telemetry — teammate summary

## Sourcetype allowlist (→ `config/sourcetype_map.yaml`)
**Macros (preferred):** `windows_security` · `windows_system` · `windows_powershell_operational` · `windows_powershell_classic` · `windows_sysmon`

**Strings:**  
`WinEventLog:Security` / `XmlWinEventLog:Security` · `WinEventLog:System` / `XmlWinEventLog:System` ·  
`…PowerShell/Operational` (Win+Xml) · `…Windows PowerShell` (Win+Xml) ·  
`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (+ WinEventLog Sysmon, legacy `sysmon`/`sysmon:*`) ·  
collapsed `WinEventLog` / `XmlWinEventLog` (pair with `source=`)

**Portability:** sourcetype/macro only — **never** hardcoded `index=`. Optional org index macros in `org.example.yaml`.

## Required fields (short)
| ID | Must-have |
| --- | --- |
| 4624/4625 | LogonType, TargetUserName, IpAddress/Workstation, Status/SubStatus (fail) |
| 4648 | Subject*, TargetUser*, TargetServerName, ProcessName |
| 4672 | SubjectUserName, PrivilegeList |
| 4688 | NewProcessName, Creator/Parent process, SubjectUserName, CommandLine if audited |
| 4698 | TaskName, SubjectUser*, TaskContent |
| 4720 | TargetUserName, SubjectUser* |
| 4728/4732/4756 | MemberName/MemberSid, TargetUserName(group), SubjectUser* |
| 4768/4769/4771 | TargetUserName, ServiceName (4769), IpAddress, TicketEncryptionType/Status |
| 4776 | TargetUserName, Workstation, Status |
| 1102 | SubjectUser* (sparse) |
| 7045 | ServiceName, ImagePath/ServiceFileName, StartType, AccountName |
| Sysmon 1 | Image, CommandLine, ParentImage, User, ProcessGuid, Hashes |
| Sysmon 3 | Image, User, Protocol, Initiated, SourceIp/Port, DestinationIp/Port |
| Sysmon 7 | Image, ImageLoaded, Signed/Signature* |
| Sysmon 10 | SourceImage, TargetImage, GrantedAccess |
| Sysmon 11 | Image, TargetFilename, User |
| Sysmon 13 | Image, TargetObject, Details |
| Sysmon 22 | Image, QueryName, QueryResults/Status, User |

Variants: classic `Account_Name` vs XML `TargetUserName`/`SubjectUserName`; CIM `user`/`process`/`cmdline` when TA maps them — **validate with fieldsummary**.

## Checklist (rule authors)
1 Allowlisted sourcetype/macro · 2 No `index=` · 3 EventCode on right channel · 4 fieldsummary proves fields · 5 OR aliases if classic+XML · 6 Prefer Sysmon 1 if 4688 cmdline missing · 7 Prefer XML · 8 Sysmon version/renderXml · 9 FP baseline · 10 Data-gap if blind · 11 Sample event · 12 CI clean

**Full doc:** `/workspace/dac-windows-splunk-telemetry.md` (= `docs/telemetry/windows-splunk.md`)  
**Map:** `/workspace/config/sourcetype_map.yaml`

## Phase-1 expansion (gap Event IDs)

| ID | Must-have |
| --- | --- |
| 4104 | ScriptBlockText, ScriptBlockId, Path, MessageNumber/Total, User* |
| 4662 | SubjectUser*, ObjectDN/GUID/Type, Properties, AccessMask |
| 4702 | TaskName, SubjectUser*, TaskContent |
| 4719 | SubjectUser*, CategoryId, SubcategoryId/Guid, AuditPolicyChanges |
| 4724 | SubjectUser*, TargetUserName/Domain |
| 4738 | SubjectUser*, TargetUser*, UAC/PasswordLastSet/SidHistory deltas |
| 4740 | TargetUserName, CallerComputerName |
| 4741 | TargetUserName (computer$), SubjectUser*, SPNs if present |
| 4886–4888 | RequestId, Requester, Attributes/Subject (+ Status on 4888) |
| 5136 | SubjectUser*, ObjectDN/GUID/Class, AttributeLDAPDisplayName, AttributeValue, OperationType |
| 5137 | SubjectUser*, ObjectDN/GUID/Class |
| 5145 | SubjectUser*, ShareName, RelativeTargetName, AccessMask, IpAddress |
| Sysmon4 | State (+ Version/SchemaVersion) |
| Sysmon6 | ImageLoaded, Hashes, Signed/Signature* |
| Sysmon8 | SourceImage, TargetImage, StartModule/Function, StartAddress |
| Sysmon16 | Configuration, ConfigurationFileHash |
| Sysmon17/18 | PipeName, Image, User |
| Sysmon19 | EventNamespace, Name, Query, User, Operation |
| Sysmon20 | Name, Type, Destination, User, Operation |
| Sysmon21 | Consumer, Filter, User, Operation |
| Sysmon25 | Image, Type, User, ProcessGuid |

Also: 4104 → `windows_powershell_operational`; AD CS 4886–4888 need CA audit onboarded; Sysmon 17–21/25 often disabled in config — treat missing telemetry as data gap.
