# Telemetry required_fields map (authoritative preview from Telemetry Researcher)

## Sourcetype macros
- `windows_security`
- `windows_system`
- `windows_powershell_operational`
- `windows_powershell_classic`
- `windows_sysmon`

Never hardcode `index=`. Prefer XML variants. Allowlist in `config/sourcetype_map.yaml`.

## required_fields by Event ID

| Event | required_fields |
| --- | --- |
| 4624/4625 | LogonType, TargetUserName, IpAddress\|WorkstationName, Status/SubStatus (fail) |
| 4648 | SubjectUserName/Domain, TargetUserName/Domain, TargetServerName, ProcessName |
| 4672 | SubjectUserName, PrivilegeList |
| 4688 | NewProcessName, Creator/Parent process, SubjectUserName, CommandLine if audited — else prefer Sysmon 1 |
| 4698 | TaskName, SubjectUser*, TaskContent |
| 4720 | TargetUserName, SubjectUser* |
| 4728/4732/4756 | MemberName\|MemberSid, TargetUserName(group), SubjectUser* |
| 4768/4769/4771 | TargetUserName, ServiceName(4769), IpAddress, TicketEncryptionType\|Status |
| 4776 | TargetUserName, Workstation, Status |
| 1102 | SubjectUser* (sparse) |
| 7045 | ServiceName, ImagePath\|ServiceFileName, StartType, AccountName |
| Sysmon1 | Image, CommandLine, ParentImage, User, ProcessGuid, Hashes |
| Sysmon3 | Image, User, Protocol, Initiated, SourceIp/Port, DestinationIp/Port |
| Sysmon7 | Image, ImageLoaded, Signed/Signature* |
| Sysmon10 | SourceImage, TargetImage, GrantedAccess |
| Sysmon11 | Image, TargetFilename, User |
| Sysmon13 | Image, TargetObject, Details |
| Sysmon22 | Image, QueryName, QueryResults\|Status, User |

Variants: classic Account_Name vs XML TargetUserName/SubjectUserName; CIM user/process/cmdline when TA maps — fieldsummary before ship.

## Validation checklist (12)
1. allowlisted ST/macro
2. no index=
3. EventCode on right channel
4. fieldsummary
5. OR aliases
6. Sysmon1 if no 4688 cmdline
7. prefer XML
8. Sysmon version/renderXml
9. FP baseline
10. data-gap if blind
11. sample event
12. CI clean

