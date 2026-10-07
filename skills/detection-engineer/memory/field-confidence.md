# Cross-cutting field confidence ledger

Quick lookup. Canonical detail lives in `memory/sourcetypes/<family>.md`.

## High confidence (reuse freely once log family known)

- Windows Security XML: `EventCode`, `CommandLine`, `NewProcessName`, `ParentProcessName`, `SubjectUserName`
- Sysmon XML: `EventCode`, `Image`, `CommandLine`, `ParentImage`, `User`
- CloudTrail: `eventName`, `eventSource`, `userIdentity.arn`, `requestParameters.roleArn`, `requestParameters.functionName`, `responseElements.functionArn`, `sourceIPAddress`, `userAgent`

## Needs confirm (do not stamp telemetry_validated until checked)

- CloudTrail: `responseElements.instancesSet.items{}.instanceId` (mv/spath)
- CloudTrail: `userIdentity.sessionContext.ec2RoleDelivery` vs nested variants
- Collapsed `WinEventLog` / `XmlWinEventLog` without `source=` filter
- Any CIM-only field name without TA confirmation

## Rejected / dangerous assumptions

- `index=*` or hardcoding `index=cloudtrail` / `index=wineventlog` in shared DaC
- Assuming classic `WinEventLog:Security` sees XML lab events
- Assuming `Image` exists on raw 4688 without coalesce
- Cmdline substring alone for LOLBin technique names

## Update protocol

When verifying a field:

1. Add/update row in the sourcetype file with confidence + evidence URL.
2. Mirror high-level change here in one line.
3. If a “high” field fails in a new TA version, demote immediately and note version.
