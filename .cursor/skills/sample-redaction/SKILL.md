---
name: sample-redaction
description: Redact a Splunk or Windows event before it is stored on a detection. Use when adding validation.sample_event, pasting _raw into a pull request, or saving lab evidence.
---

# Redact the sample event

`validation.sample_event` is required when `telemetry_validated` is true. The sample is the raw event with identity removed. Keep the fields the detection matches.

## Remove

Replace these with the literal `REDACTED`. Do not leave a partial value.

- `Computer` and `SubjectDomainName`
- `SubjectUserName` and any other account or email
- `SubjectUserSid` and other SIDs that identify the account (`S-1-5-21-...`)
- `SubjectLogonId`
- `EventRecordID`, `ProcessID`, and `ThreadID` on the System element

Also remove the host name and the Windows account if they appear in `_raw` or a note. Never copy `C:\lab\secrets\splunk-password.txt` or a password from a chat.

## Keep

- `EventID` / `EventCode`, `Channel`, `Provider`
- `NewProcessName`, `ParentProcessName`, `CommandLine`
- Sysmon `Image`, `ParentImage`, `CommandLine` when that is the channel
- The harmless command that was run, including `-EncodedCommand` or `certutil.exe -encode`, because that is the proof

`TargetUserSid` of `S-1-0-0` and `MandatoryLabel` may stay. They are not the user.

If a field is both identity and the thing the rule matches, keep the process and command line, and redact only the identity fields.
