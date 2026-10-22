# DAC-AWS-0022 review note

Status: tagged `needs-review` (2026-10-20). No logic change in this PR. `telemetry_validated: false`.

## Issue: broad `eventName="*Serial*"` match, overlap with DAC-AWS-0069

Query filter:

```
eventSource="ec2-instance-connect.amazonaws.com" eventName IN ("SendSSHPublicKey","SendSerialConsoleSSHPublicKey") OR eventName="*Serial*"
```

- In Splunk search, `OR` is evaluated before the implicit `AND` (https://docs.splunk.com/Documentation/Splunk/latest/Search/Booleanexpressions), so this reads as `eventSource=... AND (eventName IN (...) OR eventName="*Serial*")`. Inside `ec2-instance-connect.amazonaws.com` the wildcard adds nothing beyond `SendSerialConsoleSSHPublicKey`, which is already listed. If a reader or a future edit assumes the other grouping, the wildcard would match any `*Serial*` event in any service (for example `EnableSerialConsoleAccess`, `GetSerialConsoleAccessStatus`, `DisableSerialConsoleAccess` on ec2.amazonaws.com), which is noisy and unintended.
- Overlap: DAC-AWS-0069 already covers serial console access (`EnableSerialConsoleAccess` on ec2.amazonaws.com joined with `SendSerialConsoleSSHPublicKey`). Both rules fire on `SendSerialConsoleSSHPublicKey`.

## Suggested follow-up (separate PR, needs approval)

- Drop `OR eventName="*Serial*"` and add explicit parentheses, or
- Scope DAC-AWS-0022 to `SendSSHPublicKey` only and leave serial console to DAC-AWS-0069.
- Either way, add tests under `tests/cases/DAC-AWS-0022/` and run them in Splunk before clearing the tag.
