---
name: detection-review
description: Review a detection pull request against this repo's schema and lab facts. Use when reviewing a DAC YAML change, a validation flag flip, or before merging a detection.
---

# Review one detection change

Review the diff. Do not rewrite it unless asked. CI is `python pipelines/validate/validate_repo.py` from `.github/workflows/validate.yml`. Schema failure is a reject.

## Reject if

- `additionalProperties` would fail: an unknown key, or `telemetry_validated: true` without `validation.sample_event`.
- Any `index=` in Splunk SPL.
- The query searches only `sourcetype=WinEventLog:Security` or `sourcetype=WinEventLog:Sysmon` while the evidence event is `XmlWinEventLog:Security` or `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.
- `Image=` or `NewProcessName=` is required before `coalesce`. That dropped the encoded-PowerShell 4688 for `DAC-WIN-0107`.
- Macro OR is not parenthesized.
- The description was rewritten without being asked, or a new description is not `Alerts when ...` plus `Attackers use ...`.
- Tactics are not kebab-case, or a technique is not `T####` / `T####.###`.
- `telemetry_validated` flipped to true without a reality-check pass on that exact query text.
- The diff touches a second rule, `content/mitre/coverage.json` by hand, or anything under a secrets path.
- The sample still contains a computer name, account, domain, SID, or logon id.

## Accept if

The diff is one rule, schema-valid, free of `index=`, and either leaves `telemetry_validated` false or includes a redacted sample plus a stated Splunk row count greater than zero for the new query.
