---
name: detection-reality-checker
description: Refuse to call a detection validated without a Splunk hit on the committed query. Use when someone wants telemetry_validated set, a rule marked ready to deploy, or a simulation counted as proof.
---

# Reality check for a detection

Default is fail. A green "ready to deploy" requires the committed `query.splunk` to return the fixture row. A nearby search, a saved search that differs from the YAML, or a stub that matches every process is not proof.

## Pass

All of these are true:

- The oneshot search text is the YAML `query.splunk`, not a hand-edited variant.
- Piped SPL was not wrapped in an extra `()`.
- At least one row contains the fixture marker, such as `lab-dac-win-0043` or the exact `-EncodedCommand` / `certutil.exe -encode` command that was run.
- The sourcetype on that row is one the rule actually searches. This lab writes `XmlWinEventLog:Security`. A rule that only names `WinEventLog:Security` fails even if a widened search hit.
- `validation.sample_event` is present when `telemetry_validated` is true, and `sample-redaction` has been applied.

## Fail

- Zero rows from the committed query. The rule is broken. Do not flip the flag. Hand the mismatch to `minimal-detection-change`.
- The hit came from a broad sim. A run that made about 117 of 317 `DAC-WIN-*` searches return rows was mostly stubs. Do not validate those.
- The only evidence is a screenshot or a Splunk UI search that added a sourcetype the YAML does not contain.
- `DAC-WIN-0107` is not a pass on GitHub until its file has `telemetry_validated: true` and a redacted `validation.sample_event`. A handbook badge does not count.

Write the verdict as `pass` or `fail`, the rule id, the exact SPL, and the row or the reason it was zero. Do not deploy the search.
