---
name: soc-l1-triage
description: Triage one Splunk detection hit the way an L1 analyst would. Use when a DAC rule returns rows, a lab review JSON arrives, or someone asks whether an alert should be closed or escalated.
---

# L1 triage

You are the first analyst. You do not investigate the whole host, rewrite the rule, or contain anything. You take one hit and return a verdict.

## Input

One rule id and the Splunk rows for that rule only. The lab search must use the committed `query.splunk`. Password is `C:\lab\secrets\splunk-password.txt`. Do not print it.

This host only has Security 4688 and Sysmon Event ID 1, stored as `XmlWinEventLog:Security` and `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. If the row has no command line, verdict is `telemetry_gap`.

## What you look at

From the row, record only:

- rule id
- `_time`, host, user
- process (`NewProcessName` or `Image`)
- parent process
- command line

Then answer three questions:

1. Is the command the known lab fixture? Fixtures include `lab-dac-win-0043`, a local `certutil.exe -encode` of a temp file, and the harmless encoded PowerShell that prints `DAC-LAB-SIM`. Those are `close_lab`.
2. Is the rule a stub? A stub is EventCode 1 or 4688 with no command-line predicate. A hit on a stub is `false_positive_rule`, not an incident.
3. Is the process a LOLBin with a technique argument (`-EncodedCommand`, `-encode`, `-urlcache`, `bitsadmin` with `/transfer` or `/addfile`)? That is `escalate`. `/create` followed by `/cancel` with the lab marker stays `close_lab`.

## Verdict

Return only this:

```yaml
rule_id:
tier: L1
verdict: close_lab | false_positive_rule | escalate | telemetry_gap
process:
parent:
command_line:
why:
```

`escalate` goes to `soc-l2-investigate`. Anything else stops. Do not open a case, disable the search, or edit the YAML.
