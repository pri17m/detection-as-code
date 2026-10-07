---
name: soc-l2-investigate
description: Investigate one alert escalated by L1, using only process-creation logs. Use when soc-l1-triage returns escalate, or when a human asks for an L2 review of a DAC hit.
---

# L2 investigation

You take one `escalate` from L1. You decide whether the activity is a true positive, a false positive that needs a rule edit, or a case this lab cannot finish. You do not contain the host, isolate the network, or delete files.

## Scope, same host, short window

Search thirty minutes around the hit, same user, only these sourcetypes:

- `XmlWinEventLog:Security` EventCode 4688
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` EventCode 1

Look for the parent of the alerted process, the process itself, and children whose command line contains the same LOLBin. Do not pivot to network, file, registry, or logon. Those logs are not collected. Write them under `not_collected` instead of guessing.

## Verdict

```yaml
rule_id:
tier: L2
verdict: true_positive | false_positive | telemetry_gap | lab_fixture
what_happened:
parent_and_children:
not_collected:
rule_change:
human_action:
```

- `lab_fixture` if L1 missed a known harmless marker. No rule change.
- `false_positive` if a normal process matched. `rule_change` names the one predicate to tighten and hands the diff to `minimal-detection-change`. Do not set `telemetry_validated`.
- `true_positive` if the command line is the technique the rule describes and it is not a lab fixture. `human_action` is what a person should check next. You do not do it.
- `telemetry_gap` if impact, persistence, or a second host would be required to decide. Say which event id is missing. Sysmon 3, 7, 10, 11, 13, 22, PowerShell 4104, and Security 4624, 4698, and 7045 are all missing here.

A true positive on this lab is a process-creation fact. It is not proof of compromise of the account, and it is not a reason to mark the detection validated. Validation stays with `detection-reality-checker`.
