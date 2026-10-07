---
name: threat-intel-prioritizer
description: Choose the next detection to write or fix from attacker technique and available logs. Use before creating a DAC rule, when asked which technique to cover, or when a rule needs a log this lab does not collect.
---

# Threat intel, then a log source

Decide whether a technique deserves a rule in this repo. Do not write YARA, Snort, or a new pack. The output is one technique, one log, and a yes or no on lab validation.

## This environment

- Repo schema is `schemas/detection.schema.json`. Queries are `query.splunk`, `query.defender`, or `query.crowdstrike`.
- The laptop lab collects only Security 4688 with a command line, and Sysmon Event ID 1. Splunk sourcetypes are `XmlWinEventLog:Security` and `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.
- It does not collect Sysmon 3, 7, 10, 11, 13, or 22, PowerShell 4104, or Security 4624, 4698, or 7045. A rule that needs those cannot be lab-validated here. Say which channel is missing and stop.
- Claude rules need `sourcetype="anthropic:compliance:activity"`. This lab does not have that source.
- Many Windows rules search only `WinEventLog:Security`. Those miss this lab even when the event exists. Prefer fixing that class before writing a new rule.
- A search that is only `EventCode=1` or only `EventCode=4688` is a stub. Do not treat a hit on it as coverage.

## How to choose

1. Read the vendor document for the event, not a blog summary. For Windows process creation that is Security 4688 and Sysmon Event ID 1.
2. Map one ATT&CK technique. Use a real id.
3. Name the sourcetype from `config/sourcetype_map.yaml`.
4. If the lab collects that event, hand the rule to `threat-detection-engineer`. If it does not, write the rule as `telemetry_validated: false` and say it is not lab-ready.
5. Do not propose a fixture. The detection engineer asks the human for a harmless command.
