---
name: minimal-detection-change
description: Make the smallest YAML edit that fixes one detection. Use when changing a DAC rule query, sourcetype, or field list, or when a Splunk search returned zero rows for a known event.
---

# Smallest detection diff

Change only the lines required to make the committed query match the event. Do not reformat the file, do not rename keys, and do not improve nearby rules.

## Rules for this repo

- One detection id per change. `DAC-WIN-0107` and `DAC-WIN-0041` are the worked examples. Do not reopen them unless the task names them.
- Edit `query.splunk` and, if the search channel changed, `sourcetypes`. Leave `tags`, `author`, and `severity` alone.
- Do not rewrite `description` unless the user asked. New descriptions are two sentences: `Alerts when ...` then `Attackers use ...`.
- Never add `index=`.
- If macros are OR'd together, wrap the whole constraint in parentheses. A bare `` `windows_sysmon` OR `windows_security` `` binds wrong.
- Coalesce `Image` from `NewProcessName` before any `Image=` filter. Filtering on `Image` first drops XML 4688.
- Prefer `| search proc="*certutil.exe" (cmd="*-encode*" OR ...)` over `match()`. Escaped `match()` in YAML has already returned false zeros.
- `DAC-WIN-0041` is the lab-proven certutil shape: the expanded Security sourcetype clause, then `| search ... sourcetype="XmlWinEventLog:Security"`. Copy that shape only when the lab event is XML Security. Do not add the trailing sourcetype to a rule that must also match classic `WinEventLog`.
- If the fix is a sourcetype mismatch, say so in the commit. Do not set `telemetry_validated` in the same diff unless `detection-reality-checker` passed on the new text.
