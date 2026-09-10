# Enhance-TP (TP-quality re-port of enhance-existing)

**Output:** `/workspace/dac-crowdstrike/enhance-tp/`  
**Bar:** same as `tp-rewrite/` (gold: `DAC-CS-0063.yml`) — concrete ImageFileName/CommandLine/ParentBaseFileName predicates, proper `#event_simpleName`, no wildcard-only, no `splitString(..., index=N)` (use `regexExtract`).  
**Tags:** `enhance-tp` + `tp-quality-v2`. `telemetry_validated: false`. `sourcetypes: [falcon:process]`.  
**Scope:** 11 unique enhance IDs (same filenames as `enhance/`). No new IDs. No GitHub push.

## Files

| File | ID | Query-Hub source(s) | ESN used | Notes |
| --- | --- | --- | --- | --- |
| `DAC-CS-0001-falcon-powershell-encoded-command.yaml` | DAC-CS-0001 | `Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml`, `Detect_and_Decode_Base64-Encoded_PowerShell_Commands-http.yml`, `Suspicious_PowerShell_Execution.yml`, `Hunting_Powershell_Command_Length_Anomaly.yml`, `applications_spawning_cmd_or_powershell.yml` | ProcessRollup2, ProcessBlocked | Encoded PS `-e/-enc/-encodedcommand` + `regexExtract` for base64 blob (CI-safe; no splitString index) |
| `DAC-CS-0002-falcon-office-spawning-shell.yaml` | DAC-CS-0002 | `attachments_send_by_outlook.yml`, `Hunt_links_opened_from_Outlook.yml` | ProcessRollup2 | H1 Office→shell (prior IOA) + H2 content.outlook + H3 Outlook→browser |
| `DAC-CS-0003-falcon-regsvr32-remote-scriptlet.yaml` | DAC-CS-0003 | `LOLBin_Regsvr32.yml` | ProcessRollup2, ProcessBlocked | scrobj.dll + `/i:` |
| `DAC-CS-0004-falcon-mshta-remote-execution.yaml` | DAC-CS-0004 | `LOLBin_Mshta.yml` | ProcessRollup2, ProcessBlocked | http(s)/.hta/javascript:/vbscript: |
| `DAC-CS-0005-falcon-rundll32-suspicious-execution.yaml` | DAC-CS-0005 | `LOLBin_Rundll32.yml`, `Rundll32_Remote_UNC_DLL_Ordinal_Execution.yml` | ProcessRollup2, ProcessBlocked | OR hypotheses (suspicious parent / UNC ordinal / script\|comsvcs) — not incorrectly ANDed |
| `DAC-CS-0010-falcon-netsh-firewall-off.yaml` | DAC-CS-0010 | `Firewall_Rule_Additions.yml` (THIN FirewallSetRule) | ProcessRollup2, ProcessBlocked | **SAFE rewrite:** netsh ImageFileName + advfirewall/firewall CommandLine (no FirewallSetRule) |
| `DAC-CS-0011-falcon-certutil-download-decode.yaml` | DAC-CS-0011 | `LOLBin_Certutil.yml` | ProcessRollup2, ProcessBlocked | -urlcache/-decode/-verifyctl/http(s) |
| `DAC-CS-0012-falcon-bitsadmin-transfer.yaml` | DAC-CS-0012 | `hunting_bitsadmin_usage.yml` | ProcessRollup2 | PR2 bitsadmin transfer/addfile/URL; ScriptControlScanV2/CommandHistory branch not required for TP |
| `DAC-CS-0013.yml` | DAC-CS-0013 | `Credential_Dumping_Detection.yml` | ProcessRollup2 | mimikatz/procdump/lsass/sekurlsa predicates |
| `DAC-CS-0038.yml` | DAC-CS-0038 | `LOLBin_WMIC.yml` | ProcessRollup2, ProcessBlocked | wmic + **process call create** CommandLine (fixes ImageFileName-only weakness) |
| `DAC-CS-0047.yml` | DAC-CS-0047 | `ransomware_precursors.yml`, `shadow_mcp_server_activity_via_common_runtime_interpreters.yml` | ProcessRollup2 | T1490 recovery-inhibition case (H1–H7) + H8 shadow MCP runtime |

## Before → after (requested)

### DAC-CS-0001
**Before (enhance/):** Incoherent pipe-chain of five QH snippets (rename FileName, undefined DecodedString/executionCount, duplicate filters); not a single executable TP query.  
**After:** Single ProcessRollup2/ProcessBlocked query — `ImageFileName` powershell/pwsh + encoded-command regex + `regexExtract` for base64 + length gate + groupBy.

### DAC-CS-0010
**Before (enhance/):** ProcessRollup2 query referencing `FirewallRule`/`FirewallRuleId` (FirewallSetRule fields) without join — invalid / THIN.  
**After:** SAFE netsh `ImageFileName=/netsh\.exe$/i` + concrete firewall-disable/add-delete-rule `CommandLine` regex on ProcessRollup2/ProcessBlocked.

## Gate checklist
- [x] 11 files in `enhance-tp/` (same filenames as `enhance/`)
- [x] Zero wildcard-only ImageFileName/CommandLine stubs
- [x] No `splitString(..., index=`
- [x] `#event_simpleName` / `in(#event_simpleName, …)` present
- [x] `enhance-tp` + `tp-quality-v2` tags
- [x] Existing ids/titles/MITRE retained
- [x] `telemetry_validated: false`, `falcon:process`, false_positives, required_fields
