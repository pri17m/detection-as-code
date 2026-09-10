**ID namespace update:** Threat-Intel pack rebased to DAC-WIN-0100+ (additive to PR #1 max 0094).

# DAC Windows Pack — Naming, Metadata Schema & Sourcetype Contract

**Audience:** Detection Engineer → Threat Detection Engineer  
**Repo:** https://github.com/pri17m/detection-as-code  
**Threat Intel:** `/workspace/dac-phase1-windows-ad-attack-pack.md`  
**Telemetry canonical:** `/workspace/dac-telemetry-windows/` (`config/sourcetype_map.yaml` + docs)  
**Scaffold branch:** `cursor/dac-scaffold-05fa`

---

## 1. Rule ID naming

| Pattern | Example |
| --- | --- |
| `DAC-WIN-####` | `DAC-WIN-0100` |

Zero-padded 4 digits. Phase-1 IDs follow **P0→P1→P2** (0001–0015 = locked top-15 from Threat Intel pack).

---

## 2. Platform contract (LOCKED)

Required on every rule: `id`, `title`, `mitre.techniques` (**required**), `mitre.tactics`, `sourcetypes`, `preferred_macro`, `severity`, `status` (draft), `platforms` ([windows]), `telemetry_validated` (false), `required_fields`, `false_positives`, `references`.

Query rules: **must** use macro/`sourcetype=`; **must not** use `index=`.

---

## 3. Sourcetype allowlist (macros)

| Macro | Variants |
| --- | --- |
| `windows_security` | WinEventLog:Security, XmlWinEventLog:Security |
| `windows_system` | WinEventLog:System, XmlWinEventLog:System |
| `windows_powershell_operational` | WinEventLog:Microsoft-Windows-PowerShell/Operational, XmlWinEventLog:… |
| `windows_powershell_classic` | WinEventLog:Windows PowerShell, XmlWinEventLog:Windows PowerShell |
| `windows_sysmon` | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational (+ WinEventLog / legacy sysmon) |

Also: WinEventLog / XmlWinEventLog + `source=` channel (TA≥5).

Authoritative map lives under **`/workspace/dac-telemetry-windows/config/sourcetype_map.yaml`** (absorbed into scaffold `cursor/dac-scaffold-05fa`).

Do **not** invent TaskScheduler/WMI/TerminalServices/CA keys yet — flag `telemetry_gap`.

### Proposed map entries (mirror)

```yaml
macros:
  windows_security: [WinEventLog:Security, XmlWinEventLog:Security]
  windows_system: [WinEventLog:System, XmlWinEventLog:System]
  windows_powershell_operational:
    - WinEventLog:Microsoft-Windows-PowerShell/Operational
    - XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  windows_powershell_classic:
    - WinEventLog:Windows PowerShell
    - XmlWinEventLog:Windows PowerShell
  windows_sysmon:
    - XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    - WinEventLog:Microsoft-Windows-Sysmon/Operational
    - sysmon
    - "sysmon:*"
```

---

## 4. Metadata YAML example

```yaml
id: DAC-WIN-0100
title: "LSASS process access by non-EDR"
mitre:
  tactics: ["Credential Access"]
  techniques: ["T1003.001"]
preferred_macro: windows_sysmon
sourcetypes: [XmlWinEventLog:Microsoft-Windows-Sysmon/Operational, WinEventLog:Microsoft-Windows-Sysmon/Operational]
severity: critical
status: draft
platforms: [splunk]
telemetry_validated: false
required_fields: [SourceImage, TargetImage, GrantedAccess]
false_positives: "Legitimate AV/EDR/backup agents"
references: ["https://attack.mitre.org/techniques/T1003/001/"]
```

---

## 5. Pack layout suggestion

```text
config/sourcetype_map.yaml   # from dac-telemetry-windows
detections/splunk/windows/DAC-WIN-####.yml
docs/phase1/
tests/windows/
```

## 6. required_fields

Only from Telemetry map (`/workspace/dac-phase1/telemetry-required-fields-preview.md` and `/workspace/dac-telemetry-windows/`). Unknown Event IDs → `[]` + `telemetry_gap`.
