# Detection-as-Code (DaC) — Detection Engineering Portfolio

Debarshi Ghosh’s public detection-engineering portfolio: a multi-platform **Detection-as-Code** library and CI-gated pipeline for authoring, validating, and tracking behaviour-based detections across **Splunk SPL**, **CrowdStrike Falcon** (CQL / Falcon IOA-style patterns), **Microsoft Defender for Endpoint** (KQL Advanced Hunting), and **Sigma-derived sources** (when present/converted). It’s built for detection engineers who care about **high-fidelity** signals, explicit ATT&CK mappings, **field-aware validation** (and field-validated where possible), and guardrails that fail fast in CI.

## Coverage at a glance (computed from repo content)

All counts below are computed from `detections/**` plus `content/mitre/coverage.json` on the current `main` tip.

- **Total detections**: 657
- **Rules per platform**: Splunk 564 • CrowdStrike 47 • Defender 46
- **ATT&CK coverage**: 161 unique techniques • 13 unique tactics (normalized from `mitre.tactics` values)
- **ATT&CK mapping completeness**: 657/657 detections include MITRE mapping (100%)

| Platform | Rules | Query format |
| --- | ---: | --- |
| Splunk | 564 | SPL (`query.splunk`) |
| CrowdStrike Falcon | 47 | CQL / Falcon IOA-style patterns (`query.crowdstrike`) |
| Microsoft Defender for Endpoint | 46 | KQL Advanced Hunting (`query.defender`) |
| Sigma sources | 0 Sigma YAMLs under `detections/` | 10 detections carry `sigma.path` metadata (Sigma→Splunk conversions) |

**Tactics covered (normalized)**: `collection`, `command-and-control`, `credential-access`, `defense-evasion`, `discovery`, `execution`, `exfiltration`, `impact`, `initial-access`, `lateral-movement`, `persistence`, `privilege-escalation`, `resource-development`.

### Primary telemetry / sourcetypes (by frequency in `sourcetypes`)

The `sourcetypes` field is a portability contract. For Splunk Windows/ESXi sources, it’s enforced against `config/sourcetype_map.yaml` in CI; other platforms use symbolic telemetry identifiers (e.g. `mde:advanced_hunting`, `falcon:process`).

Top telemetry families referenced across the corpus:

- **Windows Sysmon**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` (140), `WinEventLog:Microsoft-Windows-Sysmon/Operational` (110), plus `sysmon` / `sysmon:*` (63 combined)
- **Windows Security**: `WinEventLog:Security` (137), `XmlWinEventLog:Security` (72)
- **Cloud audit logs**: `aws:cloudtrail` (60) + AWS CloudTrail variants, `azure:monitor:activity` (40), `azure:monitor:aad` (40), `gcp:audit` (40)
- **GitHub audit**: `github:audit` (46), `github:cloud:audit` (40)
- **VMware ESXi**: `vmw-syslog` (23), `vmware:esxlog*` (23)
- **Platform-native sources**: `falcon:process` (47), `mde:advanced_hunting` (46)

## Pipeline (Detection-as-Code)

```mermaid
flowchart LR
  A[Author YAML detection] --> B[Schema + portability validation<br/>pipelines/validate/validate_repo.py]
  B --> C[Coverage rebuild<br/>pipelines/validate/build_mitre_coverage.py]
  C --> D[CI gate (GitHub Actions)]
  D --> E[Deploy/packaging per platform<br/>docs/platforms/*]
```

## Repository layout

```text
.
├── config/
│   ├── org.example.yaml
│   └── sourcetype_map.yaml         # Splunk sourcetype/macros contract (CI-enforced for Windows/ESXi)
├── content/
│   └── mitre/
│       └── coverage.json           # Generated ATT&CK coverage inventory
├── detections/
│   ├── splunk/                     # SPL detections (Windows, cloud, GitHub, VMware, …)
│   ├── crowdstrike/                # Falcon IOA-style / CQL detections
│   └── defender/                   # MDE Advanced Hunting (KQL) detections
├── docs/
│   ├── platforms/                  # Deployment notes per platform
│   ├── reference/
│   └── telemetry/                  # Telemetry onboarding + required fields guidance
├── pipelines/
│   └── validate/                   # CI validation + MITRE coverage generator
├── quarantine/                     # Holding area (if present)
├── schemas/
│   └── detection.schema.json       # Unified detection metadata contract
├── tests/
├── CONTRIBUTING.md
└── LICENSE
```

## Rule schema (unified contract)

Every detection is YAML validated against [`schemas/detection.schema.json`](schemas/detection.schema.json). A rule must include:

- **Identity and intent**: `id`, `title`, `description`, `author`, `status`
- **Platform targeting**: `platforms` (splunk / crowdstrike / defender)
- **Telemetry contract**: `sourcetypes` (portable identifiers; Splunk Windows/ESXi allowlisted in CI)
- **ATT&CK mapping**: `mitre.tactics`, `mitre.techniques`
- **Operational metadata**: `severity`, `false_positives`, `references`, `required_fields`, `telemetry_validated`
- **Implementation**: `query.<platform>` and/or `sigma.path` (when Sigma-derived)

### Example detection (trimmed from `detections/defender/DAC-MDE-0001-powershell-encoded-command-on-endpoint.yaml`)

```yaml
id: DAC-MDE-0001
title: PowerShell encoded command on endpoint
description: Detects PowerShell executions using EncodedCommand, a common obfuscation and payload staging pattern.
author: DaC
status: experimental
platforms: [defender]
sourcetypes: [mde:advanced_hunting]
mitre:
  tactics: [execution]
  techniques: [T1059.001]
severity: high
false_positives:
  - Legitimate admin scripts may use encoded commands.
references:
  - https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table
telemetry_validated: false
required_fields: [DeviceName, ProcessCommandLine, FileName, InitiatingProcessFileName]
query:
  defender: |
    DeviceProcessEvents
    | where FileName in~ ("powershell.exe","pwsh.exe")
    | where ProcessCommandLine has_any ("-enc","-encodedcommand")
```

## Validate, test, and deploy

### Local validation (same checks as CI)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r pipelines/validate/requirements.txt
python pipelines/validate/validate_repo.py
python pipelines/validate/build_mitre_coverage.py
```

CI will fail if `content/mitre/coverage.json` changes and isn’t committed.

### Platform deployment notes

- Splunk: `docs/platforms/splunk.md`
- CrowdStrike: `docs/platforms/crowdstrike.md`
- Defender: `docs/platforms/defender.md`

## Quality bar and maturity model

This repo is intentionally conservative about what it claims.

- **Schema-gated content**: every detection must validate against `schemas/detection.schema.json`.
- **Portability guardrails**:
  - Splunk queries are rejected if they contain `index=` (deploy-time concern).
  - Splunk queries must include a `sourcetype=` constraint (or an approved telemetry macro).
  - Windows/ESXi Splunk sourcetypes are allowlisted and enforced via `config/sourcetype_map.yaml`.
- **Field validation**: `required_fields` should reflect vendor-documented fields and/or fields observed in representative telemetry.
- **ATT&CK mapping discipline**: `mitre.tactics` + `mitre.techniques` are required for every rule (coverage is inventory, not efficacy).
- **False-positive posture**: `false_positives` is part of each rule; tuning guidance should be explicit (parent process, signer, allowlists, environment constraints).
- **`telemetry_validated` meaning**:
  - `true`: query fields + log source assumptions have been validated against vendor documentation and/or representative telemetry.
  - `false`: rule is still experimental and may require field mapping and tuning.

Rules should be treated as **experimental until validated in a real tenant** (environment-specific baselines, suppressions, and ingestion differences matter).

## Roadmap

- Daily additions / iterative hardening of rule content
- Purple-team validation lab using Atomic Red Team (and other reproducible emulation) to raise confidence in behaviour-based detections
- Expand platform coverage and converters (more source formats → validated multi-platform outputs)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## About / Author

Built and maintained by **Debarshi Ghosh**. GitHub: [`pri17m`](https://github.com/pri17m)
