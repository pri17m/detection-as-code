# Detection-as-Code (DaC)

Plug-and-play Detection-as-Code for orgs adopting an in-house SOC. This repo ships:

- **Org-portable detection content** for Splunk, CrowdStrike Falcon, and Microsoft Defender.
- **A unified detection metadata schema** (validated in CI).
- **MITRE ATT&CK coverage reporting** generated from rule metadata.
- **Sourcetype portability enforcement**: detections must not hardcode `index=...`.

## Core principles

- **No hardcoded index names**. Queries must key off canonical telemetry types (e.g. `sourcetype=WinEventLog:Security`, `sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `sourcetype=github:audit`).
- **Config is deploy-time**. If your org requires index scoping, set it as an optional token/macro in `config/org.yaml` and apply it at deploy time.
- **Single metadata contract** across platforms (Splunk SPL, Defender KQL, Falcon IOA/correlation stubs, Sigma sources).

## Quickstart (adopters)

1. **Clone**

```bash
git clone <this-repo>
cd detection-as-code
```

2. **Create your org config**

```bash
cp config/org.example.yaml config/org.yaml
```

Edit `config/org.yaml`:
- Set tenant ids / placeholders as needed (Defender tenant, Falcon CID, Splunk app context, etc.).
- Optionally define index tokens if your deployment requires index scoping.

3. **Map your telemetry to canonical sourcetypes**

Edit `config/sourcetype_map.yaml` to map your actual sourcetypes (or vendor add-on sourcetypes) onto canonical aliases used by detections.

4. **Validate**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r pipelines/validate/requirements.txt
python pipelines/validate/validate_repo.py
```

CI runs the same validations:
- Detection metadata schema validation
- Query linting (forbids `index=` and other portability violations)
- MITRE coverage regeneration and diff check

5. **Deploy**

See platform docs:
- `docs/platforms/splunk.md`
- `docs/platforms/crowdstrike.md`
- `docs/platforms/defender.md`

## Repository layout

```text
/
  README.md
  CONTRIBUTING.md
  LICENSE
  config/
    org.example.yaml
    sourcetype_map.yaml
  detections/
    splunk/
      windows/
      active_directory/
      cloud/
      github/
      host/
    crowdstrike/
    defender/
    sigma/
  content/
    mitre/
      coverage.json
      gaps.md
  schemas/
    detection.schema.json
  pipelines/
    validate/
    convert/
    deploy/
  tests/
    fixtures/
    unit/
  .github/workflows/
    validate.yml
    coverage-report.yml
  docs/
    telemetry/
    platforms/
```

## Detection format

Detections are YAML files with unified metadata + a platform-native query, e.g. a Splunk rule:

```yaml
id: DAC-WIN-0001
title: "Excessive failed logons from single source"
description: "Detects bursts of EventCode 4625 that can indicate password spraying."
author: "DaC"
status: experimental
platforms: [splunk]
sourcetypes: ["WinEventLog:Security"]
mitre:
  tactics: ["TA0006"]
  techniques: ["T1110"]
severity: medium
false_positives:
  - "Legitimate user mistyping password or misconfigured service accounts"
references:
  - "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625"
telemetry_validated: false
required_fields: ["EventCode", "Account_Name", "src_ip"]
query:
  splunk: |
    sourcetype=WinEventLog:Security EventCode=4625
    | stats count dc(user) as users values(user) as users by src_ip, host
    | where count >= 20
```

## Sigma ingest

Sigma sources live under `detections/sigma/`. See `pipelines/convert/README.md` for how to pull SigmaHQ and run a converter stub that produces Splunk/Defender/CrowdStrike stubs and normalized metadata.

## License

Apache-2.0 (see `LICENSE`).
