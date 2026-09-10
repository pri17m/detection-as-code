# Contributing

Thanks for helping improve Detection-as-Code.

## Ground rules

- **Defensive content only**: detections, telemetry, validation, conversion, and deployment automation. No exploitation or offensive tooling.
- **Portability is non-negotiable**: do not hardcode `index=...` in Splunk SPL; use `sourcetype=...` and CIM/data models where relevant.
- **Schema-first**: every detection must validate against `schemas/detection.schema.json`.
- **No fake MITRE**: techniques must be real ATT&CK technique IDs (e.g. `T1059.001`).

## Adding a detection

1. Pick an id:
- Windows/Splunk pack: `DAC-WIN-####`
- Defender: `DAC-MDE-####`
- CrowdStrike: `DAC-CS-####`
- Sigma sources: `DAC-SIG-####`
- Other packs (recommended): `DAC-AD-####`, `DAC-GH-####`, `DAC-CLD-####`, `DAC-HOST-####`, etc.

2. Create a YAML file under the appropriate folder in `detections/`.

3. Validate locally:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r pipelines/validate/requirements.txt
python pipelines/validate/validate_repo.py
```

## Style guide (detections)

- **Use canonical sourcetypes** listed in `config/sourcetype_map.yaml` or documented under `docs/telemetry/`.
- **Prefer CIM fields** when possible (e.g., `user`, `src`, `dest`, `process`, `process_name`, `parent_process_name`, `process_path`, `process_guid`).
- **Be explicit about required fields** (`required_fields`) and whether telemetry was validated (`telemetry_validated`).
- **Mark unvalidated detections** as `experimental` and set `telemetry_validated: false`.

## Pull requests

- Keep PRs focused and include:
  - Rule count additions by platform
  - Updated MITRE coverage % (from `content/mitre/coverage.json`)
  - Any new telemetry requirements
