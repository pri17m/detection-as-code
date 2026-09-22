# Telemetry catalog

Machine-readable source of truth for tables/sourcetypes/macros and fields used by Detection-as-Code validation.

## Source of truth

- **JSON catalog:** [`content/telemetry/catalog.json`](../../content/telemetry/catalog.json)
- **Loader / slicer:** [`pipelines/validate/telemetry_catalog.py`](../../pipelines/validate/telemetry_catalog.py)
- **Field validator:** [`pipelines/validate/validate_fields.py`](../../pipelines/validate/validate_fields.py)

Human research notes under `docs/telemetry/*.md` remain useful for authoring, but **CI and Jev grounding use the JSON catalog**.

## MVP coverage (v1)

| Family | Tables / macros |
| --- | --- |
| Windows | `windows_security`, `windows_system`, `windows_powershell_operational`, `windows_powershell_classic`, `windows_sysmon` |
| CloudTrail | `aws_cloudtrail` (`aws:cloudtrail`, `aws:cloudtrail:json`, `aws:cloudtrail:event`) |

## Validate locally

```bash
pip install -r pipelines/validate/requirements.txt
python pipelines/validate/validate_repo.py
python pipelines/validate/validate_fields.py --in-repo --report content/validation/rule_field_report.json
```

Optional Jev soft-match (requires `TYPESAFE_API_KEY`):

```bash
python pipelines/validate/validate_fields.py --in-repo --jev --strict
```

## RuleAtlas candidates

```bash
pip install -r pipelines/ruleatlas/requirements.txt
python pipelines/ruleatlas/sync_sources.py
python pipelines/ruleatlas/search_candidates.py --seeds --out content/validation/candidates.json
python pipelines/validate/validate_fields.py --candidates content/validation/candidates.json --report content/validation/rule_field_report.json
```

Only candidates with verdict `PASS` should be imported into `detections/`.
