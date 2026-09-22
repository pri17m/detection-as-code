# RuleAtlas bridge

Thin wrappers around [RuleAtlas](https://github.com/lohit-cmd/RuleAtlas) for open-source detection discovery.

## Setup

```bash
pip install -r pipelines/ruleatlas/requirements.txt
```

Optional: `GITHUB_TOKEN` improves GitHub rate limits during sync.

## Sync curated sources

Default sources: **sigma** + **splunk** (CloudTrail-heavy ESCU content).

```bash
python pipelines/ruleatlas/sync_sources.py
# data lands in data/ruleatlas/ (gitignored)
```

## Search → candidates

```bash
python pipelines/ruleatlas/search_candidates.py --seeds \
  --out content/validation/candidates.json
```

## Validate fields

```bash
python pipelines/validate/validate_fields.py \
  --candidates content/validation/candidates.json \
  --report content/validation/rule_field_report.json
```

Import gate: only `PASS` candidates should be converted into `detections/`.
