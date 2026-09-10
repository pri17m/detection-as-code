# Sigma ingest and conversion

## Goal

Support a Sigma ingest path that:

- Pulls SigmaHQ community rules into a local folder (not committed by default).
- Normalizes Sigma YAML into `detections/sigma/` (metadata only, optional).
- Converts Sigma to platform-native detections (Splunk SPL, Defender KQL, CrowdStrike stubs).

## Pulling SigmaHQ rules

Recommended approach (do not commit the full SigmaHQ repository unless you intend to track its license separately):

```bash
mkdir -p vendor
git clone https://github.com/SigmaHQ/sigma vendor/sigma
```

## Converting (stub)

This repo includes a converter stub `pipelines/convert/sigma_convert.py` that can:

- Read Sigma YAML rules
- Emit DaC detection YAML with unified metadata
- Convert query logic to Splunk SPL and (optionally) Defender KQL when conversion backends are available

Install converter deps:

```bash
pip install -r pipelines/convert/requirements.txt
```

Run on a folder:

```bash
python pipelines/convert/sigma_convert.py --input vendor/sigma/rules --output detections/sigma --emit-splunk detections/splunk/windows
```

## License note

SigmaHQ rules are not Apache-2.0. If you import/copy Sigma rules into this repo, ensure you comply with the upstream rule license and keep attribution references intact.
