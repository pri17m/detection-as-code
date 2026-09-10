# CrowdStrike Falcon adoption and deployment

This repo supports Falcon detections as:

- **Custom IOAs** (process/network patterns)
- **Correlation rules** (where applicable)

Detections live under `detections/crowdstrike/` with unified metadata and a `query.crowdstrike` field.

## Notes

- Falcon detection formats vary by product (Falcon Insight, Falcon Identity, Falcon Cloud Security).
- For now, `query.crowdstrike` is treated as a **portable expression / stub** that adopters can translate into their specific Falcon rule primitives.

See `pipelines/deploy/README.md` for deployment hooks and placeholders.
