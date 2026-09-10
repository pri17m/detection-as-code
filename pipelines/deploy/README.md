# Deployment hooks (docs-first)

This repository is designed so orgs can deploy detections through their preferred tooling.

## Splunk

Recommended model:

1. Parse detection YAML under `detections/splunk/`.
2. Apply deploy-time scoping from `config/org.yaml` (macros/tokens).
3. Push:
   - Saved searches
   - Correlation searches (ES)
   - Notables / risk rules

Deployment mechanisms:

- Splunk REST API (saved searches, macros)
- Splunk app packaging (for versioned deployments)

## CrowdStrike Falcon

Map `detections/crowdstrike/*` into:

- Custom IOA rules
- Correlation rules / workflows (if enabled)

## Microsoft Defender

Map `detections/defender/*` into:

- Defender Advanced Hunting queries (for custom detection rules)
- (Optional) Sentinel analytics rules

## Security note

This repo intentionally avoids storing credentials. Use your CI secret store and platform-native auth methods.
