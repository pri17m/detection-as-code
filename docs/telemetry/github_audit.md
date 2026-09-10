# GitHub Audit Log telemetry

## Canonical sourcetype

- `sourcetype=github:audit`

## Notes

- GitHub audit log events differ between GitHub Enterprise Cloud, Enterprise Server, and org-level exports.
- If you export to Splunk, normalize the event name and actor fields consistently (e.g., `action`, `actor`, `org`, `repo`).

This repo includes detection stubs for GitHub audit signals under `detections/splunk/github/` and `detections/defender/` (where supported via Microsoft Defender for Cloud Apps / M365 audit).
