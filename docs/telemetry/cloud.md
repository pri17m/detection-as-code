# Cloud telemetry (roadmap)

This repo aims to support cloud control-plane detections across Splunk, CrowdStrike, and Defender/Sentinel.

For Phase‑1, cloud packs are **stubs** (folder structure + schema examples) and will be filled as tenants onboard:

- `detections/splunk/cloud/`
- `detections/defender/` (KQL)
- `detections/crowdstrike/`

Recommended sources:

- Cloud provider audit logs (AWS CloudTrail / Azure Activity / GCP Audit Logs)
- Identity provider logs (Entra ID sign-in/audit)
- SaaS audit logs (GitHub, Okta, etc.)
