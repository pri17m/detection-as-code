# Cloud telemetry (experimental)

This repo includes early-stage cloud control-plane detections across Splunk, CrowdStrike, and Defender/Sentinel.

Cloud content is **experimental** and may be incomplete; expect gaps as tenants onboard telemetry and detections are implemented/validated.

- `detections/splunk/cloud/`
- `detections/defender/` (KQL)
- `detections/crowdstrike/`

Recommended sources:

- Cloud provider audit logs (AWS CloudTrail / Azure Activity / GCP Audit Logs)
- Identity provider logs (Entra ID sign-in/audit)
- SaaS audit logs (GitHub, Okta, etc.)
