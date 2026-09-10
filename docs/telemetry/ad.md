# Active Directory telemetry (roadmap)

Phase‑1 focuses on Windows host + Security log. AD-focused detections will expand under:

- `detections/splunk/active_directory/`

Recommended data sources:

- Domain Controller Security logs (`WinEventLog:Security`)
- AD replication / Directory Service logs (where available)
- Azure AD / Entra audit (for hybrid environments)

Key signals:

- Group membership changes (4728/4732/4756)
- Privileged logons (4672)
- Kerberos anomalies (4768/4769/4771)
