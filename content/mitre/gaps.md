# MITRE ATT&CK coverage gaps (prioritized)

This repo generates `content/mitre/coverage.json` from detection metadata. This document captures **high-priority gaps** to drive roadmap and customer telemetry onboarding.

> Note: gaps are listed as techniques to add detections for, not necessarily as “missing telemetry”. Some gaps may be blocked on data availability (e.g. M365 audit, cloud control plane logs).

## Phase-1 focus (Windows / host)

- **T1003** OS Credential Dumping (beyond simple LSASS access signals)
- **T1555** Credentials from Password Stores
- **T1546.003** Event Triggered Execution: Windows Management Instrumentation Event Subscription
- **T1562.001** Impair Defenses: Disable or Modify Tools (broader coverage across products)
- **T1070.004** Indicator Removal: File Deletion (needs EDR/file telemetry)

## Active Directory (high priority)

- **T1558** Steal or Forge Kerberos Tickets (silver/golden tickets)
- **T1484.001** Domain Policy Modification: Group Policy Modification
- **T1649** Steal or Forge Authentication Certificates (AD CS abuse)
- **T1098** Account Manipulation (delegation, shadow credentials)

## Cloud control plane (high priority)

- **T1098.001** Account Manipulation: Additional Cloud Credentials
- **T1526** Cloud Service Discovery
- **T1578** Modify Cloud Compute Infrastructure
- **T1552.001** Unsecured Credentials: Credentials In Files (cloud storage)

## GitHub (high priority)

- **T1098.003** Account Manipulation: Additional Cloud Roles (org/repo privilege escalation)
- **T1567.001** Exfiltration to Cloud Storage (via artifacts/releases)
- **T1552.004** Unsecured Credentials: Private Keys

