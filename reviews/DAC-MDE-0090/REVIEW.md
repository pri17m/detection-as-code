# REVIEW — DAC-MDE-0090 Node/Bun probing IMDS, ECS credentials, or local Vault

## Attribution
Based on detections.ai rule https://detections.ai/rules/01a130ac-767f-7552-9156-c9c685959b90 by Unknown. No per-rule licence shown; site Terms apply (see THIRD_PARTY_NOTICES.md).

## ATT&CK v19.2
- T1552.005 Cloud Instance Metadata API — credential-access

## Ponytail review (applied before PR)

| # | Sev | Finding | Failing input | Fix applied |
|---|---|---|---|---|
| 1 | Should | Source `ago(7d)` over DeviceNetworkEvents is heavy for a detection | Large tenant | Lookback 1d; 10m span kept |
| 2 | Nice | Single-endpoint probes (IMDS only) are common and noisy | node health check to 169.254.169.254 | Kept EndpointCount >= 2 (source behaviour); documented FP for Vault+EC2 apps |

## Field verification
| Field | Status | Source |
|---|---|---|
| DeviceNetworkEvents RemoteIP, RemotePort | verified | Microsoft Learn DeviceNetworkEvents |
| 169.254.169.254 / 169.254.170.2 | verified | AWS EC2 / ECS metadata docs |
| 127.0.0.1:8200 Vault | verified | HashiCorp Vault agent docs; Endor Labs Shai-Hulud write-up |

## Tests
Synthetic fixtures under tests/cases/DAC-MDE-0090/; result: not run.
