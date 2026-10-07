# Log family: AWS CloudTrail (Splunk)

## Sourcetype permutations (org-dependent)

Store and try these when porting rules (never hardcode `index=` in shared DaC):

| Candidate | Notes |
|-----------|--------|
| `aws:cloudtrail` | Common Splunk Add-on for AWS |
| `aws:cloudtrail:*` | Some multi-account / pipeline variants |
| `cloudtrail` | Occasional custom rename — confirm per tenant |
| CIM / datamodel | May expose different field names post-CIM |

**Index:** often `cloudtrail` / `aws` / custom — **org overlay only**, not in shared rule body.

## Field confidence (learning loop)

Confidence: `high` = verified in official docs and/or live `_raw`; `medium` = trusted content + docs; `low` = seen in one blog/rule only.

| Field (Splunk dotted) | Confidence | Evidence |
|----------------------|------------|----------|
| `eventName` | high | AWS CloudTrail record contents |
| `eventSource` | high | AWS docs |
| `eventTime` / `_time` | high | Splunk time + CT |
| `awsRegion` | high | AWS docs |
| `userIdentity.arn` | high | AWS userIdentity docs |
| `userIdentity.type` | high | AWS docs |
| `userIdentity.sessionContext.sessionIssuer.arn` | medium | AssumedRole / federation paths |
| `userIdentity.sessionContext.sessionIssuer.userName` | medium | Role session |
| `requestParameters.roleArn` | high | PassRole / IAM APIs |
| `requestParameters.functionName` | high | Lambda Create/Update APIs |
| `responseElements.functionArn` | high | Lambda create responses |
| `responseElements.instancesSet.items{}.instanceId` | medium | EC2 RunInstances shape; confirm MV/spath |
| `sourceIPAddress` | high | AWS docs |
| `userAgent` | high | AWS docs |
| `errorCode` / `errorMessage` | high | Failed API calls |
| `requestParameters` (bag) | high | Present; nested keys vary by API |
| `responseElements` (bag) | high | Often null on failures / read-only |

## Example query fields (seed from lab discussion)

Reference pattern (behavior: privilege + compute chaining):

- `eventName` in `PassRole`, `CreateFunction`, `UpdateFunctionCode`, `RunInstances`
- `userIdentity.arn` as caller
- `requestParameters.roleArn` when PassRole
- `requestParameters.functionName` / `responseElements.functionArn` for Lambda
- `responseElements.instancesSet.items{}.instanceId` for EC2 (needs spath/mv handling)

**Portable note:** drop `index=cloudtrail`; keep sourcetype OR-set; verify nested EC2/Lambda paths against current AWS docs before `telemetry_validated`.

## Official references

- AWS: CloudTrail event record contents / userIdentity
- Splunk: Add-on for AWS / Splunk Security Content CloudTrail detections

## Last updated

- 2026-10-07 — seeded from Detection Engineer skill enhancement (PassRole/Lambda/EC2 field discussion)
