# AWS CloudTrail IR Guide Part 1 — DaC gap review

Field-path validation: see [`telemetry-cloudtrail-fields.md`](./telemetry-cloudtrail-fields.md).

Source: https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-1/ (03 Sep 2026)
Repo baseline: `main` / CS tip — **40** Splunk AWS rules `DAC-AWS-0001`…`0040`, all `experimental`, `telemetry_validated=false`, sourcetype `aws:cloudtrail` (+ aliases).

## Scenario coverage vs deployed

### Scenario 1 — Cross-account S3 recon → copy → delete (ransomware-ish)

| Signal from report | Key CloudTrail / S3 fields | Deployed? | Notes |
| --- | --- | --- | --- |
| Cross-account `AssumedRole` + session name masquerade | `userIdentity.type`, `userIdentity.arn`, `userIdentity.principalId`, session name after `/`, `recipientAccountId` ≠ issuer account | Partial — `DAC-AWS-0009` AssumeRole (admin ARN only) | Misses cross-account + suspicious sessionName patterns |
| `ListBuckets` recon | `eventSource=s3.amazonaws.com`, `eventName=ListBuckets`, `sourceIPAddress` | **Gap** | Not in pack |
| Object listing / recon | S3 data events `GetObject`/`ListObjects` (needs data events) | Partial — `DAC-AWS-0035` GetObject volume | No ListObjects*; data-plane needs separate sourcetype/enablement |
| `CopyObject` exfil before delete | `eventName=CopyObject` (or REST.COPY.OBJECT in S3 access logs) | **Gap** | Not in pack |
| Scripted mass `DeleteObject`/`DeleteObjects` | `eventName`, timing burst, same session | Partial — `DAC-AWS-0040` DeleteBucket/DeleteObject | Too broad; no session/IP burst correlation, no steal-then-destroy chain |
| Cross-account trust abuse | AssumeRole where `recipientAccountId` ≠ role account / external principal | Partial — `DAC-AWS-0024` CreateRole external trust, `DAC-AWS-0037` UpdateAssumeRolePolicy | No detection on *use* of cross-account S3 roles |

### Scenario 2 — Console creds → CloudShell → CloudFormation `CRYPTO` mining

| Signal from report | Key fields | Deployed? | Notes |
| --- | --- | --- | --- |
| Console login without MFA | `eventName=ConsoleLogin`, `additionalEventData.MFAUsed`, `userIdentity.sessionContext.attributes.mfaAuthenticated` | Partial — `DAC-AWS-0011` | Query is noisy (`errorMessage=""`); weak MFA field usage |
| `sessionCredentialFromConsole=true` + CloudShell UA | `sessionCredentialFromConsole`, `userAgent` contains `exec-env/CloudShell` | **Gap** | Strong console→CLI pivot IOC |
| `CreateStack` suspicious name / mining | `eventName=CreateStack`, `requestParameters.stackName`, `responseElements.stackId` | Partial — `DAC-AWS-0038` CreateStack+CAPABILITY_IAM | Misses stackName keywords (CRYPTO/miner), CloudShell actor, no MFA session |
| Follow-on `RunInstances` from stack | `eventName=RunInstances`, userdata / public subnet | Partial — `DAC-AWS-0017` | Not chained to CreateStack |
| Persistence after mining | CreateUser / CreateAccessKey / CreateLoginProfile | Covered — `DAC-AWS-0023`, `0003`/`0005`, `0004` | Keep; useful for scenario checklist |

## Validated field notes (from report payloads)

CloudTrail management events (reliable if trail multi-region + org trail):
- Identity: `userIdentity.type`, `.arn`, `.principalId`, `.sessionContext.sessionIssuer`, `.sessionContext.attributes.mfaAuthenticated`
- Event: `eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userAgent`, `errorCode`
- Console pivot: `sessionCredentialFromConsole`
- Request/response: `requestParameters.*`, `responseElements.*`, `recipientAccountId`

S3 data-plane (ListObjects / GetObject / CopyObject / DeleteObject) often needs **S3 data events** or **S3 server access logs**, not management CloudTrail alone. `ListBuckets` is management API and should appear in CloudTrail.

## Recommended adds (next IDs `DAC-AWS-0041+`)

P0
1. Cross-account AssumedRole with unusual sessionName (masquerade) + optional external `sourceIPAddress`
2. S3 `ListBuckets` by AssumedRole / rare principal (recon)
3. Burst `DeleteObject`/`DeleteObjects` same `userIdentity`/`sourceIPAddress` in short window
4. Steal-then-destroy chain: `CopyObject`/`GetObject` then `DeleteObject` on same key/prefix within N minutes
5. Console session without MFA → privileged API (`CreateStack`,`RunInstances`,`CreateAccessKey`,…)
6. CloudShell (`userAgent`/`exec-env/CloudShell`) performing `CreateStack`/`RunInstances`/`CreateUser`
7. `CreateStack`/`UpdateStack` with stackName matching crypto/miner/xmrig/etc. OR CAPABILITY_IAM from rare actor (enhance 0038)

P1
8. Cross-account S3 access: `recipientAccountId` vs role account mismatch on S3 APIs
9. Rapid AssumeRole → ListBuckets → Delete* sequence (transactional correlation)
10. CloudFormation stack creating EC2 in public subnet / userdata download (needs CFN + EC2 correlation)

## Quality bar

Existing Wave C AWS stubs are **thin** (single eventName + table) — same bar raise as CrowdStrike TP rewrite: portable `sourcetype=aws:cloudtrail*`, concrete predicates on validated fields, correlation where the report’s kill-chain needs it, no hardcoded `index=`.
