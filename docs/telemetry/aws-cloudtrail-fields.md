# AWS CloudTrail → Splunk field paths (IR Part 1)

Cross-link: scenario coverage and detection gaps live in [`cloudtrail-ir-part1-gap-review.md`](./cloudtrail-ir-part1-gap-review.md). This note validates **field paths** for Detection-as-Code authoring.

## Sourcetype / macro (org allowlist)

From `config/sourcetype_map.yaml`:

| Prefer | Value |
| --- | --- |
| Preferred sourcetype | `aws:cloudtrail` |
| Aliases | `aws:cloudtrail:json`, `aws:cloudtrail:event` |
| Macro | `aws_cloudtrail` → `(sourcetype=aws:cloudtrail OR sourcetype=aws:cloudtrail:json OR sourcetype=aws:cloudtrail:event)` |

**Never hardcode `index=`.** Prefer `` `aws_cloudtrail` `` or `sourcetype=aws:cloudtrail*` in rule bodies.

Splunk AWS Add-on (`aws:cloudtrail`) uses `KV_MODE = json`, so nested CloudTrail JSON becomes **dotted field names** at search time (e.g. `userIdentity.sessionContext.attributes.mfaAuthenticated`). Bare leaf names (e.g. `mfaAuthenticated` alone) are **not** guaranteed unless a tenant adds aliases, `spath`, or CIM mappings — **needs tenant confirm**.

---

## Field matrix

| Field (logical) | Native CloudTrail JSON path | Splunk search examples (`aws:cloudtrail`) | When present / typical `eventName`s | Gaps / caveats |
| --- | --- | --- | --- | --- |
| **sessionCredentialFromConsole** | Top-level `sessionCredentialFromConsole` (string `"true"` / `"false"`) | `` `aws_cloudtrail` sessionCredentialFromConsole=true `` <br> `` `aws_cloudtrail` sessionCredentialFromConsole="true" `` | Optional since **eventVersion 1.08**. AWS docs: field is **not shown unless value is `true`**. Marks API calls made with credentials from an **AWS Management Console** session (console proxy or external client using console-issued creds). Seen on follow-on management APIs after console sign-in (e.g. `EnableMFADevice`, `CreateVirtualMFADevice`, CloudShell/`exec-env/CloudShell` API calls, `CreateStack`, Bedrock recon, etc.) — **not** a field on `ConsoleLogin` itself. | **Validated** (AWS record contents + console sign-in examples + ESCU sample events). Correlate with `userAgent` containing `exec-env/CloudShell` for console→CLI pivot. Absence ≠ “not from console” only when false is omitted. |
| **mfaAuthenticated** (session) | `userIdentity.sessionContext.attributes.mfaAuthenticated` | `` `aws_cloudtrail` userIdentity.sessionContext.attributes.mfaAuthenticated=false `` <br> `` `aws_cloudtrail` "userIdentity.sessionContext.attributes.mfaAuthenticated"=true `` | Present when `userIdentity.sessionContext` exists (temporary credentials / console MFA session context). Values are strings **`"true"`** / **`"false"`**. Appears on AssumedRole API events, post-login management calls with session context (e.g. `EnableMFADevice`, `ChangePassword`, federated `GetSigninToken` / `ConsoleLogin` with AssumedRole). | **Validated** path. Do **not** treat as the primary ConsoleLogin MFA signal (use `MFAUsed` for that). Federated/SSO sessions often show `"false"`. Bare field `mfaAuthenticated` — **needs tenant confirm**. |
| **MFAUsed** (console login) | `additionalEventData.MFAUsed` | `` `aws_cloudtrail` eventName=ConsoleLogin additionalEventData.MFAUsed=No `` <br> `` `aws_cloudtrail` eventName=ConsoleLogin additionalEventData.MFAUsed=Yes `` | Primary MFA indicator on **`ConsoleLogin`** (`eventSource=signin.amazonaws.com`, `eventType=AwsConsoleSignIn`). Values **`"Yes"`** / **`"No"`** (not boolean). Also appears on some federated sign-in events (e.g. `GetSigninToken`). Pair with `responseElements.ConsoleLogin` = `Success`/`Failure`. | **Validated**. ESCU detections use this exact dotted path. Not present on ordinary service API calls. Do not confuse with `mfaAuthenticated`. |
| **recipientAccountId** | Top-level `recipientAccountId` | `` `aws_cloudtrail` recipientAccountId=* `` <br> Cross-account: `` `aws_cloudtrail` recipientAccountId!=userIdentity.accountId `` (or compare to role account from ARN) | Optional since **1.02**; present on most management (and data) events. Account ID that **received** the event. Differs from `userIdentity.accountId` in **cross-account resource access** (e.g. KMS, S3 cross-account). | **Validated**. Core for Scenario 1 cross-account detections. Confirm org-trail delivery to both requester and resource-owner accounts. |
| **stackName** (CFN) | `requestParameters.stackName` | `` `aws_cloudtrail` eventSource=cloudformation.amazonaws.com eventName=CreateStack requestParameters.stackName=* `` <br> Keyword hunt: `` requestParameters.stackName IN ("*CRYPTO*", "*miner*", "*xmrig*") `` (tune per tenant) | CloudFormation management APIs: **`CreateStack`**, also `UpdateStack` / `DeleteStack` / describe-style calls that take `StackName`. Official CFN CloudTrail example logs `"stackName": "my-test-stack"` under `requestParameters`. Related: `responseElements.stackId`. | **Validated** for CreateStack. Parameter **values** in templates are often omitted; stack **name** is logged. Keyword lists are org-specific — **needs tenant confirm**. |

### Splunk path variants (dotted vs flattened)

| Prefer in DaC rules | Sometimes after tenant `spath` / alias / CIM | Guidance |
| --- | --- | --- |
| `sessionCredentialFromConsole` | (same — already top-level) | Prefer exact string match `=true` / `="true"`. |
| `userIdentity.sessionContext.attributes.mfaAuthenticated` | `mfaAuthenticated` | Prefer full dotted path; document alias only if Telemetry confirms. |
| `additionalEventData.MFAUsed` | `MFAUsed` | Prefer dotted; ESCU / AWS TA samples use dotted. Values `Yes`/`No`. |
| `recipientAccountId` | (same) | Top-level; stable. |
| `requestParameters.stackName` | `stackName` | Prefer dotted under `requestParameters.*`. |

---

## S3: management CloudTrail vs data events

| API / signal | CloudTrail category | In default management trail (`aws:cloudtrail` family)? | Notes for IR Part 1 Scenario 1 |
| --- | --- | --- | --- |
| **`ListBuckets`** | **Management** (bucket-/account-level) | **Yes** — logged with management events by default | `eventSource=s3.amazonaws.com`, `eventName=ListBuckets`, `eventCategory=Management`. Suitable for recon detections on `` `aws_cloudtrail` `` without S3 data-event enablement. |
| **`CopyObject`** | **Data** (object-level, `resources.type=AWS::S3::Object`) | **No** — requires **S3 data events** on the trail (or S3 server access logs as alternate telemetry) | Exfil-before-delete chain **cannot** rely on management-only CloudTrail. Confirm tenant data-event selectors / alternate sourcetype before authoring. |
| **`DeleteObject`** / **`DeleteObjects`** | **Data** (object-level) | **No** — same as above | Burst delete / ransomware-ish detections need data events. `DeleteBucket` is **management** and is a different signal (already partly covered by pack rules). |
| Related recon: `ListObjects`, `ListObjectsV2`, `GetObject` | **Data** | **No** | Same enablement requirement. |

**Verdict:** `ListBuckets` → management `aws:cloudtrail`. `CopyObject` and `DeleteObject` → **S3 data events** (or S3 access logs), not management CloudTrail alone.

Sources:

- [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) — `sessionCredentialFromConsole`, `recipientAccountId`, `additionalEventData`, `requestParameters`
- [Console sign-in events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html) — `ConsoleLogin` + `additionalEventData.MFAUsed`, examples with `sessionCredentialFromConsole` on post-login APIs
- [userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) — `sessionContext.attributes.mfaAuthenticated`
- [Amazon S3 CloudTrail events](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html) — management (`ListBuckets`) vs data (`CopyObject`, `DeleteObject`, …)
- [CloudFormation API logging](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-api-logging-cloudtrail.html) — `CreateStack` / `requestParameters.stackName`
- Splunk ESCU / AWS TA: `KV_MODE=json` on `aws:cloudtrail`; ESCU uses `additionalEventData.MFAUsed` and `userIdentity.sessionContext.attributes.mfaAuthenticated`

---

## Authoring guidance (Detection Engineer)

### Validated (safe to use in portable stubs)

- Prefer macro `` `aws_cloudtrail` `` or allowlisted sourcetypes; never `index=`.
- Console without MFA: `eventName=ConsoleLogin` + `additionalEventData.MFAUsed=No` + success via `responseElements.ConsoleLogin=Success` (or ESCU-style `errorCode=success` if TA normalizes).
- Console→API pivot: `sessionCredentialFromConsole=true` on privileged `eventName`s (`CreateStack`, `RunInstances`, `CreateAccessKey`, …); optional `userAgent="*exec-env/CloudShell*"`.
- Session MFA on API activity: `userIdentity.sessionContext.attributes.mfaAuthenticated=false` **in addition to**, not instead of, login `MFAUsed`.
- Cross-account: compare `recipientAccountId` to issuer/role account from `userIdentity.accountId` / ARN.
- CFN mining name: `eventName=CreateStack` + `requestParameters.stackName` keyword predicates.
- S3 recon via **`ListBuckets`** on management CloudTrail is portable for Scenario 1 P0.

### Needs tenant confirm

- Whether bare leaf fields (`MFAUsed`, `mfaAuthenticated`, `stackName`) exist without dotted parents.
- Whether `errorCode` is coalesced to `"success"` by AWS TA EVAL (affects ConsoleLogin success checks).
- **S3 data events** enabled for `CopyObject` / `DeleteObject` / `GetObject` / `ListObjects*` — and which sourcetype those land under if segregated.
- Org CloudFormation stackName deny-list / mining keywords.
- Org trail: multi-region + organization trail so `recipientAccountId` cross-account copies are actually ingested.

### Alignment with gap review

Matches [`cloudtrail-ir-part1-gap-review.md`](./cloudtrail-ir-part1-gap-review.md): Scenario 2 MFA fields and `sessionCredentialFromConsole`; Scenario 1 `ListBuckets` as management; `CopyObject`/`DeleteObject` as data-plane gaps for P0 chain detections (`DAC-AWS-0041+`).
