# AWS CloudTrail → Splunk field paths (IR Part 2)

Cross-links:
- Part 1 field matrix: [`telemetry-cloudtrail-fields.md`](./telemetry-cloudtrail-fields.md)
- Part 1 gap review: [`cloudtrail-ir-part1-gap-review.md`](./cloudtrail-ir-part1-gap-review.md)
- Scenario source: [Incident response guide for AWS CloudTrail investigations – Part 2](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-2/) (Scenario 3: SSRF → IMDSv1 → Bedrock)

This note validates **field paths** for Detection-as-Code authoring for IR Part 2 (IMDSv1 credential harvest + multi-Region Bedrock misuse). **No Part 2 gap-review file** was present at authoring time.

## Sourcetype / macro (org allowlist)

Same allowlist as Part 1 (`config/sourcetype_map.yaml`):

| Prefer | Value |
| --- | --- |
| Preferred sourcetype | `aws:cloudtrail` |
| Aliases | `aws:cloudtrail:json`, `aws:cloudtrail:event` |
| Macro | `aws_cloudtrail` → `(sourcetype=aws:cloudtrail OR sourcetype=aws:cloudtrail:json OR sourcetype=aws:cloudtrail:event)` |

**Never hardcode `index=`.** Prefer `` `aws_cloudtrail` `` or `sourcetype=aws:cloudtrail*` in rule bodies.

Splunk AWS Add-on (`aws:cloudtrail`) uses `KV_MODE = json`, so nested CloudTrail JSON becomes **dotted field names** at search time. Bare leaf names (e.g. `ec2RoleDelivery`, `modelId`, `inputTokens`) are **not** guaranteed unless a tenant adds aliases, `spath`, or CIM mappings — **needs tenant confirm**.

---

## Field matrix (Part 2)

| Field (logical) | Native CloudTrail JSON path | Splunk search examples (`aws:cloudtrail`) | When present / typical `eventName`s | Gaps / caveats |
| --- | --- | --- | --- | --- |
| **ec2RoleDelivery** (IMDS version) | **`userIdentity.sessionContext.ec2RoleDelivery`** (string) | `` `aws_cloudtrail` userIdentity.sessionContext.ec2RoleDelivery="1.0" `` <br> `` `aws_cloudtrail` userIdentity.type=AssumedRole userIdentity.sessionContext.ec2RoleDelivery=1.0 `` | Present on API events where temporary credentials were issued via **EC2 Instance Metadata Service**. Values are strings **`"1.0"`** (IMDSv1) or **`"2.0"`** (IMDSv2 / “new IMDS scheme”). Tied to IAM context key `ec2:RoleDelivery`. Appears on AssumedRole sessions from instance profiles (any `eventSource`/`eventName` using those creds — e.g. failed `CreateUser` in IR Part 2). | **Validated** under `sessionContext` by [CloudTrail userIdentity docs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) and real-event samples (e.g. Datadog Security Labs). **IR Part 2 blog** shows `userIdentity.ec2RoleDelivery` as a sibling of `sessionContext` — treat that as a **blog layout inconsistency**; prefer the official `sessionContext` path. Bare `ec2RoleDelivery` — **needs tenant confirm**. Absence ≠ “not from EC2” (field only when IMDS-issued role creds). |
| **Bedrock recon** | Top-level `eventName` + `eventSource` | `` `aws_cloudtrail` eventSource=bedrock.amazonaws.com eventName=ListFoundationModels `` | **`ListFoundationModels`**: control-plane list API; `eventSource=bedrock.amazonaws.com`, typically `readOnly=true`, `eventCategory=Management`, `managementEvent=true`. Documented in IR Part 2 Scenario 3 and Splunk ESCU sample events. | **Validated** as management. Host header often `bedrock.<region>.amazonaws.com` (control plane), not `bedrock-runtime`. |
| **Bedrock invoke (Converse / InvokeModel)** | Top-level `eventName` + `eventSource` | `` `aws_cloudtrail` eventSource=bedrock.amazonaws.com eventName IN (Converse, ConverseStream, InvokeModel, InvokeModelWithResponseStream) `` | Official Bedrock CloudTrail guide: **`InvokeModel`**, **`InvokeModelWithResponseStream`**, **`Converse`**, **`ConverseStream`** are logged as **management events** (default trail). Also **`ListAsyncInvokes`** called out as management in the same page’s data-events section. Runtime host often in `tlsDetails.clientProvidedHostHeader` = `bedrock-runtime.<region>.amazonaws.com`. | **Validated** for management logging. Related runtime APIs that are **data** events (need selectors): e.g. `InvokeModelWithBidirectionalStream`, `GetAsyncInvoke`, `StartAsyncInvoke`, Agents (`InvokeAgent`, `InvokeInlineAgent`), Knowledge Base `Retrieve`/`RetrieveAndGenerate`, Flows, Guardrails `ApplyGuardrail`, etc. |
| **modelId** | `requestParameters.modelId` | `` `aws_cloudtrail` eventSource=bedrock.amazonaws.com eventName=Converse requestParameters.modelId=* `` <br> `` `aws_cloudtrail` eventName=InvokeModel requestParameters.modelId="amazon.nova-pro-v1:0" `` | On Bedrock Runtime invoke APIs that accept a model / inference profile / prompt resource. Official **InvokeModel** CloudTrail example: `"requestParameters": { "modelId": "stability.stable-diffusion-xl-v0" }`. IR Part 2 **Converse** example: `"modelId": "amazon.nova-pro-v1:0"`. May also include nested params (e.g. `inferenceConfig.maxTokens`) — do not assume full prompt body is logged. | **Validated** for InvokeModel + Converse samples. Bare `modelId` — **needs tenant confirm**. `ListFoundationModels` does **not** use this request param the same way (URI query filters instead). Prompt **content** is **not** in CloudTrail — use Bedrock **model invocation logging** for prompts/responses. |
| **inputTokens / outputTokens** | `additionalEventData.inputTokens` / `additionalEventData.outputTokens` | `` `aws_cloudtrail` eventName=Converse additionalEventData.inputTokens=* `` <br> `` `aws_cloudtrail` eventName=Converse additionalEventData.outputTokens=* `` | IR Part 2 Converse sample: `"additionalEventData": { "inputTokens": 944, "outputTokens": 126 }` (numeric). CloudTrail [record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html): `additionalEventData` is **variable** service metadata (max size constraints; can be omitted if oversized). | **Partially validated** via AWS Security Blog IR Part 2 (Converse). **Not** present in the official Bedrock CloudTrail **InvokeModel** example. Some workshop / service-event shapes nest tokens under `serviceEventDetails.AdditionalEventData…` — different path; **needs tenant confirm** before portable DaC. Prefer dotted `additionalEventData.*`; bare `inputTokens`/`outputTokens` — **needs tenant confirm**. For full prompt/response + token counts as primary telemetry, enable [Bedrock model invocation logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) (separate sourcetype — not invent here). |

### Splunk path variants (dotted vs flattened)

| Prefer in DaC rules | Sometimes after tenant `spath` / alias / CIM | Guidance |
| --- | --- | --- |
| `userIdentity.sessionContext.ec2RoleDelivery` | `ec2RoleDelivery`; blog-style `userIdentity.ec2RoleDelivery` | Prefer official `sessionContext` path; OR-search blog path only if Telemetry confirms tenant events use it. Match `"1.0"` as string. |
| `eventName` + `eventSource=bedrock.amazonaws.com` | (same) | Stable top-level fields. |
| `requestParameters.modelId` | `modelId` | Prefer dotted under `requestParameters.*`. |
| `additionalEventData.inputTokens` / `additionalEventData.outputTokens` | `inputTokens` / `outputTokens`; alternate service-event nests | Prefer dotted; confirm presence per `eventName` in tenant data. |

---

## Bedrock: management CloudTrail vs data events vs invocation logs

| API / signal | CloudTrail category | In default management trail (`aws:cloudtrail*` family)? | Notes for IR Part 2 Scenario 3 |
| --- | --- | --- | --- |
| **`ListFoundationModels`** | **Management** (control plane) | **Yes** | Recon signal; `eventSource=bedrock.amazonaws.com`. Portable on `` `aws_cloudtrail` ``. |
| **`Converse`** / **`ConverseStream`** | **Management** (Bedrock Runtime treated as management by AWS) | **Yes** | Active model use; `requestParameters.modelId`; optional token fields in `additionalEventData`. |
| **`InvokeModel`** / **`InvokeModelWithResponseStream`** | **Management** | **Yes** | Same as Converse for trail enablement; official sample includes `modelId`, not tokens. |
| **`ListAsyncInvokes`** | **Management** (per Bedrock CT guide) | **Yes** | Related runtime list. |
| **Agents / KB / Flows / Guardrails / bidirectional & async invoke** | **Data** | **No** — needs advanced event selectors (`AWS::Bedrock::AgentAlias`, `KnowledgeBase`, `FlowAlias`, `Guardrail`, `Model` / AsyncInvoke, etc.) | Out of scope for default management-trail DaC unless tenant enables data events. |
| **Prompt / response bodies** | **Not CloudTrail** | N/A | Enable **Bedrock model invocation logging** (CloudWatch Logs / S3). Different pipeline from `aws:cloudtrail`. |
| **`bedrock-mantle` inference** | **Data** on mantle endpoint | **No** by default | Separate endpoint; do not conflate with `bedrock-runtime` management events. |

**Verdict:** For IR Part 2 Scenario 3 (`ListFoundationModels` → `Converse` / `InvokeModel`), activity lands in **default management CloudTrail** and is searchable under org allowlisted `aws:cloudtrail*` / `` `aws_cloudtrail` `` **without** Bedrock data-event enablement. Token counts may appear on some management events; prompt content does **not**. Agent/KB/mantle paths need special logging.

Sources:

- [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) — `sessionContext.ec2RoleDelivery` values `1.0` / `2.0`
- [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) — `additionalEventData` variable / size limits; `requestParameters`
- [Monitor Amazon Bedrock API calls using CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html) — InvokeModel/Converse as management; InvokeModel sample with `requestParameters.modelId`; data-event selectors for Agents/KB/etc.
- [Monitor model invocation using CloudWatch Logs and Amazon S3](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) — prompt/response + token counts outside CloudTrail
- [IR guide Part 2 (AWS Security Blog)](https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-2/) — Scenario 3: `ec2RoleDelivery` `"1.0"`, `ListFoundationModels`, `Converse`, `requestParameters.modelId`, `additionalEventData.inputTokens`/`outputTokens`
- [IMDSv2 defense-in-depth blog](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) — `ec2:RoleDelivery` context key `1.0`/`2.0`
- Datadog Security Labs sample event — confirms JSON path `userIdentity.sessionContext.ec2RoleDelivery`
- Splunk ESCU sample — `ListFoundationModels` on sourcetype `aws:cloudtrail` with `managementEvent: true`

---

## Authoring guidance (Detection Engineer)

### Validated (safe to use in portable stubs)

- Prefer macro `` `aws_cloudtrail` `` or allowlisted sourcetypes; never `index=`.
- IMDSv1 indicator: `userIdentity.sessionContext.ec2RoleDelivery="1.0"` on AssumedRole API activity (pair with instance-id session name in `userIdentity.arn` / `principalId` when present).
- Bedrock recon: `eventSource=bedrock.amazonaws.com eventName=ListFoundationModels`.
- Bedrock misuse: `eventSource=bedrock.amazonaws.com` + `eventName` in `Converse`, `ConverseStream`, `InvokeModel`, `InvokeModelWithResponseStream`.
- Model identity: `requestParameters.modelId` on those invoke events.
- Cross-Region pivot: same principal + `awsRegion` change (e.g. us-east-1 → us-east-2) as in IR Part 2 narrative.
- Correlate with Part 1 fields when present: `sessionCredentialFromConsole=true`, `additionalEventData.MFAUsed`, `userIdentity.sessionContext.attributes.mfaAuthenticated`.

### Needs tenant confirm

- Whether bare leaves (`ec2RoleDelivery`, `modelId`, `inputTokens`, `outputTokens`) exist without dotted parents.
- Whether any tenant events expose blog-style `userIdentity.ec2RoleDelivery` instead of / in addition to `sessionContext.ec2RoleDelivery` (OR both in detection only after sample confirmation).
- Presence and type of `additionalEventData.inputTokens` / `outputTokens` for **InvokeModel** vs **Converse** (and any `serviceEventDetails` variant).
- Whether Bedrock **data** events (Agents, KB, Guardrails, mantle) are enabled and which sourcetype they land under if segregated.
- Whether Bedrock **model invocation logging** is enabled (required for prompt/response IR; separate from CloudTrail).
- Org trail multi-region coverage so us-east-2 Bedrock hops are ingested.

### Alignment with IR Part 2 Scenario 3

Supports detections for: SSRF → IMDSv1 (`ec2RoleDelivery=1.0`) → permission probe → console without MFA → Bedrock `ListFoundationModels` recon → `Converse`/`InvokeModel` with `modelId` (+ optional token quantification). Does **not** replace model-invocation logs for content forensics.
