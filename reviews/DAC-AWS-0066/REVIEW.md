# REVIEW — DAC-AWS-0066 Lambda function permission granted to any principal or a foreign account

## Coverage before
No Lambda resource-policy rule on main: no rule references AddPermission on lambda.amazonaws.com (grep, main cbcc18d).

## Coverage after
Behavior: lambda AddPermission (any API-version suffix) whose principal is "*" or another AWS account. A function invocable by anyone or by the attacker account is a backdoor that survives credential rotation (T1546). Service principals are not flagged. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1546 → privilege-escalation, persistence. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.lambda-backdoor-function.json
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_lambda_backdoor_invoke_function_for_any_principal.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `awsRegion`, `eventName`, `eventSource`, `recipientAccountId`, `requestParameters.action`, `requestParameters.functionName`, `requestParameters.principal`, `requestParameters.statementId`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.lambda-backdoor-function.json | none (real event) |
| malicious_1_derived.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.lambda-backdoor-function.json | principal set to a foreign account root ARN |
| benign_2_derived.json | benign | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.lambda-backdoor-function.json | principal set to service principal s3.amazonaws.com |
| near_miss_3_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.lambda-backdoor-function.json | principal set to the recipientAccountId (own account) |
| near_miss_4_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.lambda-backdoor-function.json | errorCode added |

First alert row (malicious fixture): `{"_time": "2024-08-01 13:47:16.000 IST", "actor": "arn:aws:iam::880896431042:user/christophe", "recipientAccountId": "880896431042", "awsRegion": "ca-centralnorth-1r", "function": "stratus-red-team-backdoor-f-func", "exposure": "any_principal", "principal": "*", "action": "lambda:InvokeFunction", "statement_id": "backdoor", "sourceIPAddress": "151.236.251.251", "userAgent": "stratus-red-team_a5b48423-fe4e-446d-a058-0f2b624cdfb1"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 1 alert row(s); base-search hits by source: {"corpus_sr_aws.persistence.lambda-backdoor-function.json": "1"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (correctness): failing input: `malicious_1_derived.json` (derived: principal=arn:aws:iam::111111111111:root). A principal="*"-only check returned 0 rows. Fix: Extract the account from a bare 12-digit ID or an IAM ARN and flag it when it differs from recipientAccountId. Replay now 1 row, exposure=foreign_account.
- F2 (fidelity): failing input: `benign_2_derived.json`: principal=s3.amazonaws.com (service principal). Fix: Service principals are neither "*" nor an account, so exposure stays null. 0 rows.
- F3 (correctness): failing input: The real Stratus payload logs eventName AddPermission20150331v2; AWS has announced it is removing date suffixes (https://github.com/SummitRoute/aws_breaking_changes/issues/53). Fix: eventName IN (AddPermission, AddPermission20150331, AddPermission20150331v2).

## Bypass table
| Attacker variation | Result |
|---|---|
| Grant to a service principal with an attacker-controlled SourceArn (e.g. attacker S3 bucket) | MISSED: sourceArn/sourceAccount not in the payload |
| CreateFunctionUrlConfig with AuthType NONE | MISSED: no real payload; not built (see PR body) |
| Grant via organization (principalOrgID) | MISSED: no payload |

## False-positive decisions
- Public function URLs that need principal "*" (AWS documents this for AuthType NONE: https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html)
- Cross-account invocation by a known partner or org account; allowlist account IDs
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- The principal "*" with a SourceAccount/SourceArn condition (legitimate pattern for some services) would still alert; field not in the payload, so not filtered.
- The undated eventName AddPermission has no real payload.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0066/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
