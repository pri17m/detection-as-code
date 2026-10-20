# REVIEW — DAC-AWS-0067 STS AssumeRoot root session issued for a member account

## Coverage before
No AssumeRoot rule on main: no rule references AssumeRoot (grep, main cbcc18d). Existing root-usage rules (if any) key on ConsoleLogin, not centralized root sessions.

## Coverage after
Behavior: sts AssumeRoot (centralized root access) issues short-lived root credentials for a member account; the root actions made with those credentials (userIdentity.type=Root, same ASIA access key) are joined onto the row. Abuse gives root on a member account (T1548.005). Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1548.005 → privilege-escalation. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html; https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-track-privileged-tasks.html
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/privilege_escalation_sts_assume_root_from_rare_user_and_member_account.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `eventName`, `eventSource`, `requestParameters.targetPrincipal`, `requestParameters.taskPolicyArn.arn`, `responseElements.credentials.accessKeyId`, `sourceIPAddress`, `userIdentity.accessKeyId`, `userIdentity.arn`, `userIdentity.principalId`, `userIdentity.type`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-track-privileged-tasks.html | none (real event) |
| malicious_1_derived.json | malicious | True | 1 | PASS | https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-track-privileged-tasks.html | errorCode=AccessDenied added and responseElements removed (failed AssumeRoot attempt; still alerts with assume_outcome=AccessDenied) |
| benign_2_real.json | benign | False | 0 | PASS | https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html | none (real event) |
| near_miss_3_real.json | near_miss | False | 0 | PASS | https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-track-privileged-tasks.html | none (real event) |

First alert row (malicious fixture): `{"session_key": "ASIAIOSFODNN7EXAMPLE", "caller": "arn:aws:sts::111111111111:assumed-role/John/JohnRole1", "target_account": "222222222222", "task_policy": "arn:aws:iam::aws:policy/root-task/S3UnlockBucketPolicy", "assume_outcome": "success", "root_actions": "s3.amazonaws.com:DeleteBucketPolicy", "src_ip": "192.0.2.1", "first_seen": "1729869731", "last_seen": "1729869827"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 0 alert row(s); base-search hits by source: {"corpus_ad_T1185_aws_concurrent_sessions_from_different_ips_cloudtrail.json": "2", "corpus_ad_T1201_aws_password_policy_cloudtrail.json": "5", "corpus_ad_T1556.006_aws_new_mfa_method_registered_for_user_cloudtrail.json": "2", "corpus_ad_T1621_aws_mfa_disabled_cloudtrail.json": "2"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (correctness): failing input: `malicious_1_derived.json` (derived: AssumeRoot with errorCode, no responseElements). With session_key taken only from responseElements, stats dropped the row: 0 rows. Fix: session_key=coalesce(accessKeyId, "nokey-".md5(_raw)), so failed attempts still alert with assume_outcome=AccessDenied. Replay now 1 row.
- F2 (triage): failing input: `malicious_0_real.json`: the AWS docs AssumeRoot plus the root DeleteBucketPolicy made with the returned key. Fix: Join root events (userIdentity.type=Root, ASIA key) on the issued accessKeyId; replay shows root_actions=s3.amazonaws.com:DeleteBucketPolicy on the same row.
- F3 (fidelity): failing input: `benign_2_real.json`: ordinary sts AssumeRole (IAM docs). `near_miss_3_real.json`: root DeleteBucketPolicy without an AssumeRoot. Fix: where has_assume=1. Both 0 rows.

## Bypass table
| Attacker variation | Result |
|---|---|
| Root console login with the member account root password | MISSED: different behaviour (ConsoleLogin) |
| AssumeRoot logged only in the management account trail and root actions only in the member trail | Partly: the join needs both accounts in the same search scope |
| Search window splits AssumeRoot and the root actions | The AssumeRoot row still alerts; root_actions may be empty |

## False-positive decisions
- Security team using centralized root access to unlock a misconfigured S3 bucket or SQS policy, or to delete root credentials (the documented task policies)
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- The join assumes the accessKeyId in responseElements.credentials equals userIdentity.accessKeyId of the root events; true in the AWS docs pair, not confirmed elsewhere.
- The base search includes all Root events with an ASIA key; volume in a real org is unmeasured.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0067/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
