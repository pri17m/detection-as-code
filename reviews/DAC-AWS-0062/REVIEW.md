# REVIEW — DAC-AWS-0062 AWS Backup recovery point, backup vault or vault lock deleted

## Coverage before
No AWS Backup rule on main: no rule in detections/splunk/cloud/aws references backup.amazonaws.com (grep, main cbcc18d). Closest: DAC-AWS rules on S3 bucket deletion/versioning, which do not cover AWS Backup.

## Coverage after
Behavior: a principal deletes AWS Backup recovery points, a backup vault, a vault lock configuration or a backup plan (backup.amazonaws.com). Removing backups before encryption or deletion stops recovery (T1490). One row per actor with recovery-point count. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1490 → impact. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://docs.aws.amazon.com/aws-backup/latest/devguide/logging-using-cloudtrail.html
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_backup_vault_deleted_or_lock_removed.toml; https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_backup_recovery_point_deleted.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode, userIdentity.invokedBy): `awsRegion`, `eventName`, `eventSource`, `recipientAccountId`, `requestParameters.backupVaultName`, `requestParameters.recoveryPointArn`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`, `userIdentity.invokedBy`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://docs.aws.amazon.com/aws-backup/latest/devguide/logging-using-cloudtrail.html | none (real event) |
| benign_1_real.json | benign | False | 0 | PASS | https://docs.aws.amazon.com/aws-backup/latest/devguide/logging-using-cloudtrail.html | none (real event) |
| near_miss_2_derived.json | near_miss | False | 0 | PASS | https://docs.aws.amazon.com/aws-backup/latest/devguide/logging-using-cloudtrail.html | DeleteRecoveryPoint with errorCode=AccessDeniedException added (failed attempt) |
| near_miss_3_derived.json | near_miss | False | 0 | PASS | https://docs.aws.amazon.com/aws-backup/latest/devguide/logging-using-cloudtrail.html | userIdentity replaced with the service-invoked shape used by this same docs page (invokedBy=backup.amazonaws.com) |

First alert row (malicious fixture): `{"actor": "arn:aws:iam::123456789012:root", "recipientAccountId": "account-id", "awsRegion": "us-east-1", "deletions": "1", "recovery_points": "1", "actions": "DeleteRecoveryPoint", "vaults": "Default", "recovery_point_arns": "arn:aws:ec2:us-east-1::snapshot/snap-05f426fd9daab3433", "src_ip": "12.34.567.89", "user_agent": "aws-internal/3 aws-sdk-java/1.11.465 Linux/4.9.124-0.1.ac.198.73.329.metal1.x86_64 OpenJDK_64-Bit_Server_VM/25.192-b12 java/1.8.0_192", "first_seen": "1792498057", "last_seen": "1792498057", "vault_or_lock_removed": "0"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 0 alert row(s); base-search hits by source: {}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (fidelity): failing input: `near_miss_3_derived.json`: the docs DeleteRecoveryPoint event with the service-invoked identity shape from the same page (userIdentity.invokedBy=backup.amazonaws.com, no arn). Without the invokedBy filter the replay returned 1 row with actor="unknown". Fix: Drop events where userIdentity.invokedBy is set (AWS service acting, e.g. lifecycle expiry). Replay now 0 rows.
- F2 (correctness): failing input: The docs example has userIdentity.type=Root with arn only; a service event has no arn, so `stats BY userIdentity.arn` would drop it silently. Fix: actor=coalesce(arn, principalId, "unknown") so a null by-key never drops a row.
- F3 (fidelity): failing input: `near_miss_2_derived.json`: failed DeleteRecoveryPoint (errorCode=AccessDeniedException). Fix: Successful calls only (isnull(errorCode)); failed attempts are a separate, noisier hunt.

## Bypass table
| Attacker variation | Result |
|---|---|
| Let recovery points expire by shortening the lifecycle (UpdateRecoveryPointLifecycle) instead of deleting | MISSED: not in eventName list; no real payload for UpdateRecoveryPointLifecycle |
| Delete the underlying EBS snapshots / RDS snapshots directly | MISSED: other services; out of scope |
| Delete from a different account via cross-account vault access | Caught if the delete is logged in the vault account trail |
| Change the vault access policy to deny restores (PutBackupVaultAccessPolicy) | MISSED: not in scope, no payload |

## False-positive decisions
- Planned retention clean-up of old recovery points by a backup administrator (AWS Backup lifecycle deletes are done by the service; https://docs.aws.amazon.com/aws-backup/latest/devguide/deleting-backups.html)
- Decommissioning a test vault in a sandbox account
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- Only DeleteRecoveryPoint has a real payload (AWS Backup docs). DeleteBackupVault, DeleteBackupVaultLockConfiguration and DeleteBackupPlan are documented API names (API reference links in references) assumed to appear as eventName unchanged; not replayed.
- The vault_or_lock_removed flag is untested for the same reason.
- Whether AWS Backup lifecycle expiry logs DeleteRecoveryPoint with invokedBy is not confirmed by a payload; the filter is based on the service-event shape shown on the same docs page.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0062/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
