# REVIEW — DAC-AWS-0064 EC2 AMI launch permission granted to another AWS account or to all

## Coverage before
No AMI-sharing rule on main: no rule references ModifyImageAttribute (grep, main cbcc18d). Snapshot sharing may be covered elsewhere; AMI launch permissions are not.

## Coverage after
Behavior: ModifyImageAttribute adds a launchPermission for a foreign 12-digit account or group "all" (public). An attacker shares an AMI built from a victim instance to their own account to copy disk contents (T1537). Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1537 → exfiltration. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.exfiltration.ec2-share-ami.json; https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_ami_shared_public/aws_cloudtrail_events.json
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/exfiltration_ec2_ami_shared_with_separate_account.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `awsRegion`, `eventName`, `eventSource`, `recipientAccountId`, `requestParameters.imageId`, `requestParameters.launchPermission.add.items{}.group`, `requestParameters.launchPermission.add.items{}.userId`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 2 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1537/aws_ami_shared_public/aws_cloudtrail_events.json | none (real event) |
| malicious_1_real.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.exfiltration.ec2-share-ami.json | none (real event) |
| benign_2_derived.json | benign | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.exfiltration.ec2-share-ami.json | launchPermission.add renamed to launchPermission.remove (share revoked) |
| near_miss_3_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.exfiltration.ec2-share-ami.json | requestParameters replaced by a description-attribute change (no launchPermission) |
| near_miss_4_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.exfiltration.ec2-share-ami.json | launchPermission userId set to the recipientAccountId (own account) |

First alert row (malicious fixture): `{"_time": "2023-03-23 21:45:16.000 IST", "actor": "arn:aws:sts::111111111111:assumed-role/AWSReservedSSO_SPLKAdministratorAccess_d9ce1347d0a6dd3f/bonobo@bo.com", "recipientAccountId": "111111111111", "awsRegion": "us-west-2", "image_id": "ami-0a2011b9052129617", "public": "1", "sourceIPAddress": "72.135.245.10", "userAgent": "AWS Internal"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 3 alert row(s); base-search hits by source: {"corpus_ad_T1537_aws_ami_shared_public_aws_cloudtrail_events.json": "2", "corpus_sr_aws.exfiltration.ec2-share-ami.json": "1"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (correctness): failing input: attack_data aws_ami_shared_public event 2 (launchPermission add group=all). Reading only items{}.userId returned 1 row of 2: the public share was missed. Fix: shared_to=mvappend(userId, group); public=1 when group=all. Replay now 2 rows.
- F2 (fidelity): failing input: `near_miss_4_derived.json`: userId equal to recipientAccountId. Without the own-account check it alerted with foreign_accounts=own account. Fix: mvmap keeps only 12-digit IDs that differ from recipientAccountId. Replay now 0 rows.
- F3 (fidelity): failing input: `benign_2_derived.json`: launchPermission.remove (share revoked). Fix: Only add.items are read, so removals never alert.

## Bypass table
| Attacker variation | Result |
|---|---|
| Share to an AWS Organization or OU (organizationArn / organizationalUnitArn in launchPermission) | MISSED: no payload with those fields, so not built |
| Share the underlying EBS snapshot instead (ModifySnapshotAttribute) | MISSED: different event |
| Copy AMI to another region first, then share | Caught at the share step |

## False-positive decisions
- Golden-image pipelines that share AMIs with member accounts; allowlist the known account IDs
- Marketplace or public AMI publishing
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- Organization/OU sharing field names not seen in any payload.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0064/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
