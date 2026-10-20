# REVIEW — DAC-AWS-0068 VPC flow logs deleted

## Coverage before
No flow-log rule on main: no rule references DeleteFlowLogs (grep, main cbcc18d). DAC-AWS-0061 covers CloudTrail StopLogging/DeleteTrail only.

## Coverage after
Behavior: successful ec2 DeleteFlowLogs. Removing flow logs blinds network forensics before exfiltration or lateral movement (T1685.002). One row per actor with deleted flow log IDs. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1685.002 → defense-impairment. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.defense-evasion.vpc-remove-flow-logs.json; https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_ec2_flow_log_deletion.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `awsRegion`, `eventName`, `eventSource`, `recipientAccountId`, `requestParameters.DeleteFlowLogsRequest.FlowLogId.content`, `responseElements.DeleteFlowLogsResponse.unsuccessful`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.defense-evasion.vpc-remove-flow-logs.json | none (real event) |
| benign_1_real.json | benign | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/aws_security_scanner/aws_security_scanner.json | none (real event) |
| near_miss_2_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.defense-evasion.vpc-remove-flow-logs.json | errorCode=Client.UnauthorizedOperation added, responseElements removed |

First alert row (malicious fixture): `{"actor": "arn:aws:iam::498376118699:user/christophe", "recipientAccountId": "498376118699", "awsRegion": "megov-south-1r", "calls": "1", "flow_logs": "1", "flow_log_ids": "fl-0e17aa62a21d4bbfe", "unsuccessful": "", "src_ip": "206.90.1.223", "user_agent": "stratus-red-team_5d25952b-37cb-46cc-a135-3407cbbca7bf", "first_seen": "1722418669", "last_seen": "1722418669"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 1 alert row(s); base-search hits by source: {"corpus_sr_aws.defense-evasion.vpc-remove-flow-logs.json": "1"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (fidelity): failing input: `near_miss_2_derived.json`: DeleteFlowLogs with errorCode=Client.UnauthorizedOperation. Without the errorCode filter the replay returned 1 row. Fix: Successful calls only. 0 rows.
- F2 (correctness): failing input: The real Stratus event nests the ID as requestParameters.DeleteFlowLogsRequest.FlowLogId.content (single ID). A multi-ID call would be an array. Fix: flow_log_ids=mvappend(FlowLogId.content, FlowLogId{}.content). The array path is unverified (no payload).
- F3 (triage): failing input: responseElements.DeleteFlowLogsResponse.unsuccessful is "" in the payload. Fix: Shown as a column, not filtered, because the failure shape is unknown.

## Bypass table
| Attacker variation | Result |
|---|---|
| Change the flow log destination or filter instead of deleting | MISSED: no payload for those calls |
| Delete the CloudWatch log group / S3 bucket that receives flow logs | MISSED here; DeleteLogGroup is a separate rule topic |
| Delete the whole VPC | MISSED: flow logs go with it |

## False-positive decisions
- Infrastructure-as-code teardown of a VPC or replacement of a flow log destination
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- Multi-ID FlowLogId{} array path not seen in a payload.
- What `unsuccessful` contains on partial failure is not shown in any payload.
- PutBucketLogging (disable S3 access logging) was in the request but has no real payload; not built.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0068/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
