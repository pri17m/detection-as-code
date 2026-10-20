# REVIEW — DAC-AWS-0069 EC2 serial console access enabled for the account

## Coverage before
Partial overlap on main: DAC-AWS-0022 matches ec2-instance-connect SendSSHPublicKey/SendSerialConsoleSSHPublicKey and, through its unscoped `OR eventName="*Serial*"`, any event with Serial in the name (so EnableSerialConsoleAccess, but also DisableSerialConsoleAccess and GetSerialConsoleAccessStatus). It has no success filter and no correlation. This rule is the scoped, behavioural version: account-level enable as the alert, key pushes joined as context. DAC-AWS-0022 is left as is (no delete); reviewer may want it tagged needs-review.

## Coverage after
Behavior: EnableSerialConsoleAccess (account-level opt-in) on ec2.amazonaws.com; SendSerialConsoleSSHPublicKey calls by the same actor are joined to show follow-on instance access. Serial console bypasses security groups and network controls (T1578.005, T1021.008). Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1578.005; T1021.008 → defense-impairment, lateral-movement. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_ec2_serial_console_access_enabled.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `awsRegion`, `eventName`, `eventSource`, `recipientAccountId`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json | none (real event) |
| malicious_1_real.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json | none (real event) |
| near_miss_2_real.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json | none (real event) |
| benign_3_derived.json | benign | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json | eventName set to DisableSerialConsoleAccess, request renamed, responseElements removed |
| near_miss_4_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json | errorCode added, responseElements removed |

First alert row (malicious fixture): `{"actor": "arn:aws:sts::844015365555:assumed-role/AWSReservedSSOrandoml3I7nL6f7BmB@gmail.com", "recipientAccountId": "844015365555", "awsRegion": "cniso-east-3r", "instances_keyed": "0", "src_ip": "201.252.42.03", "user_agent": "stratus-red-team_b0fedc91-bd4a-4ba1-a776-80e707fef2a0", "first_seen": "1732615522", "last_seen": "1732615522", "key_pushed_after_enable": "0"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 1 alert row(s); base-search hits by source: {"corpus_sr_aws.lateral-movement.ec2-serial-console-send-ssh-public-key.json": "4"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (fidelity): failing input: `near_miss_2_real.json`: SendSerialConsoleSSHPublicKey events without the account-level enable in the window. Without `where console_enabled=1` the replay returned 1 row. Fix: Alert only when the enable is present; key pushes are context. 0 rows.
- F2 (triage): failing input: `malicious_1_real.json`: the full Stratus chain (enable + 3 key pushes). Fix: Join pushes by actor; instances_keyed=3, key_pushed_after_enable=1, sorted first.
- F3 (fidelity): failing input: `benign_3_derived.json`: DisableSerialConsoleAccess (derived). Fix: Event not in scope. 0 rows.

## Bypass table
| Attacker variation | Result |
|---|---|
| Serial console already enabled in the account | MISSED: no enable event; SendSerialConsoleSSHPublicKey alone is not alerted (F1) |
| Different principal pushes the key | The enable row alerts; the push is not joined (join is by actor) |

## False-positive decisions
- Operations team enabling the serial console to troubleshoot an unbootable instance (documented use: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html)
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- A real benign enable by an operator was not available; FP volume not measured.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0069/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
