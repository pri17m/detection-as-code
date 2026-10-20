# REVIEW — DAC-AWS-0065 IAM Roles Anywhere trust anchor or profile created

## Coverage before
No IAM Roles Anywhere rule on main: no rule references rolesanywhere.amazonaws.com (grep, main cbcc18d).

## Coverage after
Behavior: CreateTrustAnchor and/or CreateProfile on rolesanywhere.amazonaws.com. A trust anchor backed by an attacker CA plus a profile mapping to a role lets the attacker mint AWS credentials from their own X.509 certificate, outliving key rotation (T1098, T1484.002). Rows with both calls by one actor sort first. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1098; T1484.002 → persistence, privilege-escalation, defense-impairment. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.rolesanywhere-create-trust-anchor.json
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_roles_anywhere_trusted_anchor_created_with_external_ca.toml; https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_iam_roles_anywhere_profile_created.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `awsRegion`, `eventName`, `eventSource`, `recipientAccountId`, `requestParameters.name`, `requestParameters.roleArns{}`, `requestParameters.source.sourceType`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.rolesanywhere-create-trust-anchor.json | none (real event) |
| near_miss_1_derived.json | near_miss | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.rolesanywhere-create-trust-anchor.json | errorCode=AccessDeniedException added to both events |
| benign_2_derived.json | benign | False | 0 | PASS | https://github.com/DataDog/stratus-red-team/blob/592c425f1707d11dfda8cf16fe7027f159dfa172/docs/detonation-logs/aws.persistence.rolesanywhere-create-trust-anchor.json | CreateTrustAnchor event renamed to ListTrustAnchors, request/response removed, readOnly=true |

First alert row (malicious fixture): `{"actor": "arn:aws:iam::791182566784:user/christophe", "recipientAccountId": "791182566784", "awsRegion": "cn-northsouth-3r", "actions": ["CreateProfile", "CreateTrustAnchor"], "trust_anchors": "malicious-rolesanywhere-trust-anchor", "anchor_source_types": "CERTIFICATE_BUNDLE", "profiles": "malicious-rolesanywhere-profile", "profile_roles": "arn:aws:iam::791182566784:role/stratus-red-team-trust-anchor-role", "src_ip": "221.252.237.0", "user_agent": "stratus-red-team_e2e652c1-ed4b-4402-b3b0-136ef4c9ace7", "first_seen": "1722500799", "last_seen": "1722500799", "anchor_and_profile": "1"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 1 alert row(s); base-search hits by source: {"corpus_sr_aws.persistence.rolesanywhere-create-trust-anchor.json": "2"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (triage): failing input: `malicious_0_real.json` (Stratus detonation: CreateTrustAnchor then CreateProfile). A per-event table gave 2 unrelated rows. Fix: stats by actor; anchor_and_profile=1 when both calls appear and those rows sort first. Replay: 1 row, anchor_and_profile=1.
- F2 (fidelity): failing input: `near_miss_1_derived.json`: both events with errorCode. Fix: Successful calls only.
- F3 (correctness): failing input: profile_roles comes from requestParameters.roleArns{} (array); confirmed extracted as `requestParameters.roleArns{}` by fieldsummary. Fix: Use the {} path, not roleArns.

## Bypass table
| Attacker variation | Result |
|---|---|
| Reuse an existing trust anchor and only create a profile | Caught (CreateProfile alone still alerts, anchor_and_profile=0) |
| UpdateTrustAnchor to swap the CA on an existing anchor | MISSED: no payload for UpdateTrustAnchor, not built |
| Add a new role to an existing profile (UpdateProfile) | MISSED: no payload |

## False-positive decisions
- On-premises workloads onboarded to Roles Anywhere by the platform team using the corporate private CA; allowlist the trust anchor source/CA
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- Elastic narrows to trust anchors with an external CA (sourceType CERTIFICATE_BUNDLE vs AWS_ACM_PCA). Only CERTIFICATE_BUNDLE is in the payload, so the rule shows anchor_source_types but does not filter on it.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0065/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
