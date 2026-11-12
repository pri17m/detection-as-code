# REVIEW - DAC-AWS-0072 Read-only discovery across three or more AWS services from one principal in 15 minutes

## Attribution
Clean-room behavioural rule from Datadog Security Labs, "On the hunt for ARTEX: understanding agentic attacks in AWS environments" (Julie Agnes Sparks, 9 Nov 2026): https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/. Datadog published no query text; the SPL is our own, written from the article's described events and the AWS CloudTrail docs. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. Partial overlap only: DAC-AWS-0042 flags ListBuckets by unusual principals and DAC-AWS-0019/0020 flag ListSecrets above a count. Neither looks across services.

## After
One actor calling the read-only discovery APIs Datadog listed (ListBuckets, GetBucket*, ListSecrets, DescribeParameters, ListTopics, DescribeLogGroups, GetRestApis, DescribeRepositories, ListFunctions*) across 3+ services and 4+ APIs in a 15-minute bin, success or failure. Sorted by denial ratio.

Thresholds are unmeasured starting points, not tuned on real data. `telemetry_validated: false`.

## ATT&CK v19.2
T1526, T1580 -> discovery. Checked against enterprise-attack-19.2.json from mitre-attack/attack-stix-data (attack-pattern present, not revoked or deprecated; tactics from kill_chain_phases).

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Discovery through `resourcegroupstaggingapi` GetResources or AWS Config instead of per-service lists | MISSED: those APIs aren't in the list | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Sweep split across a 15-minute bin edge | MISSED if neither bin reaches the threshold | https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Bin |
| Two services only (e.g. S3 + Secrets Manager) | MISSED: below 3 services (near_miss_2) | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Legitimate CSPM role | Fires. Allowlist after baselining; denial ratio near 0 helps triage | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |

## Unverified ideas
- Whether `ListFunctions20150331v2` appears in current CloudTrail; kept from the research notes, harmless if absent.
- Thresholds (3 services, 4 APIs, 15 minutes) are unmeasured.
- Raising priority when DAC-AWS-0071 also fires for the actor is a triage step, not part of this query.

## Tests / fixtures
`tests/cases/DAC-AWS-0072/`: all files are synthetic (`"synthetic": true`), built from the behaviour in the Datadog article and the CloudTrail record format. Account IDs are AWS example values and IPs are RFC 5737 documentation ranges; none are indicators. Not run by CI (the repo has no Splunk runner).

Splunk Enterprise 9.4.1 (local tarball on the agent box, throwaway instance). Splunk Add-on for AWS not installed, so `aws:cloudtrail` used `KV_MODE = json` with `TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z` in a local props.conf; field names are the raw CloudTrail JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -sourcetype aws:cloudtrail -index dac`, and the rule query ran unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). The events are synthetic, so this proves the SPL parses and the logic does what the fixture says. It says nothing about real tenant volume.

| Fixture | Label | Expect alert | Rows | Result | Rows with the draft SPL | What it is |
|---|---|---|---|---|---|---|
| benign_3_synthetic.json | benign | False | 0 | PASS | 0 | Deploy role reads one Lambda and one log group listing (2 services, 2 APIs) |
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 1 | Cognito-vended session runs Datadog's discovery list across 8 services, all denied |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | 1 | Stolen long-term key runs 5 discovery calls across 4 services, all succeed |
| malicious_4_synthetic.json | malicious | True | 1 | PASS | 0 | Discovery using bucket reads outside the draft's explicit GetBucket list (GetBucketVersioning, GetBucketCors) |
| near_miss_2_synthetic.json | near_miss | False | 0 | PASS | 0 | 5 APIs but only 2 services (S3 console-style bucket browsing plus ListSecrets) |

## Ponytail findings
Ponytail pass (2026-11-12): correctness, safety, behaviour under load, tests, speed, every line needed. Findings naming a fixture were replayed in local Splunk against the pre-fix draft SPL (our research notes, before this PR); the rest are reasoned.

- F1 (coverage): failing input: `malicious_4_synthetic.json`: ListBuckets, GetBucketVersioning, GetBucketCors, ListSecrets, DescribeParameters, all denied. The draft SPL's explicit GetBucket list didn't include GetBucketVersioning or GetBucketCors, so it saw 3 APIs and returned 0 rows. Fix: Base search uses `GetBucket*`, as Datadog wrote it. Replay: 1 row.
- F2 (null keys): failing input: Reasoned: the draft grouped `BY userIdentity.type`. Fix: `id_type` coalesced before `stats`.
- F3 (order): failing input: Reasoned: `sort - deny_ratio` without a limit truncates at 10,000 rows in Splunk. Fix: `sort 0 - deny_ratio`.

## Reviewer status
pending human review (merge approved by the repo owner in chat, 2026-11-12)
