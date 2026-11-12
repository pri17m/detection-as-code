# REVIEW - DAC-AWS-0073 Anonymous S3 reads with placeholder object keys or an anonymous read burst

## Attribution
Clean-room behavioural rule from Datadog Security Labs, "On the hunt for ARTEX: understanding agentic attacks in AWS environments" (Julie Agnes Sparks, 9 Nov 2026): https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/. Datadog published no query text; the SPL is our own, written from the article's described events and the AWS CloudTrail docs. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. Nothing on `main` (bb44f2ab) looks at anonymous (`userIdentity.accountId=anonymous`) S3 data events.

## After
Anonymous GetObject / ListObjects / ListObjectsV2 / HeadObject / HeadBucket per bucket in 30-minute bins. Alerts on any not-found probe key (nonexist, notexist, zzz_ / zzz-) or on 20+ anonymous reads. Needs S3 data events.

Thresholds are unmeasured starting points, not tuned on real data. `telemetry_validated: false`.

## ATT&CK v19.2
T1530, T1619 -> collection, discovery. Checked against enterprise-attack-19.2.json from mitre-attack/attack-stix-data (attack-pattern present, not revoked or deprecated; tactics from kill_chain_phases).

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Placeholder key with a new naming scheme (e.g. `missing-404-check`) | MISSED by the placeholder branch; the 20-read branch may still fire | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |
| Probe via CloudFront or website endpoint instead of the S3 REST API | Depends on OAC: OAC requests log as AWSService/cloudfront, not anonymous | https://awsteele.com/blog/2025/02/10/cloudfront-triggered-s3-data-event-formats.html |
| Trail without S3 data events | No events, no alert | https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html |
| Fewer than 20 guesses and no placeholder | MISSED (near_miss_2 shape) | https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/ |

## Unverified ideas
- Whether S3 data events for anonymous `NoSuchKey` failures always carry `requestParameters.key`; the replay used synthetic events.
- The 20-read and 30-minute thresholds are unmeasured. On public website buckets the burst branch will be noisy.
- The placeholder regex is wider than Datadog's two examples (F1); FP rate unknown.

## Tests / fixtures
`tests/cases/DAC-AWS-0073/`: all files are synthetic (`"synthetic": true`), built from the behaviour in the Datadog article and the CloudTrail record format. Account IDs are AWS example values and IPs are RFC 5737 documentation ranges; none are indicators. Not run by CI (the repo has no Splunk runner).

Splunk Enterprise 9.4.1 (local tarball on the agent box, throwaway instance). Splunk Add-on for AWS not installed, so `aws:cloudtrail` used `KV_MODE = json` with `TIME_FORMAT = %Y-%m-%dT%H:%M:%S%Z` in a local props.conf; field names are the raw CloudTrail JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -sourcetype aws:cloudtrail -index dac`, and the rule query ran unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). The events are synthetic, so this proves the SPL parses and the logic does what the fixture says. It says nothing about real tenant volume.

| Fixture | Label | Expect alert | Rows | Result | Rows with the draft SPL | What it is |
|---|---|---|---|---|---|---|
| benign_3_synthetic.json | benign | False | 0 | PASS | 0 | Authenticated IAM user reads a key named zzz_nonexistent_abc.txt (not anonymous) |
| malicious_0_synthetic.json | malicious | True | 1 | PASS | 1 | Anonymous placeholder probes (zzz_nonexistent_abc.txt, Notexist-xyz) then config guesses on an app bucket |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | 1 | Anonymous read burst of 22 guessed keys on one bucket, no placeholder key |
| malicious_4_synthetic.json | malicious | True | 1 | PASS | 0 | Anonymous placeholder probes with new names (zzz_probe_404.html, notexist_q1.txt) then 3 guesses |
| near_miss_2_synthetic.json | near_miss | False | 0 | PASS | 0 | Five anonymous reads of real website assets (normal public bucket traffic) |

## Ponytail findings
Ponytail pass (2026-11-12): correctness, safety, behaviour under load, tests, speed, every line needed. Findings naming a fixture were replayed in local Splunk against the pre-fix draft SPL (our research notes, before this PR); the rest are reasoned.

- F1 (coverage): failing input: `malicious_4_synthetic.json`: anonymous probes for `zzz_probe_404.html` and `notexist_q1.txt`, then 3 guesses. The draft regex only listed the exact Datadog/Wiz strings (`zzz_nonexistent`, `notexist-xyz`, ...), so it returned 0 rows. Fix: Regex `(?i)(nonexist|notexist|zzz[_-])`. Replay: 1 row. Datadog says the playbook varies by model, so the exact strings will drift.
- F2 (null keys): failing input: Reasoned: the draft grouped `BY requestParameters.bucketName` and used only `requestParameters.key`; ListObjects carries `prefix`, not `key`. Fix: `bucket` coalesced; `obj=coalesce(key, prefix, "")`.
- F3 (output size): failing input: `malicious_1_synthetic.json`: 22 keys in `sample_keys`. Fix: `mvindex(sample_keys,0,19)` caps the list.

## Reviewer status
pending human review (merge approved by the repo owner in chat, 2026-11-12)
