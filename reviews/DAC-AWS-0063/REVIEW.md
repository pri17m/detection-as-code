# REVIEW — DAC-AWS-0063 S3 object written or copied with SSE-C customer-provided key

## Coverage before
No SSE-C rule on main: no rule references x-amz-server-side-encryption-customer-algorithm (grep, main cbcc18d). Existing S3 rules cover bucket policy/ACL/versioning, not object encryption with a caller key.

## Coverage after
Behavior: PutObject/CopyObject/CreateMultipartUpload on S3 (or S3 on Outposts) carrying x-amz-server-side-encryption-customer-algorithm, i.e. the caller supplied the encryption key. Codefinger-style ransomware re-encrypts objects with a key the victim never had (T1486). Needs S3 data events. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1486 → impact. Checked against https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json (attack-pattern present, not revoked or deprecated; tactics from its kill_chain_phases).

## Source and fields
- Real payload(s): https://docs.aws.amazon.com/AmazonS3/latest/s3-outposts/S3OutpostsCloudtrail.html; https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json
- Behaviour idea (inspiration only, Elastic License 2.0): https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_s3_unusual_object_encryption_with_sse_c.toml; https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/impact_s3_excessive_object_encryption_with_sse_c.toml. Clean-room: the SPL here was written from the CloudTrail payload fields and AWS API docs; no Elastic query text was read into or copied into this rule.
- Fields used, all confirmed present by `| fieldsummary` on the malicious fixture in local Splunk (absence-checked fields, not present on the malicious event: errorCode): `eventName`, `eventSource`, `recipientAccountId`, `requestParameters.Key`, `requestParameters.bucketName`, `requestParameters.x-amz-server-side-encryption-customer-algorithm`, `sourceIPAddress`, `userAgent`, `userIdentity.arn`, `userIdentity.principalId`, `errorCode`
- Attribution: Stratus Red Team detonation logs are Apache-2.0 (DataDog/stratus-red-team); splunk/attack_data is Apache-2.0; AWS documentation examples are cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR (see PR body).

## Local Splunk replay (telemetry check)
Splunk Enterprise 9.4.1 (free tarball, trial licence) on the agent box. Splunk Add-on for AWS not installed (Splunkbase download needs a login), so `aws:cloudtrail` used `KV_MODE = json` in a local props.conf; field names are the raw CloudTrail JSON paths, which is what the add-on also extracts for this sourcetype. Each fixture was indexed with `splunk add oneshot -sourcetype aws:cloudtrail -index dac` and the rule query was run unchanged via REST (`search index=dac source="*<fixture>" <query>`, earliest=0). Events older than Splunk's MAX_DAYS_AGO were stamped at index time; no rule logic depends on _time spans.

| Fixture | Label | Expect alert | Rows | Result | Payload source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://docs.aws.amazon.com/AmazonS3/latest/s3-outposts/S3OutpostsCloudtrail.html | none (real event) |
| near_miss_1_real.json | near_miss | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1486/s3_file_encryption/aws_cloudtrail_events.json | none (real event) |
| near_miss_2_derived.json | near_miss | False | 0 | PASS | https://docs.aws.amazon.com/AmazonS3/latest/s3-outposts/S3OutpostsCloudtrail.html | SSE-C headers removed (plain SSE-S3 upload) |
| near_miss_3_derived.json | near_miss | False | 0 | PASS | https://docs.aws.amazon.com/AmazonS3/latest/s3-outposts/S3OutpostsCloudtrail.html | errorCode=AccessDenied added |

First alert row (malicious fixture): `{"actor": "arn:aws:iam::111122223333:user/yourUserName", "bucket": "amzn-s3-demo-bucket1", "recipientAccountId": "444455556666", "sse_c_writes": "1", "objects": "1", "actions": "PutObject", "sample_keys": "path/upload.sh", "src_ip": "26.29.66.20", "user_agent": "aws-cli/1.18.39 Python/3.4.10 Darwin/18.7.0 botocore/1.15.39", "first_seen": "1792498057", "last_seen": "1792498057"}`

Cross-check: rule run over a corpus of all 55 splunk/attack_data AWS CloudTrail JSON datasets plus all 35 Stratus Red Team AWS detonation logs (same local index): 0 alert row(s); base-search hits by source: {"corpus_ad_T1486_s3_file_encryption_aws_cloudtrail_events.json": "2"}.

## Ponytail review
Ponytail pass (2026-10-20): correctness, safety, behaviour under load, tests, speed, every line needed. Findings that name a fixture file were replayed in local Splunk against the pre-fix query (rows quoted); the others are reasoned from the payload shape.
- F1 (fidelity): failing input: Real attack_data payload s3_file_encryption (CopyObject with x-amz-server-side-encryption=aws:kms, own KMS key). Anchoring on `x-amz-server-side-encryption` returned 1 alert row on the corpus (KMS re-encryption, not SSE-C). Fix: Anchor only on requestParameters.x-amz-server-side-encryption-customer-algorithm, which is present only when the caller supplies the key. Corpus replay now 0 rows.
- F2 (correctness): failing input: `malicious_0_real.json` (AWS S3 on Outposts docs example) uses `requestParameters.Key` (capital K); attack_data S3 events use `key`. Using only `requestParameters.key` gave objects=0 and empty sample_keys. Fix: object_key=coalesce(key, Key). Replay now objects=1, sample_keys=path/upload.sh.
- F3 (load): failing input: Ransomware writes thousands of objects; one row per event would flood. Fix: stats by actor+bucket with object count and first 10 keys.

## Bypass table
| Attacker variation | Result |
|---|---|
| Client-side encryption then PutObject without SSE headers | MISSED: nothing in CloudTrail distinguishes it; see Stratus aws.impact.s3-ransomware-client-side-encryption |
| Encrypt with an attacker-owned KMS key in another account (SSE-KMS) | MISSED by design; separate behaviour |
| Only management events logged | MISSED: PutObject/CopyObject are data events; needs a data-event trail |
| UploadPart with SSE-C after CreateMultipartUpload | Caught at CreateMultipartUpload (in list); UploadPart not listed |

## False-positive decisions
- Applications that deliberately use SSE-C for their own data (AWS documents SSE-C as a supported option: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerSideEncryptionCustomerKeys.html); baseline by bucket and principal
- No suppression is hard-coded (no account or role allowlist shipped); tune per environment.

## Unverified ideas
- The only real SSE-C payload found is the AWS S3 on Outposts docs example (eventSource s3-outposts.amazonaws.com). A standard s3.amazonaws.com SSE-C CopyObject is shown only as a fragment in https://panther.com/blog/detecting-and-hunting-for-cloud-ransomware-part-1-aws-s3; the AWS Security Blog confirms the field name for S3 data events. s3.amazonaws.com events are assumed to use the same field.
- Customer-algorithm value differs: "Aes256" (Outposts docs) vs "AES256" (Panther fragment); the rule tests presence only, so case does not matter.
- AWS says SSE-C is disabled by default for new buckets from April 2026 (Panther post); volume may drop to near zero.
- telemetry_validated stays false: the replay used public sample events, not this org's live CloudTrail.

## Tests
`tests/cases/DAC-AWS-0063/`: files ending `_real` are verbatim real events; `_derived` are minimal documented edits of a real event (listed in `modification`). Not run by CI (repo has no Splunk runner); results above are from the local Splunk replay.

## Reviewer status: pending human approval
