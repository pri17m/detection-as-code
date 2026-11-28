# REVIEW - DAC-MDE-0112 AWS: EC2 DryRun permission-probe burst

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence published an example hunt (Hunt 14); this rule is written separately: it groups on the role rather than the session ARN, drops service-invoked calls, and requires several distinct dry-run actions. No query text was copied.
- Google Threat Intelligence Group, ARTEX and friends (ARTEX 'tested compromised IAM user permissions using DryRun flags and placeholder IDs to evaluate EC2 compute, EBS volume, and snapshot capabilities'): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence Hunt 14: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (agentic secret abuse context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- Sentinel AWSCloudTrail schema (ErrorCode, EventName, SessionIssuerArn, UserIdentityInvokedBy, SourceIpAddress, etc.): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail
- EC2 API error codes (DryRunOperation: 'The user has the required permissions, so the request would have succeeded, but the DryRun parameter was used'; client errors written with a Client. prefix, for example Client.UnauthorizedOperation): https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
- EC2 CloudTrail logging (all EC2 API actions are logged as management events): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitor-with-cloudtrail.html
- CloudTrail record contents (errorCode, userIdentity.invokedBy, userIdentity.invokedBy names the AWS service for calls made on your behalf; sourceIPAddress shows only the DNS name for AWS services, and 'AWS Internal/#' for events AWS originates): https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- CloudTrail sample with errorCode Client.DryRunOperation, confirmed as expected behaviour by the Karpenter maintainers in AWS's own repo: https://github.com/aws/karpenter-provider-aws/issues/8015
- ATT&CK v19.2: T1580 Cloud Infrastructure Discovery (discovery). https://attack.mitre.org/techniques/T1580/

## errorCode check (the open item from the report)
The report left open whether CloudTrail writes DryRunOperation or Client.DryRunOperation. The EC2 error page names the code DryRunOperation and shows client errors with a Client. prefix; the CloudTrail record in the AWS Karpenter issue shows `"errorCode": "Client.DryRunOperation"`. The rule uses `endswith "DryRunOperation"` so both forms match.

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H14a was a Gap. No rule on main referenced DryRun. DAC-AWS-0071/0072 cover denied discovery bursts across services in Splunk, not EC2 dry runs.

## After
New defender (Sentinel KQL) rule DAC-MDE-0112 on AWSCloudTrail. Splunk version not built: no Splunk attack_data payload with DryRun events was found for this pass, and the standing rule is not to build Splunk logic without a payload.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Key has no EC2 rights at all, so every probe is UnauthorizedOperation (no dry-run success) | T1580 | https://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html | yes | high | known gap | Denials alone also come from normal misconfigured jobs; DAC-AWS-0071/0072 cover denied sweeps. |
| Probe slowly (under 10 calls per 5 minutes) | T1580 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | n/a | known gap | GTIG describes compressed 2-25 s bursts, so the window fits the observed behaviour. |
| Probe non-EC2 services (IAM SimulatePrincipalPolicy, S3) | T1580 / T1526 | https://attack.mitre.org/techniques/T1580/ | yes | unknown | out of scope | Different APIs; DryRun is an EC2 parameter. |
| Spread calls over several regions | T1580 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail | yes | low | covered | Grouping is not per region; regions are listed. |
| Rotate assumed-role session names | T1580 | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html | yes | low | covered | Actor uses SessionIssuerArn first. |

## Unverified ideas
- Whether UnauthorizedOperation responses to a DryRun call can be told apart from a real call's denial in CloudTrail (requestParameters may not keep the dryRun flag). Not relied on.
- Placeholder resource IDs (GTIG) as an extra signal. Not used: values vary and would be string matching.
- Follow-on correlation with DAC-MDE-0118 (foothold cluster) for the same identity.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0112/ (synthetic, not run).

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_dryrun_probe_mixed_allowed_and_denied | yes | alert | match |
| malicious_role_sessions_rotating | yes | alert | match |
| benign_karpenter_periodic_dryrun | no | no alert | match |
| benign_aws_service_invoked_dryrun | no | no alert | match |
| near_miss_denials_without_dryrun | no | no alert | match |
| near_miss_spread_over_30_minutes | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel or Splunk.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Exact match on "DryRunOperation" misses CloudTrail's Client. prefix (and the reverse) | errorCode Client.DryRunOperation | `endswith "DryRunOperation"` |
| 2 | Per-session ARN splits one role's burst into many single-call groups | assumed-role/app-role/sess-0..11 | Actor = SessionIssuerArn first |
| 3 | Service-invoked dry runs (autoscaling, Lambda VPC ENI checks) are not the caller probing | sourceIPAddress autoscaling.amazonaws.com | Drop UserIdentityInvokedBy set, service DNS-name source, or 'AWS Internal' source |
| 4 | Counting denials alone fires on any broken job | 12 UnauthorizedOperation, no dry run | Require 3+ distinct dry-run actions |
| 5 | Karpenter-style controllers dry-run 3 actions repeatedly | CreateFleet / CreateLaunchTemplate / RunInstances x4 | 5-action floor (distinct EventName) |

## Reviewer status
- pending human approval
