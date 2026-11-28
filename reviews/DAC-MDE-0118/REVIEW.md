# REVIEW - DAC-MDE-0118 AWS: stolen-key EC2 foothold cluster

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 14 has an example that counts event kinds per identity and IP; this rule requires a specific combination (key pair plus launch plus address or volume), groups on the role rather than the session, drops service-invoked calls and adds a first-launch baseline. No query text was copied.
- Google Threat Intelligence Group, ARTEX and friends ('Generated a new SSH key pair, allocated a dedicated public Elastic IP, attempted to create a custom security group but failed due to permission issues, and launched persistent t3.micro instances'; 'Created a new 100GB volume'): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence Hunt 14 (foothold part) and the 'Holding access in AWS' row: https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (cross-cloud agentic secret-abuse context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- Sentinel AWSCloudTrail schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail
- EC2 CloudTrail logging (all EC2 API actions logged as management events, names as in the EC2 API Reference): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitor-with-cloudtrail.html
- EC2 API actions (CreateKeyPair, ImportKeyPair, AllocateAddress, AssociateAddress, RunInstances, CreateVolume, AttachVolume, CreateSecurityGroup, AuthorizeSecurityGroupIngress): https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Operations.html
- CloudTrail record contents (userIdentity.invokedBy; sourceIPAddress shows the DNS name for AWS services, 'AWS Internal/#' for AWS-originated events): https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- ATT&CK v19.2: T1578.002 Create Cloud Instance (tactic defense-impairment in v19.2). T1098.004 SSH Authorized Keys was considered and not tagged: its cloud text is about adding keys to an existing VM (metadata or PATCH), not creating a key pair for a new instance.

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H14b was a Gap. No rule on main referenced CreateKeyPair or AllocateAddress.

## After
New defender (Sentinel KQL) rule DAC-MDE-0118 on AWSCloudTrail. Splunk version not built (no attack_data payload with this sequence was found; standing rule).

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Reuse an existing key pair (no CreateKeyPair / ImportKeyPair) | T1578.002 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | high | known gap | Launch + address or volume alone matches routine deploys. |
| Use SSM Session Manager or EC2 Instance Connect instead of an SSH key | T1578.002 | https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Operations.html | yes, other events | unknown | not added | Different APIs; not observed in the GTIG case. |
| Spread the steps across more than an hour | T1578.002 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | medium | known gap | Window trade-off. |
| Use an identity that already launches instances (a compromised deploy role) | T1578.002 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | n/a | known gap | Baseline suppresses it by design. |
| Launch in many regions | T1578.002 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/awscloudtrail | yes | low | covered | Not grouped per region; regions listed. |

## Unverified ideas
- Instance type and volume size from RequestParameters (GTIG: t3.micro, 100 GB) as context columns. Left out because the exact JSON paths inside RequestParameters were not confirmed on an AWS sample page on this pass.
- Chain with DAC-MDE-0112: DryRun burst then foothold for the same actor within a day.
- Whether CreateKeyPair is ever service-invoked in practice.

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0118/ (synthetic, not run). `_phase` marks baseline vs recent rows for the Python mirror.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_gtig_style_foothold | yes | alert | match |
| malicious_import_key_and_volume | yes | alert | match |
| benign_known_terraform_role | no | no alert | match |
| benign_autoscaling_launch | no | no alert | match |
| near_miss_instance_without_key_pair | no | no alert | match |
| near_miss_dryrun_only | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel or Splunk.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | Counting any 3 event kinds (Hunt 14 style) fires on launch + volume + security group in every deploy | RunInstances, CreateVolume, CreateSecurityGroup | Require key pair AND launch AND (address OR volume) |
| 2 | Per-session ARN baseline treats every Terraform run as a new identity | assumed-role/terraform-deployer/tf-run-2 | Actor = SessionIssuerArn first |
| 3 | Dry runs and denials are not a foothold | Client.DryRunOperation on all steps | Successful calls only (`isempty(ErrorCode)`), failures kept for security-group context |
| 4 | Autoscaling and other services launch instances for you | invokedBy autoscaling.amazonaws.com | Drop service-invoked calls |
| 5 | Baseline and live filters defined twice | drift on edit | One `Ec2Calls` function |

## Reviewer status
- pending human approval
