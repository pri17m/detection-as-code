# REVIEW - DAC-MDE-0121 Sentinel: Azure blob written then deleted within 2 s by a new caller

## Attribution
Clean-room behavioural rule from public sources opened on 28 Nov 2026 (IST). ThreatDefence Hunt 15 joins writes and deletes on AccountName, ObjectKey and CallerIpAddress; this rule joins on the authenticated caller, strips the port from CallerIpAddress, uses string status codes and adds a per-caller baseline. No query text was copied.
- Google Threat Intelligence Group, ARTEX and Friends ('writing and immediately deleting a tiny test blob in ~330-400 ms'; SAS tokens, service principals, Kudu credentials and storage account keys mapped with sub-second capability checks): https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks
- ThreatDefence Hunt 15 and the 'blob written and deleted within a second' signal ('Normal backup and deployment tools also write and delete test blobs'): https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
- Microsoft 5 Nov 2026 post (ARTEX context): https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-ai-tooling-to-find-and-abuse-exposed-secrets/
- StorageBlobLogs schema (StatusCode is string; CallerIpAddress 'including the port number'; ObjectKey; AuthenticationHash; RequesterObjectId; RequesterAppId): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs
- Blob storage monitoring reference (AuthenticationType values AccountKey, SAS, DelegationSas, OAuth, Anonymous; sample record with callerIpAddress 192.168.0.1:11111): https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference
- Logged operation names PutBlob, PutBlockList, DeleteBlob: https://learn.microsoft.com/en-us/rest/api/storageservices/storage-analytics-logged-operations-and-status-messages
- Put Blob returns 201 (Created): https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob; Delete Blob returns 202 (Accepted): https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob
- ATT&CK v19.2 T1580 Cloud Infrastructure Discovery (discovery): https://attack.mitre.org/techniques/T1580/

## As-is
Gap from the ARTEX coverage report (artex-detection-report, 28 Nov 2026). ThreatDefence H15a was a Gap: no rule on main read StorageBlobLogs.

## After
New defender (Sentinel KQL) rule DAC-MDE-0121. Write (PutBlob/PutBlockList, 200/201) then DeleteBlob (200/202) on the same object by the same caller within 2 s, caller with no such pair on that account in the prior 14 days.

## Bypass research
| bypass | technique | source URL | telemetry OK | noise | decision | reason |
|---|---|---|---|---|---|---|
| Wait more than 2 s before deleting | T1580 | https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks | yes | higher | known gap | Window is from the observed 330-400 ms; a 2 s cap leaves room for latency without catching normal temp files. |
| Write and never delete (or delete much later) | T1580 | https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting | yes | high | out of scope | Not a capability-check signature; volume rules cover bulk writes. |
| Hierarchical-namespace (ADLS Gen2) accounts using DFS path operations | T1580 | https://learn.microsoft.com/en-us/rest/api/storageservices/storage-analytics-logged-operations-and-status-messages | unknown | unknown | known gap | DFS endpoint operation names were not checked on this pass. |
| Delete via a lifecycle policy or a different identity | T1580 | https://learn.microsoft.com/en-us/azure/storage/blobs/monitor-blob-storage-reference | yes | low | not suspicious | Different caller is not a self-test (near-miss fixture). |
| Reuse a caller that is already in the baseline (same key used by a backup tool) | T1580 | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/storagebloblogs | yes | n/a | known gap | AuthenticationHash is per key/SAS; a stolen key that a known tool already uses for write checks is hidden. |
| Probe with container create/delete instead of blobs | T1580 | https://learn.microsoft.com/en-us/rest/api/storageservices/storage-analytics-logged-operations-and-status-messages | yes | unknown | known gap | CreateContainer/DeleteContainer not included. |

## FP check
First-day runs of new backup or sync tools, and developers testing storage code, will alert once and then fall into the baseline. Azure first-party probes were not measured. No tenant data used.

## Unverified ideas
- IPv6 CallerIpAddress format with a port (left unmodified; pairs still join on the authenticated caller).
- Whether StorageBlobLogs StatusCode for DeleteBlob is always '202' or sometimes '200' through some SDKs (both allowed).
- Whether AuthenticationHash is populated for AccountKey requests in every region (assumed from the Learn column description).

## Tests / fixtures
Synthetic fixtures under tests/cases/DAC-MDE-0121/ (synthetic, not run). Mirror 'now' is 2026-11-27T00:00Z.

| Fixture | Expect alert | Python mirror | Result |
|---|---|---|---|
| malicious_account_key_write_delete_350ms | yes | alert | match |
| malicious_sas_probe_across_containers | yes | alert | match |
| malicious_oauth_sp_blocklist_then_delete | yes | alert | match |
| benign_backup_tool_known_from_baseline | no | no alert | match |
| near_miss_delete_after_5s | no | no alert | match |
| near_miss_different_caller_deletes | no | no alert | match |

CI validate: see PR checks. Not run in Sentinel.

## Ponytail findings
| # | Finding | Failing input | Fix |
|---|---|---|---|
| 1 | CallerIpAddress includes the port, so joining on it breaks when the delete uses a new connection | 203.0.113.50:50211 vs :50212 | Port stripped for IPv4; join on authenticated caller instead |
| 2 | StatusCode is a string column; `in (200, 201)` compares to ints | StatusCode "201" | String literals |
| 3 | IP-keyed join merges different identities behind one NAT and splits one identity across egress IPs | two SPs on one NAT IP | Caller = AuthenticationType + object ID / app ID / auth hash |
| 4 | Backup tools that test write access daily would alert every day | known hash in baseline | 14-day per-caller, per-account baseline |
| 5 | A cleanup job deleting another identity's blob looked like a self-test | different RequesterObjectId on delete | Caller must match on both sides |

## Reviewer status
- pending human approval
