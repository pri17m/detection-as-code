# ProcessRollup family — field deep dive
**Corpus:** [ByteRay-Labs/Query-Hub](https://github.com/ByteRay-Labs/Query-Hub) (`/workspace/Query-Hub`)
**LogScale note:** filter with tagged `#event_simpleName=ProcessRollup2` (hash required for tags).


## Authoritative ProcessRollup2 fields (FDR / Events Data Dictionary via public schema mirrors)

Sources: CrowdStrike Events Data Dictionary (tenant docs); mirrored in [Panther FDR ProcessRollup2 schema](https://docs.panther.com/data-onboarding/supported-logs/crowdstrike/falcon-data-replicator). Cross-checked against Query-Hub usage.

### Process identity & lineage
| Field | Valid on | Notes |
| --- | --- | --- |
| `TargetProcessId` | PR2, SPR2 | UPID of the process represented by this rollup (primary join target for behaviors) |
| `TargetProcessId_decimal` | PR2 (exports) | Decimal form; LogScale corpus usually uses hex/string `TargetProcessId` |
| `ParentProcessId` | PR2, SPR2 | Parent UPID |
| `SourceProcessId` | PR2, SPR2 | Creating process UPID (can differ from ParentProcessId in edge cases) |
| `SourceThreadId` | PR2, SPR2 | Creating thread |
| `RawProcessId` | PR2, SPR2 | OS PID — join SPR2 parent enrichment on `[aid, RawProcessId]` |
| `ContextProcessId` | **Not primary on PR2** | On DnsRequest/NetworkConnect/etc. — maps **to** PR2 `TargetProcessId` |

### Image / command
| Field | Valid on | Notes |
| --- | --- | --- |
| `ImageFileName` | PR2, SPR2 | Full path to executable |
| `CommandLine` | PR2, SPR2 | May be empty |
| `OriginalCommandLine` | PR2 (Win) | When present |
| `BaseFileName` | PR2 (Win) | Base name |
| `ParentBaseFileName` | PR2 | Parent base name (Mac/Win) |
| `FileName` / `FilePath` | often derived | Query-Hub often regexes these from `ImageFileName` |

### Hashes / timing
| Field | Valid on | Notes |
| --- | --- | --- |
| `SHA256HashData` | PR2, SPR2 | Image hash |
| `MD5HashData` | PR2, SPR2 | |
| `SHA1HashData` | PR2, SPR2 | |
| `ProcessStartTime` | PR2, SPR2 | |
| `ProcessEndTime` | PR2, SPR2 | |

### User / session (Windows-heavy)
| Field | Valid on | Notes |
| --- | --- | --- |
| `UserSid` | PR2, SPR2 | |
| `UserName` | PR2 | Also via join to `UserIdentity` on `AuthenticationId` |
| `AuthenticationId` | PR2, SPR2 | Logon session LUID |
| `ParentAuthenticationId` | PR2 (Win) | |
| `IntegrityLevel` | PR2, SPR2 (Win) | |
| `SessionId` / `TokenType` | PR2 (Win) | |

### Flags / extras
| Field | Valid on | Notes |
| --- | --- | --- |
| `ProcessCreateFlags` / `ProcessParameterFlags` / `ProcessSxsFlags` | PR2 (Win) | Bitfields |
| `ImageSubsystem` | PR2, SPR2 (Win) | |
| `SyntheticPR2Flags` | **SPR2 only** | PROCESS_RUNDOWN, HOLLOWED, etc. |
| `SignInfoFlags` | PR2 (corpus) | Code-signing bitmask — confirm in tenant |
| `IsChild` | PR2 (corpus) | Parent/child rollup patterns in Query-Hub |
| `Tags` | PR2 | Process tags CSV |
| `UID`/`GID`/… | PR2/SPR2 Mac/Linux | POSIX ids |

### Related ESNs (not ProcessRollup2 itself)
| EventSimpleName | Role |
| --- | --- |
| `ProcessRollup2Stats` | Mac/Linux aggregation follow-on (SHA256 + counts) — **not** in Query-Hub top set |
| `SyntheticProcessRollup2` | Synthetic/rundown PR2 for enrichment joins |
| `ProcessRollup` (v1) | **Absent** from Query-Hub — do not author new rules on it |

### Join cheat-sheet
```
#event_simpleName=ProcessRollup2
| join({#event_simpleName=UserIdentity}, field=AuthenticationId, include=[UserName])

#event_simpleName=ProcessRollup2
| join({#event_simpleName=SyntheticProcessRollup2}, field=[aid, RawProcessId], include=[SHA256HashData], suffix=Parent)

# behavior event (e.g. NetworkConnectIP4) ContextProcessId  ==  ProcessRollup2 TargetProcessId  (plus aid)
```

---

## Names in corpus
| EventSimpleName | Query-Hub hits (clause-level) |
| --- | ---: |
| `ProcessRollup2` | 106 |
| `SyntheticProcessRollup2` | 19 |

**Not observed in Query-Hub:** plain `ProcessRollup` (v1). Prefer `ProcessRollup2`. `SyntheticProcessRollup2` used for synthetic/parent enrichment joins.

## Core fields valid on ProcessRollup2 (validated)
| Field | Notes |
| --- | --- |
| `aid` | agent id — join key across events · *docs/community (confirm in tenant)* |
| `cid` | customer id (tagged #cid in LogScale) · *docs/community (confirm in tenant)* |
| `ComputerName` | hostname · *Query-Hub (n=49)* |
| `event_platform` | Win/Mac/Lin · *Query-Hub (n=46)* |
| `aip` | agent IP (when present) · *docs/community (confirm in tenant)* |
| `TargetProcessId` | Falcon process id (string); often join key; also TargetProcessId_decimal in some APIs · *Query-Hub (n=14)* |
| `RawProcessId` | OS PID; join parent SyntheticProcessRollup2 on [aid, RawProcessId] · *Query-Hub (n=5)* |
| `ParentProcessId` | parent Falcon process id · *Query-Hub (n=7)* |
| `ContextProcessId` | context/parent linkage used in network joins · *Query-Hub (n=8)* |
| `SourceProcessId` | seen on some related events; verify before use on ProcessRollup2 · *docs/community (confirm in tenant)* |
| `ImageFileName` | full image path · *Query-Hub (n=67)* |
| `FileName` | base name (sometimes derived via regex from ImageFileName) · *Query-Hub (n=41)* |
| `FilePath` | directory path · *Query-Hub (n=3)* |
| `CommandLine` | process command line · *Query-Hub (n=62)* |
| `OriginalFilename` | PE version resource original filename (when present) · *Query-Hub (n=7)* |
| `ParentBaseFileName` | parent base filename · *Query-Hub (n=29)* |
| `ParentImageFileName` | parent image path (when present on event) · *Query-Hub (n=2)* |
| `GrandParentBaseFileName` | grandparent base name (when enriched/present) · *Query-Hub (n=3)* |
| `SHA256HashData` | SHA256 of image · *Query-Hub (n=8)* |
| `MD5HashData` | MD5 of image · *Query-Hub (n=2)* |
| `SHA1HashData` | SHA1 when present · *docs/community (confirm in tenant)* |
| `SignInfoFlags` | code-signing bitmask · *Query-Hub (n=2)* |
| `UserName` | username (sometimes via UserIdentity join on AuthenticationId) · *Query-Hub (n=32)* |
| `UserSid` | SID · *Query-Hub (n=6)* |
| `AuthenticationId` | logon session id — join to UserIdentity · *Query-Hub (n=1)* |
| `AuthenticationID` | alias casing variant seen in queries — prefer AuthenticationId after fieldsummary · *Query-Hub (n=3)* |
| `IsChild` | 0/1 child flag used in parent/child rollup patterns · *Query-Hub (n=2)* |
| `IntegrityLevel` | integrity level when present — confirm in tenant · *docs/community (confirm in tenant)* |
| `ProcessCreateFlags` | create flags when present — confirm in tenant · *docs/community (confirm in tenant)* |

### Additional fields frequently co-filtered on ProcessRollup2 clauses in Query-Hub
| Field | Clause hits | Caution |
| --- | ---: | --- |
| `RemoteAddressIP4` | 8 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `ProcessStartTime` | 7 | Observed in ProcessRollup2 clauses — validate |
| `event_simpleName` | 6 | Observed in ProcessRollup2 clauses — validate |
| `RemotePort` | 6 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `LastSeen` | 6 | Observed in ProcessRollup2 clauses — validate |
| `TargetFileName` | 5 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `DecodedString` | 4 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `EncodedString` | 4 | Observed in ProcessRollup2 clauses — validate |
| `SubEncodedString` | 4 | Observed in ProcessRollup2 clauses — validate |
| `CmdLinePrefix` | 4 | Observed in ProcessRollup2 clauses — validate |
| `SubCmdLinePrefix` | 4 | Observed in ProcessRollup2 clauses — validate |
| `SubDecodedString` | 4 | Observed in ProcessRollup2 clauses — validate |
| `ParentCommandLine` | 4 | Observed in ProcessRollup2 clauses — validate |
| `RegObjectName` | 4 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `SignalType` | 4 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `FirstSeen` | 4 | Observed in ProcessRollup2 clauses — validate |
| `ChildProcess` | 3 | Observed in ProcessRollup2 clauses — validate |
| `TargetImageFileName` | 3 | Observed in ProcessRollup2 clauses — validate |
| `Confidence` | 3 | Observed in ProcessRollup2 clauses — validate |
| `DllLoaded` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ContextBaseFileName` | 2 | Observed in ProcessRollup2 clauses — validate |
| `customer_tok` | 2 | Observed in ProcessRollup2 clauses — validate |
| `aid_tok` | 2 | Observed in ProcessRollup2 clauses — validate |
| `Urlink` | 2 | Observed in ProcessRollup2 clauses — validate |
| `raw_pid` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ProcessExplorer` | 2 | Observed in ProcessRollup2 clauses — validate |
| `GraphExplorer` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ContextId` | 2 | Observed in ProcessRollup2 clauses — validate |
| `MD5` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ChildCLI` | 2 | Observed in ProcessRollup2 clauses — validate |
| `DataSet` | 2 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `CommandLength` | 2 | Observed in ProcessRollup2 clauses — validate |
| `PercentIncrease` | 2 | Observed in ProcessRollup2 clauses — validate |
| `HtaPath` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ProcId` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ParentSHA256HashData` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ChildCommandLine` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ParentFileName` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ParentFilePath` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ShortFile` | 2 | Observed in ProcessRollup2 clauses — validate |
| `LastCommandRun` | 2 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `Status` | 2 | Observed in ProcessRollup2 clauses — validate |
| `MajorVersion` | 2 | Observed in ProcessRollup2 clauses — validate |
| `MinorVersion` | 2 | Observed in ProcessRollup2 clauses — validate |
| `BuildNumber` | 2 | Observed in ProcessRollup2 clauses — validate |
| `LocalAddressIP4` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ProductName` | 2 | Observed in ProcessRollup2 clauses — validate |
| `RegStringValue` | 2 | Observed in ProcessRollup2 clauses — validate |
| `SuspectActivity` | 2 | Observed in ProcessRollup2 clauses — validate |
| `hunt_hypothesis` | 2 | Observed in ProcessRollup2 clauses — validate |
| `ScriptContent` | 2 | Likely from JOINED event — do not assume on ProcessRollup2 alone |
| `Curl_CMD` | 2 | Observed in ProcessRollup2 clauses — validate |
| `Tree` | 2 | Observed in ProcessRollup2 clauses — validate |
| `CommandTimestampMs` | 2 | Observed in ProcessRollup2 clauses — validate |
| `CmdLower` | 2 | Observed in ProcessRollup2 clauses — validate |
| `Hypothesis` | 2 | Observed in ProcessRollup2 clauses — validate |
| `Priority` | 2 | Observed in ProcessRollup2 clauses — validate |
| `UserID` | 2 | Observed in ProcessRollup2 clauses — validate |
| `RegNumericValue` | 2 | Likely from JOINED event — do not assume on ProcessRollup2 alone |

## SyntheticProcessRollup2
Used mainly as **join enrichment** (parent hash / parent image), not as primary process-create stream.

| Field | Clause hits | Notes |
| --- | ---: | --- |
| `CommandLine` | 13 | Often via `join(..., include=[...])` |
| `FileName` | 12 | Often via `join(..., include=[...])` |
| `ImageFileName` | 11 | Often via `join(..., include=[...])` |
| `ComputerName` | 10 | Often via `join(..., include=[...])` |
| `UserName` | 9 | Often via `join(..., include=[...])` |
| `ParentBaseFileName` | 6 | Often via `join(..., include=[...])` |
| `RawProcessId` | 3 | Often via `join(..., include=[...])` |
| `SHA256HashData` | 3 | Often via `join(..., include=[...])` |
| `TargetProcessId` | 2 | Often via `join(..., include=[...])` |
| `Urlink` | 2 | Often via `join(..., include=[...])` |
| `GrandParentBaseFileName` | 2 | Often via `join(..., include=[...])` |
| `raw_pid` | 2 | Often via `join(..., include=[...])` |
| `ProcessExplorer` | 2 | Often via `join(..., include=[...])` |
| `ProcessStartTime` | 2 | Often via `join(..., include=[...])` |
| `GraphExplorer` | 2 | Often via `join(..., include=[...])` |
| `ParentProcessId` | 2 | Often via `join(..., include=[...])` |
| `ContextId` | 2 | Often via `join(..., include=[...])` |
| `ContextProcessId` | 2 | Often via `join(..., include=[...])` |
| `event_platform` | 2 | Often via `join(..., include=[...])` |
| `ParentCommandLine` | 2 | Often via `join(..., include=[...])` |
| `TargetFileName` | 2 | Often via `join(..., include=[...])` |
| `RegNumericValue` | 2 | Often via `join(..., include=[...])` |
| `RemoteAddressIP4` | 2 | Often via `join(..., include=[...])` |
| `MD5HashData` | 2 | Often via `join(..., include=[...])` |
| `HuntLogic` | 2 | Often via `join(..., include=[...])` |
| `HuntObject` | 2 | Often via `join(..., include=[...])` |
| `RegValueName` | 2 | Often via `join(..., include=[...])` |
| `SeverityTier` | 2 | Often via `join(..., include=[...])` |
| `OriginalFilename` | 2 | Often via `join(..., include=[...])` |
| `RegObjectName` | 2 | Often via `join(..., include=[...])` |
| `FirstSeen_epoch` | 2 | Often via `join(..., include=[...])` |
| `LastSeen` | 2 | Often via `join(..., include=[...])` |
| `RMMTool` | 2 | Often via `join(..., include=[...])` |
| `FirstSeen` | 2 | Often via `join(..., include=[...])` |
| `ParentImageFileName` | 1 | Often via `join(..., include=[...])` |
| `AuthenticationID` | 1 | Often via `join(..., include=[...])` |

## Join / lookup patterns (ProcessRollup family)
| Pattern | Keys | Purpose |
| --- | --- | --- |
| ProcessRollup2 → UserIdentity | `AuthenticationId` / `AuthenticationID` | Resolve `UserName` |
| ProcessRollup2 → SyntheticProcessRollup2 | `[aid, RawProcessId]` | Parent `SHA256HashData` |
| ProcessRollup2 → ProcessRollup2 (parent/child) | `ParentProcessId` ↔ `TargetProcessId` | Child process correlation |
| ProcessRollup2 → NetworkConnectIP4/IP6 | `aid` + `TargetProcessId` / `ContextProcessId` / `falconPID` | Attribute network to process |
| ProcessRollup2 → DnsRequest | `aid` + `falconPID` / process id | DNS from process |

## Rule-author guidance
1. Always start with `#event_simpleName=ProcessRollup2` (add `event_platform=Win` when Windows-only).
2. Prefer native fields listed as core above; treat join-sourced fields as requiring an explicit join.
3. Do not use legacy `ProcessRollup` unless tenant still emits it (absent from Query-Hub).
4. Confirm decimal id variants (`TargetProcessId_decimal`) in your Falcon/API export — LogScale queries in this corpus use `TargetProcessId`.
