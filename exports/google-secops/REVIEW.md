# Google SecOps (YARA-L 2.0) conversion review

Date: 2026-11-17. Converter: RuleBridge 0.1.0 (commit `2ad2aaa`, branch `feat/v1-mvp` of `pri17m/rulebridge`). Source: `main` of this repo at `9a7a7d9`.

## How rules were picked

Every rule in `detections/**` (901 rules: 655 SPL, 167 CQL, 79 KQL) was converted to YARA-L 2.0. A rule became a **candidate** only if all of this held:

- RuleBridge graded it `exact`, or `approximate` where every caveat is low-risk. Low-risk means only these: the match window defaulted to 1h because SPL `stats` has no window (`window-default`), a tumbling `bin` became a sliding `over` window (`window-sliding`), or a coalesced group-by field uses the first alias (`groupby-coalesce`). Any medium or low confidence field mapping, unmapped field, passthrough field or substring-for-term change disqualified the rule.
- The round-trip check agreed. RuleBridge builds synthetic events from the source rule and runs both the source and the re-parsed YARA-L over them; every event had to get the same verdict, with no unknowns.
- The YARA-L passed RuleBridge's structural checker against Google's published UDM field list.
- The output has no `TODO(rulebridge)` markers.

| step | rules |
|---|---:|
| converted | 901 |
| graded exact, or approximate with only low-risk caveats | 279 (254 exact, 25 approximate) |
| failed the round-trip gate (re-parse error, so the check could not run) | 13 |
| **candidates** | **266** (241 exact, 25 approximate) |
| dropped in detection-engineering review | 183 |
| **approved and added here** | **83** (62 exact, 21 approximate) |

All 83 come from SPL (`query.splunk`). No KQL or CQL rule was approved; see below.

## Detection-engineering review

A conversion can be faithful and still be a bad rule to import. The review looked at each candidate's YARA-L next to its SPL, checked every UDM field against Google's parser pages (WINEVTLOG, Windows Sysmon, GitHub, GCP Cloud Audit, Azure AD audit, the AZURE_ACTIVITY change log and the Microsoft Defender for Endpoint parser), and dropped anything that was not clearly safe.

The Detection Engineer agent could not be reached from this run (no agent-to-agent messaging tool was available), so this review was done by the converter's operator against the docs in `rulebridge/docs/reference/google-secops`. Please treat it as a first pass and have a human detection engineer skim the approved list before anything is enabled.

### Why rules were dropped

| reason | rules | detail |
|---|---:|---|
| Sigma-wave1 template stubs | 125 | Source is a Sigma-wave1 template: the SPL only filters on the event code and the Sigma selection logic was never ported, so the converted rule would fire on every event of that type |
| Noisy, or query does not do what the title says | 23 | Source query matches routine, high-volume activity (or does not implement what the title says), so importing it would be noisy |
| KQL source with a medium-confidence path field | 16 | KQL source: the RuleBridge pack rates FolderPath/InitiatingProcessFolderPath as medium confidence, but the grade came out exact. Google's MDE parser builds principal/target full_path as FolderPath + '/' + FileName when FolderPath lacks the file name, so the `\\name.exe$` regexes could miss. Converter grading bug; fix and re-run before import. |
| Title needs a sequence, burst or join the query does not have | 11 | Title describes a sequence, burst or correlation that the source query does not implement; as a single-event rule it would alert on routine activity |
| CQL source with an unverified UDM landing field | 4 | CQL source: ImageFileName/ParentBaseFileName are medium confidence in the pack, Falcon uses \Device\HarddiskVolumeN paths, and the Google CrowdStrike EDR parser page in our doc set was a 404, so the UDM landing field is not doc-verified. |
| Duplicate logic | 2 | Same logic as another approved rule (DAC-WIN-0119) |
| Marked not production-ready in the source | 1 | Source SPL says it needs a Tier-0 allowlist / first-seen baseline join before enabling |
| Converter flattened the logic | 1 | RuleBridge flattened per-channel (event ID AND log channel) pairs into two independent OR lists and still called it exact; 7036/7040 service-state events from any channel would match. Logged as a converter bug. |

Rule ids per reason:

- **Sigma-wave1 template stubs** (125): DAC-WIN-0201, DAC-WIN-0202, DAC-WIN-0203, DAC-WIN-0204, DAC-WIN-0205, DAC-WIN-0206, DAC-WIN-0209, DAC-WIN-0211, DAC-WIN-0212, DAC-WIN-0213, DAC-WIN-0214, DAC-WIN-0215, DAC-WIN-0216, DAC-WIN-0217, DAC-WIN-0218, DAC-WIN-0219, DAC-WIN-0220, DAC-WIN-0221, DAC-WIN-0222, DAC-WIN-0223, DAC-WIN-0224, DAC-WIN-0225, DAC-WIN-0226, DAC-WIN-0227, DAC-WIN-0228, DAC-WIN-0229, DAC-WIN-0230, DAC-WIN-0231, DAC-WIN-0232, DAC-WIN-0233, DAC-WIN-0234, DAC-WIN-0235, DAC-WIN-0236, DAC-WIN-0237, DAC-WIN-0238, DAC-WIN-0239, DAC-WIN-0240, DAC-WIN-0241, DAC-WIN-0242, DAC-WIN-0243, DAC-WIN-0244, DAC-WIN-0245, DAC-WIN-0246, DAC-WIN-0247, DAC-WIN-0248, DAC-WIN-0249, DAC-WIN-0250, DAC-WIN-0251, DAC-WIN-0252, DAC-WIN-0253, DAC-WIN-0254, DAC-WIN-0255, DAC-WIN-0256, DAC-WIN-0257, DAC-WIN-0258, DAC-WIN-0259, DAC-WIN-0260, DAC-WIN-0261, DAC-WIN-0262, DAC-WIN-0263, DAC-WIN-0264, DAC-WIN-0265, DAC-WIN-0266, DAC-WIN-0267, DAC-WIN-0268, DAC-WIN-0269, DAC-WIN-0270, DAC-WIN-0271, DAC-WIN-0272, DAC-WIN-0273, DAC-WIN-0274, DAC-WIN-0275, DAC-WIN-0276, DAC-WIN-0277, DAC-WIN-0278, DAC-WIN-0279, DAC-WIN-0280, DAC-WIN-0281, DAC-WIN-0282, DAC-WIN-0283, DAC-WIN-0284, DAC-WIN-0285, DAC-WIN-0286, DAC-WIN-0287, DAC-WIN-0288, DAC-WIN-0289, DAC-WIN-0290, DAC-WIN-0291, DAC-WIN-0292, DAC-WIN-0293, DAC-WIN-0294, DAC-WIN-0295, DAC-WIN-0296, DAC-WIN-0297, DAC-WIN-0298, DAC-WIN-0299, DAC-WIN-0300, DAC-WIN-0301, DAC-WIN-0302, DAC-WIN-0303, DAC-WIN-0304, DAC-WIN-0305, DAC-WIN-0306, DAC-WIN-0307, DAC-WIN-0308, DAC-WIN-0309, DAC-WIN-0310, DAC-WIN-0311, DAC-WIN-0312, DAC-WIN-0313, DAC-WIN-0314, DAC-WIN-0315, DAC-WIN-0316, DAC-WIN-0317, DAC-WIN-0318, DAC-WIN-0319, DAC-WIN-0320, DAC-WIN-0321, DAC-WIN-0322, DAC-WIN-0323, DAC-WIN-0324, DAC-WIN-0325, DAC-WIN-0326, DAC-WIN-0327, DAC-WIN-0328
- **Noisy, or query does not do what the title says** (23): DAC-MDE-0056, DAC-AZ-0009, DAC-AZ-0016, DAC-AZ-0022, DAC-AZ-0032, DAC-AZ-0040, DAC-GCP-0007, DAC-GCP-0010, DAC-GCP-0017, DAC-GCP-0019, DAC-GCP-0023, DAC-GCP-0033, DAC-GCP-0039, DAC-GH-0038, DAC-GH-0044, DAC-GH-0045, DAC-WIN-0118, DAC-WIN-0126, DAC-WIN-0154, DAC-WIN-0166, DAC-WIN-0167, DAC-WIN-0177, DAC-WIN-0183
- **KQL source with a medium-confidence path field** (16): DAC-MDE-0002, DAC-MDE-0010, DAC-MDE-0032, DAC-MDE-0039, DAC-MDE-0067, DAC-MDE-0068, DAC-MDE-0069, DAC-MDE-0070, DAC-MDE-0071, DAC-MDE-0073, DAC-MDE-0075, DAC-MDE-0076, DAC-MDE-0077, DAC-MDE-0079, DAC-MDE-0080, DAC-MDE-0081
- **Title needs a sequence, burst or join the query does not have** (11): DAC-AZ-0003, DAC-AZ-0014, DAC-AZ-0015, DAC-AZ-0039, DAC-GCP-0004, DAC-GCP-0014, DAC-GCP-0026, DAC-GCP-0036, DAC-WIN-0106, DAC-WIN-0156, DAC-WIN-0023
- **CQL source with an unverified UDM landing field** (4): DAC-CS-0013, DAC-CS-0079, DAC-CS-0085, DAC-CS-0086
- **Duplicate logic** (2): DAC-WIN-0159, DAC-WIN-0022
- **Marked not production-ready in the source** (1): DAC-WIN-0112
- **Converter flattened the logic** (1): DAC-WIN-0114

Round-trip gate failures (13): DAC-ENTRA-0006, DAC-ENTRA-0014, DAC-ENTRA-0015, DAC-ENTRA-0017, DAC-ENTRA-0019, DAC-ENTRA-0020, DAC-ENTRA-0023, DAC-ENTRA-0025, DAC-ENTRA-0029, DAC-ENTRA-0032, DAC-ENTRA-0035, DAC-ENTRA-0036, DAC-ENTRA-0040. All are Entra audit rules; the re-parse of the YARA-L failed (`'Or' object has no attribute 'field'`), which is a RuleBridge bug, not a rule problem.

### Converter bugs found during review

These are RuleBridge issues, logged so they get fixed before the next run:

1. **Logic flattening (DAC-WIN-0114).** `(channel A AND ids 1,2) OR (channel B AND ids 3,4)` came out as `(A or B) and (1 or 2 or 3 or 4)` and was still graded exact. The round-trip check missed it because the synthetic events did not cover cross-channel pairs.
2. **Source-side confidence ignored.** The KQL `FolderPath` / `InitiatingProcessFolderPath` and CQL `ImageFileName` / `ParentBaseFileName` mappings are medium confidence in the packs, but only target-side confidence lowers the grade. Those 20 rules were graded exact when they should have been approximate.
3. **Entra re-parse error.** The YARA-L parser fails on some `or` groups over `metadata.product_event_type`, so 13 Entra conversions could not be round-trip checked.

## Caveats on the approved rules

- `telemetry_validated` stays `false` on every rule. Nothing here has run against real SecOps data.
- The syntax check is RuleBridge's own checker, not Google's compiler. Run `verifyRuleText` (see `README.md`) before creating rules.
- 21 approved rules are `approximate`. Their caveats are listed per rule in `conversions.google_secops.caveats` and in `manifest.json`. Most say the 1h match window is a guess for an SPL `stats` with no time bucket; set it to the schedule you run the Splunk search on.
- Approved rules still carry the logic of their SPL source. Where the SPL is broad (for example DAC-WIN-0117 matches any user id containing "admin"), the YARA-L is equally broad. Tune both together.

