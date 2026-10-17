# REVIEW — DAC-OKTA-0009 Okta: sign-in allowed by a single-factor (1FA) policy rule

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_successful_single_factor_authentication.yml (security_content develop @ d6afc62b750d)

## Coverage after
Detects Okta System Log policy.evaluate_sign_on events with outcome.result=ALLOW where a matched rule target has detailEntry.policyRuleFactorMode=1FA, i.e. Okta let the user in with one factor. A stolen password alone is enough for these sign-ins. One row per user and app (target of type AppInstance) with the matched rule names. Built only from field paths and values in the Splunk attack_data sample okta_single_factor_auth.log.

## ATT&CK mapping check (v19.2)
T1078.004 → initial-access, persistence, privilege-escalation, stealth. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/okta_single_factor_auth/okta_single_factor_auth.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `target{}.detailEntry.policyRuleFactorMode`, `target{}.type`, `target{}.displayName`, `actor.alternateId`, `client.ipAddress`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/okta_single_factor_auth/okta_single_factor_auth.log | 5 | 1 | 1 | `{"user": "user85540a@example.com", "app": "Okta Dashboard", "count": 1}` |

Other attack_data Okta payloads that also produce rows: attack_techniques__T1539__okta_web_session_multiple_ip__okta_web_session_multiple_ip.log (1 row).

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (correctness, from the payload): the event has two Rule targets (Default Rule, sfa) and one AppInstance. Picking "the rule" with mvindex(...,0) would report only one. Fix: values(target{}.displayName) lists all; app is picked by type AppInstance.
- F2 (fidelity): upstream infers single factor from user.authentication.verify/auth_via_mfa without Okta Verify, which also fires for password+SMS. Fix: use Okta's own policyRuleFactorMode=1FA on the matched rule.
- F3 (every line needed): the multivalue match on "target{}.detailEntry.policyRuleFactorMode"="1FA" is true if any matched rule is 1FA; that is the intended meaning.
- F4 (correctness): stats drops events whose by-key is null; a 1FA sign-on with no AppInstance target would vanish. Fix: fillnull app="unknown".

## Bypass table
| Attacker variation | Result |
|---|---|
| Attacker signs in through an app with its own 2FA rule | Not this rule (no weakness) |
| Org uses legacy (Classic) sign-on policy events | Unverified: field may be absent |

## False-positive check
- Apps or networks deliberately configured for 1FA (e.g. a low-risk app from a trusted zone). Tune by app and rule name; each row names both.

## Unverified ideas
- This is a posture-type detection: volume depends entirely on how many 1FA rules the org has. Expect it to need per-app tuning.
- The session-cookie sample also contains 1FA ALLOW events, so it fires there too (expected).
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0009/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_2fa_rule | benign | False | 0 | PASS |
| near_miss_1fa_denied | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
