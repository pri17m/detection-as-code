# REVIEW — DAC-OKTA-0001 Okta: two or more MFA factors reset for one user by the same actor

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_multi_factor_authentication_disabled.yml (security_content develop @ d6afc62b750d)

## Coverage after
Detects Okta System Log user.mfa.factor.deactivate events with outcome.result=SUCCESS where one actor resets two or more distinct factors (parsed from outcome.reason "User reset <FACTOR> factor") on the same target user (target{}.id of type User). Stripping every enrolled factor lets an attacker who controls the session or an admin account enrol their own factor. other_user=1 marks an actor resetting someone else's factors. Built only from field paths and values in the Splunk attack_data sample okta_mfa_method_disabled.log. Run over a 60-minute window.

## ATT&CK mapping check (v19.2)
T1556.006 → defense-impairment, persistence, credential-access. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.006/okta_mfa_method_disabled/okta_mfa_method_disabled.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `outcome.reason`, `actor.id`, `actor.alternateId`, `target{}.id`, `target{}.type`, `target{}.alternateId`, `client.ipAddress`, `authenticationContext.externalSessionId`, `transaction.id`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556.006/okta_mfa_method_disabled/okta_mfa_method_disabled.log | 3 | 1 | 1 | `{"actor_id": "00ufb5gta21oowKfZ5d7", "actor": "user15@splunkresearch.com", "target_user_id": "00uffks4r9kkYNxpj5d7", "other_user": 1, "factors_reset": 3, "factor": ["OKTA_SOFT_TOKEN", "OKTA_VERIFY_PUSH", "SIGNED_NONCE"]}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (correctness, from the payload): the same target.id 00uffks4r9kkYNxpj5d7 appears with two target alternateIds (user15o@... and user15@...). Grouping by target login split the three resets into 2+1 rows. Fix: group by target{}.id where target{}.type=User; logins kept as values(target_login).
- F2 (fidelity): alerting on every deactivate (upstream behaviour) fires on each single help-desk reset. Failing input: one OKTA_VERIFY_PUSH reset for a user who lost a phone. Fix: require dc(factor)>=2 for the same actor/target; other_user is a triage column, not a filter (benign fixture).
- F3 (correctness): factor taken from outcome.reason with an anchored rex; if Okta changes the wording, coalesce falls back to the full reason string so distinct reasons still count.
- F4 (every line needed): outcome.result="SUCCESS" kept; near-miss fixture with FAILURE events must not alert.
- F5 (correctness): stats drops events whose by-key is null; a deactivate with no User target would vanish. Fix: fillnull target_user_id="unknown" after other_user is computed.

## Bypass table
| Attacker variation | Result |
|---|---|
| Reset factors one at a time hours apart | MISSED beyond the 60-minute window |
| Reset only the one factor the victim uses, then enrol own | MISSED (single reset); see device-enrolment rule in batch 2 |
| Delete the user and recreate | Not this rule |

## False-positive check
- Help-desk or self-service "reset all factors" for a user who lost their phone. Confirm a ticket and that the actor is a help-desk admin; other_user=0 means the user reset their own factors.

## Unverified ideas
- Okta wording "User reset <FACTOR> factor" is from the sample only; other reset paths (admin API, self-service) may use different outcome.reason text. Fallback keeps the rule firing but may double count.
- In the sample, debugContext.debugData.requestUri is /api/v1/devices/.../lifecycle/deactivate, a device deactivation; real tenants may log factor resets with other URIs. Not used by the rule.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0001/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_single_factor_helpdesk_reset | benign | False | 0 | PASS |
| near_miss_same_factor_twice | near_miss | False | 0 | PASS |
| near_miss_failed_reset | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
