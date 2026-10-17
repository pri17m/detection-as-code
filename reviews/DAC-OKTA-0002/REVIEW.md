# REVIEW — DAC-OKTA-0002 Okta: identity provider created, activated, deactivated or deleted

## Coverage before
No Okta rules in the repo (no `OktaIM2:log` detections). Splunk security_content has this use case:
- https://github.com/splunk/security_content/blob/develop/detections/application/okta_idp_lifecycle_modifications.yml (security_content develop @ d6afc62b750d)

## Coverage after
Detects successful Okta System Log system.idp.lifecycle.create / activate / deactivate / delete events. Adding and activating an external identity provider (for example a Google OIDC IdP) gives an attacker a federated sign-in path that bypasses the org password and MFA; deactivating or deleting one can break SSO or remove evidence. new_idp_enabled=1 marks the same actor creating and activating the same IdP. Built only from field paths and values in the Splunk attack_data sample okta_idp/okta.log.

## ATT&CK mapping check (v19.2)
T1484.002 → defense-impairment, privilege-escalation. Checked against enterprise-attack 19.2 (not revoked or deprecated; tactics as listed in 19.2).

## Source and fields
- Payload (only source of field names and values): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/okta_idp/okta.log
- Fields used (raw Okta LogEvent JSON paths, as auto-extracted for `OktaIM2:log`): `eventType`, `outcome.result`, `actor.alternateId`, `target{}.id`, `target{}.type`, `target{}.displayName`, `target{}.alternateId`, `debugContext.debugData.protocol`, `client.ipAddress`. Every path and every literal value in the query appears in the payload.
- Field meaning cross-checked: Okta event types catalogue (https://developer.okta.com/docs/okta-event-types.csv) and System Log docs (externalSessionId = "events that occurred in the same user session"; transaction.id = events "part of an operation").
- Clean-room: own SPL. No security_content search text copied; no CIM datamodel, tstats or `okta` macro. Upstream detection used for the use case and the test payload only. Attribution: THIRD_PARTY_NOTICES.md (splunk/security_content, splunk/attack_data, Apache-2.0).

## Payload match (local Python stand-in, not Splunk)
| Payload | Events | Alert rows | Rows with malformed lines dropped | First row |
|---|---|---|---|---|
| https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/okta_idp/okta.log | 5 | 1 | 1 | `{"actor": "attacker@github.oktaidp", "idp_id": "0oadup8giv0zAemm65d7", "actions": ["activate", "create", "deactivate", "delete"], "new_idp_enabled": 1}` |

Other attack_data Okta payloads that also produce rows: none.

## Ponytail review
Ponytail pass (2026-10-17): correctness, safety, behaviour under load, tests, speed, every line needed.
- F1 (triage): five lifecycle events for one IdP came out as five rows. Fix: one row per actor + IdP id with values(action); new_idp_enabled=1 ranks create+activate first.
- F2 (correctness): IdP id/name taken by mvfind on target{}.type="IdentityProvider", not mvindex 0, so extra targets in other tenants do not shift it.
- F3 (every line needed): no threshold. IdP lifecycle changes are rare admin actions (Okta docs: "audit that a new identity provider has been created"), so every one is reviewed.
- F4 (correctness): stats drops events whose by-key is null; an IdP event without an IdentityProvider target would vanish. Fix: fillnull idp_id="unknown".

## Bypass table
| Attacker variation | Result |
|---|---|
| Modify an existing IdP (routing rule, JIT provisioning) instead of creating one | MISSED: system.idp.lifecycle.update is not in the payload, so not in scope (record for batch 2 once a sample exists) |
| Add an org-to-org (inbound federation) app instead of an IdP | MISSED |

## False-positive check
- Planned SSO or social-login setup by an identity admin. Confirm a change record for the IdP name/protocol shown.

## Unverified ideas
- mvindex/mvfind alignment assumes every target element has displayName; if one lacks it the multivalue lists shift. All payload targets have it.
- Field extraction assumes the Splunk Add-on for Okta Identity Cloud JSON extraction yields the raw dotted paths (security_content searches on `OktaIM2:log` use the same raw paths, e.g. `debugContext.debugData.factor`). Not run in Splunk; telemetry_validated=false.
- Depends on PR #65 (adds `OktaIM2:log` to allowed_sourcetypes and the THIRD_PARTY_NOTICES entry).

## Tests
`tests/cases/DAC-OKTA-0002/`: malicious fixture(s) are trimmed real attack_data events; benign and near-miss fixtures are synthetic edits of those events. Not run by CI (repo has no runner). Local stand-in results:

| Fixture | Label | Expect alert | Stand-in rows | Result |
|---|---|---|---|---|
| benign_idp_update_event | benign | False | 0 | PASS |
| near_miss_failed_create | near_miss | False | 0 | PASS |

## Reviewer status: pending human approval
