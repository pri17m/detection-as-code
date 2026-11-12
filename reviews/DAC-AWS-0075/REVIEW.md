# REVIEW - DAC-AWS-0075 Long-lived IAM access key created by a GitHub OIDC or CI role session, with the new key's first use

## Attribution
Behaviour from Aikido Security, "Compromised GitHub accounts push CI secret stealer to tens of thousands of repositories" (Oliver Smith, 12 Nov 2026): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories. Aikido says the payload "mints GitHub OIDC tokens for AWS, GCP and Azure audiences and exchanges them for cloud sessions" and "chains into other IAM roles it finds in the repository, then calls `iam:CreateAccessKey` to create long-lived credentials for IAM users." Aikido published no query; the SPL is our own, from the AWS CloudTrail userIdentity docs, the IAM AssumeRoleWithWebIdentity CloudTrail sample and the Stratus Red Team CreateAccessKey detonation log. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. DAC-AWS-0003 and DAC-AWS-0005 fire on every `CreateAccessKey` with no caller context (0005's "use from new source" join is a comment only). Nothing on `main` ties a key creation to a CI or GitHub OIDC session or reports the new key's first use.

## After
Pulls `AssumeRoleWithWebIdentity`, `AssumeRole`, `CreateAccessKey` and every call made with an `AKIA` key in the search window. A `CreateAccessKey` that succeeds and returns an `AKIA` key alerts when:
- `github_oidc_direct` (critical): the caller has `webIdFederationData.federatedProvider` (or `identityProvider`) for `token.actions.githubusercontent.com`.
- `github_oidc_chained` (critical): the caller's `accessKeyId` is the `responseElements.credentials.accessKeyId` that an STS call from a GitHub OIDC session issued. One hop only.
- `ci_role_name` (high): the caller's role name has github, gha, actions, ci, cicd, jenkins, gitlab, pipeline, deploy or build as a separate part of the name.

For each alert it reports the target user, the new key ID, the first later call made with that key (time, API, source, user agent) and the number of calls. Run it over at least 24 hours so the chain and the first use are in the window. `telemetry_validated: false`; the name pattern is an unmeasured heuristic.

## ATT&CK v19.2
T1098.001 (persistence, privilege-escalation), T1078.004 (stealth, persistence, privilege-escalation, initial-access). Checked against enterprise-attack-19.2.json: both present, not revoked or deprecated.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Two or more AssumeRole hops after the OIDC session before CreateAccessKey | MISSED by the chain branch (one hop only); caught only if the role name matches the CI pattern | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html |
| CI role named without any CI-like word (for example `data-pipeline2`, `svc-x`) and not OIDC | MISSED | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| `CreateUser` then `CreateAccessKey` for the new user | Caught (target user doesn't matter); DAC-AWS-0023 also fires on the CreateUser | https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html |
| Key created but first used after the search window ends | Alert still fires; `first_use` says "not seen in search window" | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html |
| Stolen long-term keys from the runner used directly (no CreateAccessKey) | MISSED here by design | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |

## Unverified
- Whether a session created by `AssumeRole` from a GitHub OIDC session still carries `webIdFederationData`. The CloudTrail docs describe it for credentials "obtained by web identity federation". If it does carry over, the chain branch is redundant but harmless.
- That `responseElements.credentials.accessKeyId` is present on every AssumeRole record in your pipeline. The AWS sample shows it.
- The cost of `userIdentity.accessKeyId="AKIA*"` over 24 hours in a busy organisation trail. Not measured. If it is too heavy, drop the first-use part and run DAC-AWS-0005-style follow-up as a separate search.
- The CI name pattern has no measured false-positive rate.

## Tests / fixtures
`tests/cases/DAC-AWS-0075/`: all synthetic. Account IDs are AWS example values, keys are `EXAMPLE` placeholders, IPs are RFC 5737 ranges.

Splunk Enterprise 9.4.1 (throwaway local instance on the agent box). No Splunk add-ons installed, so a local props.conf set `KV_MODE = json` for the sourcetype (`aws:cloudtrail` timestamps from `eventTime`, `github:audit` timestamps from `@timestamp` in epoch ms). Field names are the raw JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -index dac`, and the rule query ran unchanged via REST (`search index=dac source="<fixture>" <query>`, earliest=0). The events are synthetic, so this shows the SPL parses and the logic does what each fixture says. It says nothing about real volume or real field shapes. CI does not run fixtures (the repo has no Splunk runner).

| Fixture | Label | Expect alert | Rows | Result | What it is |
|---|---|---|---|---|---|
| malicious_0_synthetic.json | malicious | True | 1 | PASS | OIDC session, one AssumeRole hop, CreateAccessKey for `svc-reporting`, new key used twice (chained, critical) |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | CreateAccessKey straight from the OIDC session; key unused in window (direct, critical) |
| malicious_2_synthetic.json | malicious | True | 1 | PASS | Static-key `jenkins-deploy` role creates a key (name heuristic, high) |
| benign_3_synthetic.json | benign | False | 0 | PASS | SSO admin rotates a key; an OIDC session in the same window only lists buckets |
| near_miss_4_synthetic.json | near_miss | False | 0 | PASS | Chained OIDC session gets AccessDenied on CreateAccessKey; `financial-reports` role creates a key |

## Ponytail findings
Ponytail pass (2026-11-12). Findings naming a fixture were replayed in local Splunk against the pre-fix draft; the rest are reasoned.

- F1 (time label): failing input: `malicious_0_synthetic.json`. The draft printed `first_use` as `2026-11-10T18:50:00Z` for an event at 13:20 UTC, because `strftime` renders in the search head's zone and the draft hard-coded `Z`. Fix: format with `%z`. Replay: `2026-11-10T18:50:00+0530`, correct.
- F2 (name heuristic too loose): failing input: `near_miss_4_synthetic.json`. The draft's `(ci|deploy|...)` matched `financial-reports` because it contains "ci", and alerted. Fix: the name part must be bounded by start, end, `-`, `_` or `.`. Replay: 0 rows.
- F3 (failed calls): reasoned. A failed CreateAccessKey has no `responseElements`, so `new_key` is empty and `is_create` is 0. The AccessDenied case in `near_miss_4` confirms 0 rows.
- F4 (load): reasoned. Every AKIA call in the window is pulled in for the first-use lookup. This is the most expensive part of the rule; noted under Unverified.

## Reviewer status
pending human review
