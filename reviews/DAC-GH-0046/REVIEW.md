# REVIEW - DAC-GH-0046 GitHub: OIDC cloud role assumption from Actions for unexpected repo

## Attribution
Fix prompted by the Aikido CI-stealer write-up (12 Nov 2026): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories, which says the payload "mints GitHub OIDC tokens for AWS, GCP and Azure audiences and exchanges them for cloud sessions." Field names are from the AWS CloudTrail userIdentity docs and the IAM AssumeRoleWithWebIdentity CloudTrail sample. The `sub` format (`repo:ORG/REPO:ref:refs/heads/BRANCH`) is from GitHub's OIDC hardening docs. Own SPL. No employer, client or tenant data. Fixtures are synthetic.

## As-is
`search action IN ("workflows.completed_workflow_run","oidc.*") OR operation_type="oidc" | # Correlate separately ...`
- GitHub's org and enterprise audit event lists have no `oidc.*` actions; the only OIDC entries are `business.enable_oidc` / `business.disable_oidc` (an enterprise SSO setting). The GitHub audit log records no event when a workflow requests an OIDC token.
- `| #` is not valid SPL. Splunk 9.4.1 rejected the query: "Missing a search command before '#'". It returned an error on every fixture.

## After
The behaviour can't be expressed with GitHub audit-log data, but it can be with the cloud side, so the query now reads CloudTrail and keeps the rule ID. It takes successful and failed `sts:AssumeRoleWithWebIdentity` calls whose identity provider is `token.actions.githubusercontent.com`, pulls the repo from the `sub` claim (`responseElements.subjectFromWebIdentityToken`, falling back to `userIdentity.userName`), and finds (role, repo) pairs whose first appearance is in the last hour of the search window, for roles that already have at least one other repo. Schedule hourly over 30 days. Sourcetype changed from `github:audit`/`github:cloud:audit` to `aws:cloudtrail`, which is on the allowlist. `telemetry_validated: false`.

## ATT&CK v19.2
T1550.001 (lateral-movement, kept), T1078.004 (stealth, persistence, privilege-escalation, initial-access, added). Checked against enterprise-attack-19.2.json: both present, not revoked or deprecated. Tactic list updated to lateral-movement and initial-access.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Abuse a repo the role already trusts, on a new branch (the Aikido `chore/xxxxxxxx` case) | MISSED: only new repos alert; DAC-AWS-0075 catches the follow-on key creation | https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect |
| Role used by only one repo so far | MISSED: no baseline, see F2 | (fixture near_miss_2) |
| Custom `sub` template without `repo:` | Repo shows as `unparsed:<sub>` and still counts as a new pair | https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect |
| Replay the stolen OIDC token against GCP or Azure | MISSED: AWS only | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |

## Unverified
- Whether a failed AssumeRoleWithWebIdentity (trust condition mismatch) still carries `userIdentity.identityProvider`. If not, failures are dropped.
- Real volume of new (role, repo) pairs. Not measured.
- The rule file stays under `detections/splunk/github/` with a GH ID while reading CloudTrail. Moving or renumbering it was out of scope.

## Tests / fixtures
`tests/cases/DAC-GH-0046/`: all synthetic, 30 days of history per fixture.

Splunk Enterprise 9.4.1 (throwaway local instance on the agent box). No Splunk add-ons installed, so a local props.conf set `KV_MODE = json` for the sourcetype (`aws:cloudtrail` timestamps from `eventTime`, `github:audit` timestamps from `@timestamp` in epoch ms). Field names are the raw JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -index dac`, and the rule query ran unchanged via REST (`search index=dac source="<fixture>" <query>`, earliest=0). The events are synthetic, so this shows the SPL parses and the logic does what each fixture says. It says nothing about real volume or real field shapes. CI does not run fixtures (the repo has no Splunk runner).

| Fixture | Label | Expect alert | Rows | Result | Rows with the as-is query | What it is |
|---|---|---|---|---|---|---|
| malicious_0_synthetic.json | malicious | True | 1 | PASS | error | Role with two known repos; a third repo assumes it in the last hour |
| benign_1_synthetic.json | benign | False | 0 | PASS | error | Known repos only, including a pull_request context |
| near_miss_2_synthetic.json | near_miss | False | 0 | PASS | error | New role with one repo (no baseline); a new repo first seen 3 h before window end |

## Ponytail findings
- F1 (does not parse): failing input: any fixture. The as-is query errored in Splunk on `| #`. Fix: the comment line is gone.
- F2 (no baseline): failing input: `near_miss_2_synthetic.json`. A draft without `repos_seen_for_role>=2` alerted on a brand-new role whose only caller is its own repo. Fix: require another repo on record for the role. Replay: 0 rows.
- F3 (now() vs data): reasoned. The draft compared `first_seen` with `now()`, which makes the rule untestable on stored data and drifts if the search is delayed. Fix: compare with the newest event in the window (`last_event`).
- F4 (author): the author stays "Detection Engineer" while the repo-wide author cleanup is on hold.

## Reviewer status
pending human review
