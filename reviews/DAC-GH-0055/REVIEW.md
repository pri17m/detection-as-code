# REVIEW - DAC-GH-0055 GitHub: Actions workflow run deleted within 15 minutes of being created

## Attribution
Behaviour from Aikido Security (12 Nov 2026): https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories. Aikido says the actor "reverts within at most one minute and deletes the workflow run, along with its logs. A missing run number in the workflow's history is often the only trace." Event and field names are from GitHub's "Audit log events for your organization": https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization. Own SPL. No employer, client or tenant data. Fixtures are synthetic.

## As-is (new)
New rule. No rule on `main` uses `workflows.delete_workflow_run` or `workflows.created_workflow_run`.

## After
Pairs `workflows.created_workflow_run` with `workflows.delete_workflow_run` for the same run, keyed on repo + `workflow_id` + `run_number` (both events carry these per the docs), falling back to `workflow_run_id`. Alerts when the delete comes 0 to 15 minutes after the create. Output: repo, workflow name, `head_branch`, `head_sha`, trigger event, run number, who triggered, who deleted, whether they match, and the token hash and type. The 15-minute window is unmeasured. `telemetry_validated: false`.

`workflows.created_workflow_run` is "not available in the web interface, only via the REST API, audit log streaming, or JSON/CSV exports" (GitHub docs), so this needs a streamed or API-pulled audit log.

## ATT&CK v19.2
T1070 (stealth), T1677 (execution). Checked against enterprise-attack-19.2.json: both present, not revoked or deprecated.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Delete the run after 15 minutes | MISSED (window) | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Leave the run, delete only the logs (`DELETE /repos/{owner}/{repo}/actions/runs/{run_id}/logs`) | MISSED: no documented audit event for log deletion was found on the org events page | https://docs.github.com/en/rest/actions/workflow-runs |
| Delete the whole repo or branch instead | Not this rule; DAC-GH-0047 covers repo deletion | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization |
| Run in a personal repo outside the org | MISSED: the org audit log only covers org repos | https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization |

## Unverified
- Whether `workflow_id` and `run_number` are populated on both events in real streams. The docs list them as additional fields, but no real sample was available.
- Field naming in the Splunk Add-on for GitHub. Fixtures use the documented flat names (`repo`, `workflow_run_id`, ...).
- Whether the actor on `created_workflow_run` is the pusher or the account that owns the token. Shown for triage only, not used to filter.
- The sourcetypes `github:audit` and `github:cloud:audit` match the 54 existing DAC-GH rules but are not in `config/sourcetype_map.yaml`. The validator only enforces that list for Windows sourcetypes. The allowlist was not edited.

## Tests / fixtures
`tests/cases/DAC-GH-0055/`: all synthetic. Org, repo and user names are made up.

Splunk Enterprise 9.4.1 (throwaway local instance on the agent box). No Splunk add-ons installed, so a local props.conf set `KV_MODE = json` for the sourcetype (`aws:cloudtrail` timestamps from `eventTime`, `github:audit` timestamps from `@timestamp` in epoch ms). Field names are the raw JSON paths. Each fixture's `events` were indexed as one JSON line per event with `splunk add oneshot -index dac`, and the rule query ran unchanged via REST (`search index=dac source="<fixture>" <query>`, earliest=0). The events are synthetic, so this shows the SPL parses and the logic does what each fixture says. It says nothing about real volume or real field shapes. CI does not run fixtures (the repo has no Splunk runner).

| Fixture | Label | Expect alert | Rows | Result | What it is |
|---|---|---|---|---|---|
| malicious_0_synthetic.json | malicious | True | 1 | PASS | Run on `chore/k3j9x2qa` deleted 70 s later by the same PAT |
| malicious_1_synthetic.json | malicious | True | 1 | PASS | Run on `main` deleted 9 min later by another account; delete event has no `workflow_run_id` |
| benign_2_synthetic.json | benign | False | 0 | PASS | Admin deletes a two-day-old run; a normal run completes |
| near_miss_3_synthetic.json | near_miss | False | 0 | PASS | Run deleted 16 min after creation |

## Ponytail findings
Ponytail pass (2026-11-12). Findings naming a fixture were replayed in local Splunk against the pre-fix draft.

- F1 (join key): failing input: `malicious_1_synthetic.json`. The draft keyed on `coalesce(workflow_run_id, repo:workflow_id:run_number)`. When only one of the two events carried `workflow_run_id`, the pair split into two keys and returned 0 rows. Fix: key on repo + `workflow_id` + `run_number` first, run ID as the fallback. Replay: 1 row.
- F2 (order): reasoned. `deleted_time>=created_time` stops a stale delete from pairing with a later run that reuses the key.
- F3 (performance): reasoned. Only two actions are searched; `stats` by run key is linear.

## Reviewer status
pending human review
