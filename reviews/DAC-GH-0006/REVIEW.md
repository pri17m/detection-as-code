# REVIEW - DAC-GH-0006 GitHub: Actions workflow modified

## Attribution
Event-name check against GitHub's "Audit log events for your organization" (https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization) and the enterprise list (https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise), pulled 2026-11-12. Prompted by the Aikido CI-stealer research (https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories), where workflow file injection is the main payload path. No employer, client or tenant data.

## As-is
`sourcetype=github:audit (action="workflows.workflow_file_modified" OR action="repo.actions_workflow_update" OR action="repo.create_workflow" OR action="repo.update_workflow") | stats count values(actor) as actors values(repo) as repos by action`

The action names (workflows.workflow_file_modified, repo.actions_workflow_update, repo.create_workflow, repo.update_workflow) are not on GitHub's org or enterprise audit-log event lists. The query can't match real audit-log data, so the rule never fires.

## After
Tag `needs-review` added (the rule had no `tags` field). One sentence added to the description saying why. Query, ID, ATT&CK, author and everything else unchanged.

Status: **needs-review**. The behaviour is a change to a file under `.github/workflows/`. GitHub's audit log records `git.push` with `external_id`, `repository_public`, `transport_protocol` and `transport_protocol_name` as extra fields, but not which files a push changed, and no `workflows.*` event records a workflow file being added or edited (the documented workflows actions cover runs, jobs, enable/disable and pin). So the behaviour can't be expressed with audit-log data alone. Following the brief, I didn't invent event names and didn't delete or renumber the rule.

## Options for the reviewer
- Option A (preferred): add a push-webhook source (`push` event, `commits[].added` / `commits[].modified`, `pusher`, `ref`; https://docs.github.com/en/webhooks/webhook-events-and-payloads#push) and rewrite against it. That needs a new sourcetype in `config/sourcetype_map.yaml`, which I haven't touched.
- Option B: retarget to a documented neighbour such as `workflows.disable_workflow` / `workflows.enable_workflow`. That changes what the rule means (workflow state, not file content), so I didn't do it.
- Option C: keep it as a documented gap until a file-level source exists.

## Bypass research
| Attacker variation | Result | Source |
|---|---|---|
| Any workflow file change (the Aikido `ci: refresh build cache` and `build-audit-xxxxxx.yml` variants) | MISSED: no matching audit event exists | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |
| Install hook (`postinstall` + `.ci-xxxxxx.sh`) instead of a workflow edit | MISSED: not a workflow change | https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories |

## Unverified
- That no undocumented audit action for workflow edits exists in real streams. I only checked the documented lists.
- Push webhook nested commit fields: the docs page lists `commits` but doesn't expand its objects in the copy I pulled.

## Tests / fixtures
None added. The query is unchanged and can't match documented events, so fixtures would only restate that. They'll be added with whichever option is chosen. Not run in local Splunk.

## Ponytail findings
- F1 (dead query): failing input: a GitHub audit event for a real workflow change. The only documented candidate is `git.push`, which the query doesn't select and which carries no file path. Fix: none applied; tagged needs-review (see Options).
- F2 (author): the author stays as-is while the repo-wide author cleanup is on hold.

## Reviewer status
pending human review (needs-review)
