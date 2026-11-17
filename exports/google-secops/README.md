# Google SecOps import bundle

83 detections from this repo, converted from SPL to YARA-L 2.0 by RuleBridge and approved in review. Nothing in this folder has been sent to a SecOps tenant yet.

| file | what it is |
|---|---|
| `rules/<id>.yaral` | One YARA-L 2.0 rule per detection. Same text as `query.google_secops` in the detection YAML. |
| `import-requests/<id>.json` | The two API calls RuleBridge's `build_import_request` produces for that rule (dry run): `verifyRuleText`, then `rules.create`. `{project}`, `{location}` and `{instance}` are placeholders. |
| `manifest.json` | Rule list with fidelity, score, source path and caveats. `push_to_secops.py` reads it. |
| `push_to_secops.py` | Verifies, and with `--apply` creates, the rules through the SecOps v1alpha API. Not run yet. |
| `REVIEW.md` | How the 83 were picked from 901, and why 183 candidates were dropped. |
| `dropped.json`, `gate_failed.json` | The dropped and gate-failed rules with reasons. |

## Pushing to SecOps

You need:

1. The SecOps instance's **project id**, **region** (for example `us` or `europe`) and **instance id** (the customer id shown under SIEM Settings > Profile).
2. A Google identity with the Chronicle API roles that allow `chronicle.rules.verifyRuleText` and `chronicle.rules.create`. Chronicle API Editor covers both. A service account key or `gcloud auth application-default login` both work.

Then:

```bash
cd exports/google-secops
pip install google-auth requests
gcloud auth application-default login
export SECOPS_PROJECT=my-project SECOPS_LOCATION=us SECOPS_INSTANCE=<instance id>

python push_to_secops.py            # verify only: runs Google's compiler on every rule, creates nothing
python push_to_secops.py --apply    # verify, then create the rules that passed
```

Results go to `push_results.json`. Rules that fail `verifyRuleText` are not created. Created rules are not live until you turn on the deployment in SecOps (Rules Editor or `rules.updateDeployment`). Turn on alerting one family at a time, and watch the volume for a day or two first.

API references: [verifyRuleText](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances/verifyRuleText), [rules.create](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.rules/create).

## Regenerating

The bundle and the `query.google_secops` fields are produced from RuleBridge output. Do not hand-edit them. If a rule's SPL changes, re-run the conversion and re-review that rule.
