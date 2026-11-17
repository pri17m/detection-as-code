#!/usr/bin/env python3
"""Upload the converted YARA-L rules in this folder to a Google SecOps instance.

Not run yet: no SecOps tenant or credentials were available when this bundle was built.

What it does, per rule in manifest.json:
  1. POST {instance}:verifyRuleText   (always; stops that rule if SecOps reports a compile error)
  2. POST {instance}/rules            (only with --apply)
New rules are created without a live deployment, so nothing alerts until you enable it in SecOps.

Setup:
  pip install google-auth requests
  gcloud auth application-default login     # or GOOGLE_APPLICATION_CREDENTIALS=<service-account.json>
  export SECOPS_PROJECT=<gcp project id> SECOPS_LOCATION=<us|europe|...> SECOPS_INSTANCE=<customer id / instance id>

Usage:
  python push_to_secops.py                 # verify only, nothing is created
  python push_to_secops.py --apply         # verify, then create the rules that passed
  python push_to_secops.py --only DAC-WIN-0018 --apply
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="create rules after verifyRuleText passes")
    ap.add_argument("--only", nargs="*", help="rule ids to process")
    a = ap.parse_args()

    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
    except ImportError:
        print("pip install google-auth requests", file=sys.stderr)
        return 2
    env = {k: os.environ.get(k) for k in ("SECOPS_PROJECT", "SECOPS_LOCATION", "SECOPS_INSTANCE")}
    if not all(env.values()):
        print("set SECOPS_PROJECT, SECOPS_LOCATION and SECOPS_INSTANCE", file=sys.stderr)
        return 2
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    s = AuthorizedSession(creds)
    base = (f"https://{env['SECOPS_LOCATION']}-chronicle.googleapis.com/v1alpha/projects/{env['SECOPS_PROJECT']}"
            f"/locations/{env['SECOPS_LOCATION']}/instances/{env['SECOPS_INSTANCE']}")

    manifest = json.loads((HERE / "manifest.json").read_text())
    results = []
    for m in manifest["rules"]:
        if a.only and m["id"] not in a.only:
            continue
        text = (HERE / m["rule_file"]).read_text()
        v = s.post(f"{base}:verifyRuleText", json={"ruleText": text})
        body = v.json() if v.content else {}
        ok = v.ok and body.get("success", False)
        row = {"id": m["id"], "verify_http": v.status_code, "verified": ok, "verify": body}
        if ok and a.apply:
            c = s.post(f"{base}/rules", json={"text": text})
            row["create_http"] = c.status_code
            row["created"] = c.json().get("name") if c.ok else c.text[:500]
        results.append(row)
        print(f"{m['id']}: verify={'ok' if ok else 'FAIL'}" + (f" create={row.get('create_http')}" if a.apply and ok else ""))
    (HERE / "push_results.json").write_text(json.dumps(results, indent=1))
    bad = [r["id"] for r in results if not r["verified"]]
    print(f"{len(results) - len(bad)}/{len(results)} passed verifyRuleText" + (f"; failed: {', '.join(bad)}" if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
