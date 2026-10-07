# Trusted detection authors / sources

Use as a **prior**, not proof. Always verify fields against official log docs + Splunk/TA behavior.

Update this file when an author’s rules repeatedly match real `_raw` field paths.

## Trust tiers

| Tier | Meaning | Action |
|------|---------|--------|
| T1 | Repeatedly field-correct in our lab/tenants | Prefer as reference; still doc-check new log families |
| T2 | Reputable OSS / vendor content | Strong starting point; verify nested/cloud fields |
| T3 | Unknown / unverified | Full field audit before porting |

## Seed list (maintain live)

| Author / org | Tier | Notes |
|--------------|------|-------|
| Splunk Security Content (research/splunk) | T2 | Aligns with TA field names; check version |
| SigmaHQ (quality-labeled rules) | T2 | Translation to Splunk often breaks fields — re-verify |
| Microsoft / ATT&CK data sources | T2 | Telemetry existence, not SPL |
| AWS security blog / CT docs | T2 | Schema authority for CloudTrail |
| detections.ai — *add named authors after verification* | T3→T1 | Promote only after field proof |

## detections.ai workflow

1. Search technique / keyword.
2. Prefer rules from T1/T2 authors when listed.
3. If site requires auth → **ask user to log on**, then continue.
4. Extract sourcetype + fields → run learning loop → update `memory/sourcetypes/*`.
5. Port without `index=`; record author + URL in DaC `references`.

## Promotion rule

After **≥2** independent field verifications (docs + live/sample `_raw`) for the same author on the same log family, move author to T1 for that family.
