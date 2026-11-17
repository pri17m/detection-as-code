# Google SecOps (Chronicle)

Detections that support Google SecOps list `google_secops` in `platforms` and carry YARA-L 2.0 in `query.google_secops`.

Right now every one of them was converted from the rule's SPL by [RuleBridge](https://github.com/pri17m/rulebridge), not written by hand. Each converted rule records where the query came from in `conversions.google_secops`:

```yaml
conversions:
  google_secops:
    converter: rulebridge
    converter_version: 0.1.0
    source_language: spl
    source_query: query.splunk
    fidelity: exact            # or approximate
    roundtrip: agree
    caveats: []                # what differs from the SPL, if anything
```

`telemetry_validated` stays `false` until a rule has been run against real SecOps data.

The validator requires `query.google_secops` when `google_secops` is in `platforms`. It also requires `conversions.google_secops` when the YARA-L says `converted_by = "rulebridge"`.

The import bundle, review notes and an upload script are in `exports/google-secops/`.
