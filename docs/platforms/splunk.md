# Splunk adoption and deployment

## Portability contract

- Detections **must not** hardcode `index=...`.
- SPL must include **canonical sourcetype constraints**, e.g. `sourcetype=WinEventLog:Security`.

If your Splunk architecture requires index scoping, implement it **at deploy time** via:

- Macros (preferred), e.g. `` `org_windows_security_scope` `` expanding to `index=...` or a constrained index list.
- Token substitution in deployment tooling (least preferred).

See `config/org.example.yaml` for optional placeholders.

## Running detections

Detections under `detections/splunk/` contain:

- Unified metadata (id/title/mitre/severity/etc.)
- `query.splunk` which can be used in:
  - Correlation searches (ES)
  - Scheduled saved searches
  - Notable events / risk-based alerting pipelines

## Recommended add-ons / normalization

For best results, onboard:

- Windows Security logs with a consistent sourcetype (`WinEventLog:Security` or `XmlWinEventLog:Security`)
- Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)
- Splunk CIM (to normalize fields across sources)

## Deployment hooks (optional)

See `pipelines/deploy/README.md` for a deploy-time model:
- read `config/org.yaml`
- inject macros/tokens
- push saved searches via Splunk REST

## Splunk Free / single-instance PoC

Splunk Free (≈500 MB/day) is a valid adopter target for this repo:

- Keep rules **sourcetype-first**; Free often lands everything in `index=main`.
- Put any `index=` constraint only in gitignored `config/org.yaml` macros (see `config/org.example.yaml`), never in committed `query.splunk`.
- Prefer macros from `config/sourcetype_map.yaml` (e.g. `` `windows_security` ``, `` `windows_sysmon` ``).
- Cap ingest with host filters and Sysmon config — not by hardcoding indexes into shared detections.

Also see the **Splunk Free / PoC adopters** section in the root `README.md`.

