# Lookup templates

Templates for lookups that rules reference. Rows are fake placeholders (`EXAMPLE-*`); never commit real host or VM names.
Naming follows the repo convention for templates (`config/org.example.yaml`): copy and drop the `.example` suffix.

## dac_domain_controller_vms (used by DAC-VMW-0038)

Columns: `vm_name` (ESXi VM name as it appears in hostd logs), `is_dc` (`true`/`false`).

Deploy:
1. Copy `dac_domain_controller_vms.csv.example` to `dac_domain_controller_vms.csv` and replace the rows with your DC VM names (e.g. from a CMDB or vCenter export).
2. Upload it to the app running the rule: Settings > Lookups > Lookup table files > New (or place it in `$SPLUNK_HOME/etc/apps/<app>/lookups/`).
3. Share it with the app (or globally) so `| lookup dac_domain_controller_vms vm_name OUTPUT is_dc` resolves. Matching is case-sensitive by default; add a lookup definition with `case_sensitive_match = false` if needed.
4. Keep it current; DCs absent from both the lookup and `dc_name_pattern` are missed.
