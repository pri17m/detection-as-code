# REVIEW — DAC-VMW-0038 ESXi snapshot created or VMDK downloaded for a domain controller VM

## Coverage before
DAC-VMW-0020 alerts on every datastore download (any file, any VM). No rule covers snapshot creation, and none is scoped to domain controllers (grep "Create Snapshot" and "dc" in detections/splunk/vmware at main a936b38).

## Coverage after
Behavior: ESXi hostd "Create Snapshot:" on a VM, or a datastore download of a .vmdk, where the VM is a domain controller. Offline dumping of NTDS.dit from a DC virtual disk bypasses in-guest EDR (Unit 42, CVE-2026-0257 intrusions). DC identification is configurable: lookup dac_domain_controller_vms (vm_name,is_dc) and a default name pattern in eval dc_name_pattern; edit both for your naming. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1003.003; T1006; T1578.001 → credential-access, stealth, defense-impairment. Checked against attack-stix-data enterprise-attack-19.2.json (present, not revoked/deprecated, tactics from kill_chain_phases).

## Source and fields
- Threat context: Unit 42, https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/ (Oct 19 2026 update: VPN → vCenter → execInstalledOnly disabled on ESXi → offline credential dump from a DC VMDK).
- Real payload(s): https://knowledge.broadcom.com/external/article/318905/detected-an-invalid-snapshot-configurati.html; https://knowledge.broadcom.com/external/article/438753/quiesced-snapshot-creation-succeeds-but.html; https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1005/esxi_vm_download/esxi_vm_download.log; https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1673/esxi_vm_discovery/esxi_vm_discovery.log
- Fields used (confirmed by `| fieldsummary` on the first fixture in local Splunk, plus _raw rex): `_raw`, `sub`, `user`
- Licences: PaloAltoNetworks/Splunk-Apps samples ISC; splunk/attack_data Apache-2.0; Broadcom KB lines cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR.

## Local Splunk replay
Splunk Enterprise 9.4.1 on the agent box. `vmw-syslog` with no VMware add-on (Splunkbase login needed). The rule uses only _raw terms and rex, so no add-on field is needed. Lookup `dac_domain_controller_vms` created locally with rows VM_Name,true and Test2,true for the test. Fixtures indexed with `splunk add oneshot`, rule query run unchanged via REST (`search index=dac2 source="*<fixture>" <query>`, earliest=0).

| Fixture | Label | Expect alert | Rows | Result | Source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://knowledge.broadcom.com/external/article/438753/quiesced-snapshot-creation-succeeds-but.html | none (real) |
| malicious_1_real.json | malicious | True | 1 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1005/esxi_vm_download/esxi_vm_download.log | none (real) |
| malicious_2_derived.json | malicious | True | 1 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1005/esxi_vm_download/esxi_vm_download.log | VM folder/disk renamed Test2 -> DC01 (matches default name pattern, not the lookup) |
| near_miss_3_real.json | near_miss | False | 0 | PASS | https://knowledge.broadcom.com/external/article/318905/detected-an-invalid-snapshot-configurati.html | none (real) |
| near_miss_4_derived.json | near_miss | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1005/esxi_vm_download/esxi_vm_download.log | downloaded file changed from Test2.vmdk to Test2.vmx (config file, not a disk) |
| near_miss_5_derived.json | near_miss | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1005/esxi_vm_download/esxi_vm_download.log | VM renamed Test2 -> APP01 (not in lookup, not matching DC pattern) |
| benign_6_real.json | benign | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1673/esxi_vm_discovery/esxi_vm_discovery.log | none (real) |

First alert row: `{"host": "grok-bot-vm-322405535", "vm_name": "VM_Name", "dc_match": "lookup", "count": "1", "actions": "snapshot_create", "snapshot_names": "VM Snapshot YYYY-MM-DD", "users": "vpxuser:Domain\\User", "first_seen": "1792643245", "last_seen": "1792643245"}`

## Ponytail review
Ponytail pass (2026-10-22). Findings naming a fixture were replayed in local Splunk against the pre-fix query (rows quoted); others are reasoned.
- F1 (fidelity): failing input: `near_miss_4_derived.json`: download of Test2/Test2.vmx (config file) from a lookup-listed DC. Without the .vmdk filter it returned 1 row. Fix: disk_download only when file_path ends in .vmdk. 0 rows.
- F2 (correctness): failing input: `near_miss_3_real.json` (Broadcom KB 318905): the lines "Create Snapshot translated error..." and "Create Snapshot message: ..." also contain "Create Snapshot". Fix: Base term and rex require "Create Snapshot:" followed by the name; error lines never produce snapshot_name. (Reasoned; the KB lines also have an empty VM path, so they produce 0 rows either way.)
- F3 (config): failing input: `malicious_2_derived.json` DC01 is not in the lookup. Fix: Default dc_name_pattern catches common DC names; dc_match column says which source matched so tuning is visible.
- F4 (load): failing input: Many hostd lines per snapshot. Fix: stats by host, vm_name.

## Bypass table
| Attacker variation | Result |
|---|---|
| Attach the DC VMDK to another (attacker) VM via reconfigure | MISSED: no real hostd/vpxd log line for disk hot-add found; not built |
| Copy the VMDK via SSH/SCP or vmkfstools in the ESXi shell | MISSED here; shell.log commands not covered |
| DC named outside the lookup and pattern | MISSED: keep the lookup current (CMDB export) |
| vCenter-only logging (vmware:vclog) without ESXi hostd | MISSED: no real vclog snapshot event sample |

## False-positive decisions
- Backup products (snapshot-based image backup of DCs runs nightly; the KB example user is vpxuser, i.e. vCenter-driven: https://knowledge.broadcom.com/external/article/438753/quiesced-snapshot-creation-succeeds-but.html). Exclude your backup service account and schedule.
- Admin snapshot before patching a DC

## Unverified ideas
- Broadcom KB lines have placeholders (YYYY, #####) as published; timestamps parse to index time.
- The lookup dac_domain_controller_vms ships only as a template: `lookups/dac_domain_controller_vms.csv.example` (fake EXAMPLE-* rows). Deploy: copy to `dac_domain_controller_vms.csv`, fill with your DC VM names, upload via Settings > Lookups > Lookup table files (or the app's `lookups/` dir) and share with the app. Steps in `lookups/README.md`. The rule errors in Splunk until it is deployed.
- hostd user= field in real vCenter-driven snapshots is vpxuser:<domain user> per KB 438753; direct ESXi users not seen.
- telemetry_validated stays false.

## Tests
`tests/cases/DAC-VMW-0038/`: `_real` = verbatim real events/lines; `_derived` = minimal documented edits (see `modification`). Not run by CI.

## Reviewer status: pending human approval
