# REVIEW — DAC-VMW-0015 ESXi encryption or execInstalledOnly enforcement changed

## Coverage before
DAC-VMW-0015 (main a936b38) matches any esxcli system settings encryption set with -e/-s/--require-secure-boot/execInstalledOnly/--require-exec-installed-only, whatever the value. It alerts on enabling, and misses mis-typed --require-exec* flags.

## Coverage after
Detects esxcli system settings encryption set that DISABLES secure boot or execInstalledOnly enforcement (value 0/F/false, including mis-typed --require-exec* flags), excluding shell-echo lines. Enabling the controls no longer alerts. Disabling those checks lets unsigned code run on the host (abused in CVE-2026-0257 intrusions per Unit 42).

## ATT&CK mapping check (v19.2)
T1685 → defense-impairment. Checked against attack-stix-data enterprise-attack-19.2.json (present, not revoked/deprecated, tactics from kill_chain_phases).

## Source and fields
- Threat context: Unit 42, https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/ (Oct 19 2026 update: VPN → vCenter → execInstalledOnly disabled on ESXi → offline credential dump from a DC VMDK).
- Real payload(s): https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_encryption_modified/esxi_encryption_modified.log; https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1673/esxi_vm_discovery/esxi_vm_discovery.log
- Fields used (confirmed by `| fieldsummary` on the first fixture in local Splunk, plus _raw rex): `Message`, `_raw`
- Licences: PaloAltoNetworks/Splunk-Apps samples ISC; splunk/attack_data Apache-2.0; Broadcom KB lines cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR.

## Local Splunk replay
Splunk Enterprise 9.4.1 on the agent box. `vmw-syslog` with no VMware add-on (Splunkbase login needed). The rule uses the add-on `Message` field, approximated locally with EXTRACT `\S+\[\d+\]:\s(?<Message>.*)$`. Lookup `dac_domain_controller_vms` created locally with rows VM_Name,true and Test2,true for the test. Fixtures indexed with `splunk add oneshot`, rule query run unchanged via REST (`search index=dac2 source="*<fixture>" <query>`, earliest=0).

| Fixture | Label | Expect alert | Rows | Result | Source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_real.json | malicious | True | 1 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_encryption_modified/esxi_encryption_modified.log | none (real) |
| near_miss_1_real.json | near_miss | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_encryption_modified/esxi_encryption_modified.log | none (real) |
| near_miss_2_real.json | near_miss | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562/esxi_encryption_modified/esxi_encryption_modified.log | none (real) |
| benign_3_real.json | benign | False | 0 | PASS | https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1673/esxi_vm_discovery/esxi_vm_discovery.log | none (real) |

First alert row: `{"dest": "localhost.localdomain", "user": "root", "count": "6", "firstTime": "1783430562", "lastTime": "1783430621", "command": [" esxcli system settings encryption set --require-exec-install-only=0", " esxcli system settings encryption set --require-exec-installed-only=0", " esxcli system settings encryption set --require-exec=install-only=0", " esxcli system settings encryption set --require-secure-boot=0", " esxcli system settings encryption set -s 0", " esxcli system settings encryption set -s 0 -e 0"]}`

## Ponytail review
Ponytail pass (2026-10-22). Findings naming a fixture were replayed in local Splunk against the pre-fix query (rows quoted); others are reasoned.
- F1 (fidelity): failing input: `near_miss_1_real.json` (attack_data esxi_encryption_modified): "--require-exec-installed-only=1" x2 and "-e 1" (enabling the controls). The main version returned 1 row with all 3. Fix: where match(command, disable values only: =0|f|false or -e/-s 0|f|false). 0 rows.
- F2 (coverage): failing input: `malicious_0_real.json`: "--require-exec-install-only=0" and "--require-exec=install-only=0". The main version returned 4 of the 6 disable lines. Fix: Base filter "*require-exec*" and regex --require-exec\S*=0. Replay now 6 of 6.
- F3 (fidelity): failing input: `near_miss_2_real.json`: bare "set -s", "set --mode", "set" (no value). Fix: No value means no change; regex needs a value. 0 rows.

## Bypass table
| Attacker variation | Result |
|---|---|
| esxcli system settings kernel set -s execInstalledOnly -v FALSE (boot option, Broadcom docs https://knowledge.broadcom.com/external/article/320681/the-spherelet-service-is-failing-to-star.html) | MISSED: no real shell.log line with that command found; not built |
| esxcli system settings advanced set -o /User/execInstalledOnly -i 0 | MISSED: no real log line found |
| localcli instead of esxcli | MISSED: query requires "system settings encryption set" via esxcli line text; localcli lines unseen |

## False-positive decisions
- Planned maintenance or host rebuilds. Confirm the actor and change window.

## Unverified ideas
- Local test approximated the VMware add-on Message field with EXTRACT `\S+\[\d+\]:\s(?<Message>.*)$` (add-on not installable without Splunkbase login).
- Whether ESXi accepts -e/-s with f/false is not confirmed; Broadcom docs show =T/=F and 0/1 in the attack_data payload.
- telemetry_validated stays false.

## Tests
`tests/cases/DAC-VMW-0015/`: `_real` = verbatim real events/lines; `_derived` = minimal documented edits (see `modification`). Not run by CI.

## Reviewer status: pending human approval
