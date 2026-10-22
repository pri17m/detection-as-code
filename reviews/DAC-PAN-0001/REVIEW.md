# REVIEW — DAC-PAN-0001 GlobalProtect gateway-connected session with CVE-2026-0257 exploit fingerprint

## Coverage before
No Palo Alto rule on main (no pan:* sourcetype in detections/, grep at main a936b38).

## Coverage after
Behavior: a successful GlobalProtect gateway-connected session whose client reports values Unit 42 published for CVE-2026-0257 exploitation: placeholder host IDs (aa:bb:cc:dd:ee:ff, 00:11:22:33:44:55), PoC device names (WINDOWS-LAPTOP-001, DESKTOP-GP01, GP-CLIENT), the PoC hard-coded OS string "Microsoft Windows 10 Pro 64-bit" (real clients log "Microsoft Windows 10 Pro , 64-bit"), or a Unit 42 pre-PoC source IP. Used by Qilin and INC to bypass GlobalProtect auth/MFA. Raw Strata Logging Service (HTTPS) field names, sourcetype pan:firewall_cloud. Not telemetry_validated.

## ATT&CK mapping check (v19.2)
T1190; T1133 → initial-access, persistence. Checked against attack-stix-data enterprise-attack-19.2.json (present, not revoked/deprecated, tactics from kill_chain_phases).

## Source and fields
- Threat context: Unit 42, https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/ (Oct 19 2026 update: VPN → vCenter → execInstalledOnly disabled on ESXi → offline credential dump from a DC VMDK).
- Real payload(s): https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json
- Fields used (confirmed by `| fieldsummary` on the first fixture in local Splunk, plus _raw rex): `DeviceName`, `EndpointDeviceName`, `EndpointOSVersion`, `EventIDValue`, `EventStatus`, `GlobalProtectClientVersion`, `HostID`, `LogType`, `Portal`, `PrivateIPv4`, `PublicIPv4`, `SourceUserName`
- Licences: PaloAltoNetworks/Splunk-Apps samples ISC; splunk/attack_data Apache-2.0; Broadcom KB lines cited by URL. THIRD_PARTY_NOTICES.md not edited in this one-rule PR.

## Local Splunk replay
Splunk Enterprise 9.4.1 on the agent box. `pan:firewall_cloud` configured as in the Palo Alto Splunk add-on props.conf (KV_MODE=json, TIME_PREFIX TimeGenerated); the add-on field aliases were not installed, so the rule uses raw JSON keys only. Fixtures indexed with `splunk add oneshot`, rule query run unchanged via REST (`search index=dac2 source="*<fixture>" <query>`, earliest=0).

| Fixture | Label | Expect alert | Rows | Result | Source | Modification |
|---|---|---|---|---|---|---|
| malicious_0_derived.json | malicious | True | 1 | PASS | https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json | EndpointOSVersion set to the PoC hard-coded value "Microsoft Windows 10 Pro 64-bit" published by Unit 42 (https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/) |
| malicious_1_derived.json | malicious | True | 1 | PASS | https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json | HostID and EndpointDeviceName set to Unit 42 published suspicious values aa:bb:cc:dd:ee:ff / DESKTOP-GP01 |
| malicious_2_derived.json | malicious | True | 1 | PASS | https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json | PublicIPv4 set to Unit 42 published pre-PoC IP 23.128.228[.]6 |
| near_miss_3_real.json | near_miss | False | 0 | PASS | https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json | none (real) |
| benign_4_real.json | benign | False | 0 | PASS | https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json | none (real) |
| near_miss_5_derived.json | near_miss | False | 0 | PASS | https://github.com/PaloAltoNetworks/Splunk-Apps/blob/ae653b335e633895c1dcc796139d0c21c4c34696/demo/samples/pan_firewall_cloud_globalprotect.json | PoC values on a gateway-auth event with EventStatus=failure (not a connected session) |

First alert row: `{"_time": "2026-10-22 09:57:25.000 IST", "DeviceName": "GPGW_193480_us-east-2_649068640", "Portal": "GlobalProtect_External_Gateway", "SourceUserName": "EWard@alvisofincorp.com", "user_without_domain": "0", "PublicIPv4": "40.122.193.74", "PrivateIPv4": "172.31.68.22", "HostID": "0a6c5783-07a4-488d-8e1e-8d45b2b1354c", "EndpointDeviceName": "Mike-HIP-2", "EndpointOSVersion": "Microsoft Windows 10 Pro 64-bit", "GlobalProtectClientVersion": "5.2.8", "fp_host_id": "0", "fp_device_name": "0", "fp_os_string": "1", "fp_ioc_ip": "0", "fingerprint_hits": "1"}`

## Ponytail review
Ponytail pass (2026-10-22). Findings naming a fixture were replayed in local Splunk against the pre-fix query (rows quoted); others are reasoned.
- F1 (fidelity): failing input: `near_miss_3_real.json`: the real vendor-sample gateway-connected event from a genuine client, EndpointOSVersion "Microsoft Windows 10 Pro , 64-bit". A loose match(EndpointOSVersion,"Windows 10 Pro.*64-bit") returned 1 row. Fix: Exact equality on the PoC string "Microsoft Windows 10 Pro 64-bit" (no " ,"), the exact value Unit 42 published. Replay now 0 rows.
- F2 (fidelity): failing input: `near_miss_5_derived.json`: PoC host ID on a gateway-auth failure. Without the EventIDValue=gateway-connected EventStatus=success scope it returned 1 row. Fix: Scope to successful gateway-connected, as Unit 42 advises ("successful gateway-connected events"). 0 rows.
- F3 (correctness): failing input: HostID values may arrive upper-case; device names case varies. Fix: lower(HostID) / upper(EndpointDeviceName) before comparison.
- F4 (every line needed): failing input: Unit 42 also lists source_user_info.domain empty. The HTTPS-format sample has no domain field (keys checked: SourceUserName only). Fix: Emitted only as an informational column user_without_domain (SourceUserName without @ or \), not used to alert.

## Bypass table
| Attacker variation | Result |
|---|---|
| Patched PoC with a randomised host ID, device name and real OS string | MISSED: fingerprint-only rule; pair with VPN-session anomaly hunting |
| Exploit from an IP not in the Unit 42 list | Still caught if any client fingerprint remains |
| Logs forwarded as PAN-OS syslog (sourcetype pan:globalprotect) instead of Strata/Cortex HTTPS JSON | MISSED: different field names; no real pan:globalprotect GLOBALPROTECT-format sample found |
| Attacker only probes (portal-prelogin) without connecting | MISSED by design; Unit 42 says most probes did not connect |

## False-positive decisions
- A legitimate client whose device name happens to be GP-CLIENT or DESKTOP-GP01 (generic names; Unit 42 lists them as suspicious, not conclusive: https://unit42.paloaltonetworks.com/active-exploitation-of-pan-os-cve-2026-0257/)
- Lab or test VMs cloned with a placeholder MAC as host ID

## Unverified ideas
- No real exploit log line is public. Malicious fixtures are the real vendor sample gateway-connected event with fields set to Unit 42 published values (labelled derived).
- Field-name mapping of Unit 42 names (endpoint_os_version, source_user_info.domain) to HTTPS names (EndpointOSVersion, no domain field) is from the PAN Strata log reference; the domain field is not in the sample.
- IOC IPs age quickly; they are a flag, not the core logic.
- pan:firewall_cloud is the Splunk PAN add-on sourcetype for this format (props.conf + eventgen.conf in the PAN Splunk-Apps repo); it is not in config/sourcetype_map.yaml.
- telemetry_validated stays false.

## Tests
`tests/cases/DAC-PAN-0001/`: `_real` = verbatim real events/lines; `_derived` = minimal documented edits (see `modification`). Not run by CI.

## Reviewer status: pending human approval
