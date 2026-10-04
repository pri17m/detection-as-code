# SigmaHQ Import Shortlist — Wave 1 (Windows)

**Source:** https://github.com/SigmaHQ/sigma

**Shortlist count:** 139


Prefer macros from `config/sourcetype_map.yaml`.

**NEEDS_FIELD_GROUNDING:** 4662/5145/4104/4886/5136/Sysmon 4/8/16/17–21/25.

**TELEMETRY_GAP_CHANNEL:** TaskScheduler/WMI/RDP/CA — do not invent keys.


### builtin/security (30) — windows_security

- `rules/windows/builtin/security/account_management/win_security_admin_rdp_login.yml`
- `rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml`
- `rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml`
- `rules/windows/builtin/security/account_management/win_security_rdp_localhost_login.yml`
- `rules/windows/builtin/security/account_management/win_security_successful_external_remote_rdp_login.yml`
- `rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml`
- `rules/windows/builtin/security/account_management/win_security_susp_wmi_login.yml`
- `rules/windows/builtin/security/win_security_account_backdoor_dcsync_rights.yml`
- `rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml`
- `rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability.yml`
- `rules/windows/builtin/security/win_security_adcs_certificate_template_configuration_vulnerability_eku.yml`
- `rules/windows/builtin/security/win_security_admin_share_access.yml`
- `rules/windows/builtin/security/win_security_audit_log_cleared.yml`
- `rules/windows/builtin/security/win_security_default_domain_gpo_modification.yml`
- `rules/windows/builtin/security/win_security_disable_event_auditing.yml`
- `rules/windows/builtin/security/win_security_disable_event_auditing_critical.yml`
- `rules/windows/builtin/security/win_security_gpo_scheduledtasks.yml`
- `rules/windows/builtin/security/win_security_hidden_user_creation.yml`
- `rules/windows/builtin/security/win_security_impacket_psexec.yml`
- `rules/windows/builtin/security/win_security_impacket_secretdump.yml`
- `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_mshta_services_security.yml`
- `rules/windows/builtin/security/win_security_invoke_obfuscation_via_use_rundll32_services_security.yml`
- `rules/windows/builtin/security/win_security_kerberoasting_activity.yml`
- `rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml`
- `rules/windows/builtin/security/win_security_kerberos_coercion_via_dns_object.yml`
- `rules/windows/builtin/security/win_security_lsass_access_non_system_account.yml`
- `rules/windows/builtin/security/win_security_metasploit_or_impacket_smb_psexec_service_install.yml`
- `rules/windows/builtin/security/win_security_not_allowed_rdp_access.yml`
- `rules/windows/builtin/security/win_security_powershell_script_installed_as_service.yml`
- `rules/windows/builtin/security/win_security_rdp_reverse_tunnel.yml`

### builtin/system (6) — windows_system

- `rules/windows/builtin/system/microsoft_windows_certification_authority/win_system_adcs_enrollment_request_denied.yml`
- `rules/windows/builtin/system/microsoft_windows_eventlog/win_system_susp_eventlog_cleared.yml`
- `rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_cert_use_no_strong_mapping.yml`
- `rules/windows/builtin/system/microsoft_windows_kerberos_key_distribution_center/win_system_kdcsvc_tgs_no_suitable_encryption_key_found.yml`
- `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_mshta_services.yml`
- `rules/windows/builtin/system/service_control_manager/win_system_invoke_obfuscation_via_use_rundll32_services.yml`

### create_remote_thread (3) — windows_sysmon (EID8)

- `rules/windows/create_remote_thread/create_remote_thread_win_powershell_lsass.yml`
- `rules/windows/create_remote_thread/create_remote_thread_win_powershell_susp_targets.yml`
- `rules/windows/create_remote_thread/create_remote_thread_win_susp_password_dumper_lsass.yml`

### file (6) — windows_sysmon (EID11)

- `rules/windows/file/file_access/file_access_win_susp_gpo_files.yml`
- `rules/windows/file/file_delete/file_delete_win_delete_exchange_powershell_logs.yml`
- `rules/windows/file/file_delete/file_delete_win_delete_powershell_command_history.yml`
- `rules/windows/file/file_event/file_event_win_impacket_file_indicators.yml`
- `rules/windows/file/file_event/file_event_win_lsass_default_dump_file_names.yml`
- `rules/windows/file/file_event/file_event_win_lsass_shtinkering.yml`

### image_load (8) — windows_sysmon (EID7)

- `rules/windows/image_load/image_load_dll_amsi_suspicious_process.yml`
- `rules/windows/image_load/image_load_dll_comsvcs_load_renamed_version_by_rundll32.yml`
- `rules/windows/image_load/image_load_dll_dbghelp_dbgcore_unsigned_load.yml`
- `rules/windows/image_load/image_load_lsass_unsigned_image_load.yml`
- `rules/windows/image_load/image_load_office_powershell_dll_load.yml`
- `rules/windows/image_load/image_load_rundll32_remote_share_load.yml`
- `rules/windows/image_load/image_load_scrcons_wmi_scripteventconsumer.yml`
- `rules/windows/image_load/image_load_side_load_dbghelp.yml`

### network_connection (8) — windows_sysmon (EID3)

- `rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml`
- `rules/windows/network_connection/net_connection_win_rdp_outbound_over_non_standard_tools.yml`
- `rules/windows/network_connection/net_connection_win_rdp_reverse_tunnel.yml`
- `rules/windows/network_connection/net_connection_win_rdp_to_http.yml`
- `rules/windows/network_connection/net_connection_win_regsvr32_network_activity.yml`
- `rules/windows/network_connection/net_connection_win_rundll32_net_connections.yml`
- `rules/windows/network_connection/net_connection_win_susp_outbound_kerberos_connection.yml`
- `rules/windows/network_connection/net_connection_win_susp_remote_powershell_session.yml`

### powershell (18) — windows_powershell_operational

- `rules/windows/powershell/powershell_classic/posh_pc_abuse_nslookup_with_dns_records.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_delete_volume_shadow_copies.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_download_via_webclient.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_exe_calling_ps.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_powercat.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_remote_powershell_session.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_remotefxvgpudisablement_abuse.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_renamed_powershell.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_susp_get_nettcpconnection.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_susp_zip_compress.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_tamper_windows_defender_set_mp.yml`
- `rules/windows/powershell/powershell_classic/posh_pc_wsman_com_provider_no_powershell.yml`
- `rules/windows/powershell/powershell_module/posh_pm_active_directory_module_dll_import.yml`
- `rules/windows/powershell/powershell_module/posh_pm_alternate_powershell_hosts.yml`
- `rules/windows/powershell/powershell_module/posh_pm_bad_opsec_artifacts.yml`
- `rules/windows/powershell/powershell_module/posh_pm_clear_powershell_history.yml`
- `rules/windows/powershell/powershell_module/posh_pm_decompress_commands.yml`

### process_access (11) — windows_sysmon (EID10)

- `rules/windows/process_access/proc_access_win_hktl_handlekatz_lsass_access.yml`
- `rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml`
- `rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml`
- `rules/windows/process_access/proc_access_win_lsass_memdump.yml`
- `rules/windows/process_access/proc_access_win_lsass_python_based_tool.yml`
- `rules/windows/process_access/proc_access_win_lsass_remote_access_trough_winrm.yml`
- `rules/windows/process_access/proc_access_win_lsass_seclogon_access.yml`
- `rules/windows/process_access/proc_access_win_lsass_susp_access_flag.yml`
- `rules/windows/process_access/proc_access_win_lsass_werfault.yml`
- `rules/windows/process_access/proc_access_win_lsass_whitelisted_process_names.yml`
- `rules/windows/process_access/proc_access_win_susp_dbgcore_dbghelp_load.yml`

### process_creation (37) — windows_sysmon (EID1)

- `rules/windows/process_creation/proc_creation_win_amsi_registry_tampering.yml`
- `rules/windows/process_creation/proc_creation_win_autorun_registry_modified_via_wmic.yml`
- `rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml`
- `rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.yml`
- `rules/windows/process_creation/proc_creation_win_bitsadmin_download_file_sharing_domains.yml`
- `rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.yml`
- `rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_targetfolder.yml`
- `rules/windows/process_creation/proc_creation_win_bitsadmin_download_susp_extensions.yml`
- `rules/windows/process_creation/proc_creation_win_certutil_certificate_installation.yml`
