#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any, Dict, List

import yaml


def _slug(s: str) -> str:
    s = s.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    return s.strip("-")[:80] or "rule"


def _dump_yaml(obj: Dict[str, Any]) -> str:
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True)


def _det(
    *,
    id_: str,
    title: str,
    description: str,
    platforms: List[str],
    sourcetypes: List[str],
    tactics: List[str],
    techniques: List[str],
    severity: str,
    false_positives: List[str],
    references: List[str],
    required_fields: List[str],
    query: Dict[str, str] | None = None,
    sigma: Dict[str, str] | None = None,
    tags: List[str] | None = None,
) -> Dict[str, Any]:
    obj: Dict[str, Any] = {
        "id": id_,
        "title": title,
        "description": description,
        "author": "DaC",
        "status": "experimental",
        "platforms": platforms,
        "sourcetypes": sourcetypes,
        "mitre": {"tactics": tactics, "techniques": techniques},
        "severity": severity,
        "false_positives": false_positives,
        "references": references,
        "telemetry_validated": False,
        "required_fields": required_fields,
    }
    if query:
        obj["query"] = {k: v.strip() + "\n" for k, v in query.items()}
    if sigma:
        obj["sigma"] = sigma
    if tags:
        obj["tags"] = tags
    return obj


def write_defender_pack(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    n = 1

    def did() -> str:
        nonlocal n
        s = f"DAC-MDE-{n:04d}"
        n += 1
        return s

    rules: List[Dict[str, Any]] = []

    rules.append(
        _det(
            id_=did(),
            title="PowerShell encoded command on endpoint",
            description="Detects PowerShell executions using EncodedCommand, a common obfuscation and payload staging pattern.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["execution"],
            techniques=["T1059.001"],
            severity="high",
            false_positives=["Legitimate admin scripts may use encoded commands."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "ProcessCommandLine", "FileName", "InitiatingProcessFileName"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-enc","-encodedcommand")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Office spawning shell or script interpreter",
            description="Detects Office processes spawning cmd/powershell/wscript/cscript; common in macro-based initial execution.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["execution"],
            techniques=["T1204"],
            severity="high",
            false_positives=["Legitimate add-ins or automation workflows."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "InitiatingProcessFileName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Suspicious LOLBin: regsvr32 remote scriptlet",
            description="Detects regsvr32 being used with remote URLs or scriptlets, a signed-binary proxy execution pattern.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["defense-evasion"],
            techniques=["T1218.010"],
            severity="high",
            false_positives=["Rare legitimate use; validate command line and source."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName =~ "regsvr32.exe"
| where ProcessCommandLine has_any ("http://","https://",".sct","scrobj.dll")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="LSASS access by non-security tooling",
            description="Detects potential credential dumping by identifying processes accessing LSASS or creating memory dumps.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["credential-access"],
            techniques=["T1003"],
            severity="critical",
            false_positives=["Security tools may legitimately access LSASS; tune by signer/allowlists."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where ProcessCommandLine has_any ("lsass.exe","comsvcs.dll","minidump","procdump")
| where FileName in~ ("rundll32.exe","procdump.exe","taskmgr.exe","werfault.exe","powershell.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Defense evasion: disable firewall via netsh",
            description="Detects attempts to disable Windows firewall via netsh.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["defense-evasion"],
            techniques=["T1562.004"],
            severity="high",
            false_positives=["Legitimate troubleshooting by admins; tune by accounts/devices."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName =~ "netsh.exe"
| where ProcessCommandLine has_all ("advfirewall","state","off")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
"""
            },
        )
    )

    # Add a few additional starter rules (network + persistence + scheduled tasks)
    rules.append(
        _det(
            id_=did(),
            title="Scheduled task creation via schtasks",
            description="Detects schtasks creating or modifying scheduled tasks, commonly used for persistence.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["persistence"],
            techniques=["T1053.005"],
            severity="medium",
            false_positives=["Legitimate admin automation and software updaters."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create","/change","/run")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Persistence: service creation via sc.exe",
            description="Detects service creation using sc.exe, a common persistence method.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["persistence"],
            techniques=["T1543.003"],
            severity="high",
            false_positives=["Legitimate installs and admin operations."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Rundll32 suspicious execution (signed proxy)",
            description="Detects rundll32 with suspicious arguments such as javascript/vbscript or DLL entrypoint patterns.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["defense-evasion"],
            techniques=["T1218.011"],
            severity="medium",
            false_positives=["Some control panel applets; tune by allowlists."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("javascript:","vbscript:",".dll,", "comsvcs.dll")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Certutil used to download or decode",
            description="Detects certutil used with urlcache/decode flags often used for tool transfer.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["command-and-control"],
            techniques=["T1105"],
            severity="medium",
            false_positives=["Legitimate certificate operations."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table"],
            required_fields=["DeviceName", "FileName", "ProcessCommandLine"],
            query={
                "defender": r"""
DeviceProcessEvents
| where FileName =~ "certutil.exe"
| where ProcessCommandLine has_any ("-urlcache","-decode","-encode")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="Suspicious outbound connections from scripting engines",
            description="Detects endpoints making outbound connections from scripting engines and common LOLBins; useful for staging/exfil triage.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["command-and-control"],
            techniques=["T1105"],
            severity="medium",
            false_positives=["Browsers and legitimate updaters; tune by process allowlist."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-devicenetworkevents-table"],
            required_fields=["DeviceName", "InitiatingProcessFileName", "RemoteUrl", "RemoteIP"],
            query={
                "defender": r"""
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
"""
            },
        )
    )

    # Ensure we have 12 rules (add 2 more basic ones)
    rules.append(
        _det(
            id_=did(),
            title="Registry Run key created or modified",
            description="Detects modifications to common Run key paths on endpoints which can indicate persistence.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["persistence"],
            techniques=["T1547.001"],
            severity="medium",
            false_positives=["Legitimate software startup entries."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-deviceregistryevents-table"],
            required_fields=["DeviceName", "RegistryKey", "RegistryValueName"],
            query={
                "defender": r"""
DeviceRegistryEvents
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
    or RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\RunOnce"
| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
"""
            },
        )
    )

    rules.append(
        _det(
            id_=did(),
            title="RDP logon events spike (DeviceLogonEvents)",
            description="Detects spikes in RDP (remote interactive) logon events on an endpoint; useful for lateral movement triage.",
            platforms=["defender"],
            sourcetypes=["mde:advanced_hunting"],
            tactics=["lateral-movement"],
            techniques=["T1021.001"],
            severity="medium",
            false_positives=["Jump hosts and IT admin behavior."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender/advanced-hunting-devicelogonevents-table"],
            required_fields=["DeviceName", "AccountName", "LogonType"],
            query={
                "defender": r"""
DeviceLogonEvents
| where LogonType has_any ("RemoteInteractive","RemoteInteractiveSession")
| summarize count() as logons, dcount(AccountName) as users by DeviceName, bin(Timestamp, 1h)
| where logons >= 20 and users >= 5
"""
            },
        )
    )

    for r in rules:
        fname = f"{r['id']}-{_slug(r['title'])}.yaml"
        (out_dir / fname).write_text(_dump_yaml(r), encoding="utf-8")

    return len(rules)


def write_crowdstrike_pack(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    n = 1

    def cid() -> str:
        nonlocal n
        s = f"DAC-CS-{n:04d}"
        n += 1
        return s

    # These are intentionally expressed as portable "Falcon IOA-like" patterns.
    # Adopters translate into Custom IOAs / correlation rules depending on their Falcon SKU.
    rules: List[Dict[str, Any]] = []

    def cs_query(pattern: str) -> str:
        return f"falcon_ioa_pattern: {pattern}"

    rules.append(
        _det(
            id_=cid(),
            title="Falcon: PowerShell encoded command",
            description="Detects PowerShell executions using encoded command patterns (Custom IOA candidate).",
            platforms=["crowdstrike"],
            sourcetypes=["falcon:process"],
            tactics=["execution"],
            techniques=["T1059.001"],
            severity="high",
            false_positives=["Legitimate automation; tune by parent process or signer."],
            references=["https://www.crowdstrike.com/"],
            required_fields=["ImageFileName", "CommandLine", "ParentBaseFileName"],
            query={"crowdstrike": cs_query('ImageFileName in ["powershell.exe","pwsh.exe"] AND CommandLine CONTAINS_ANY ["-enc","-encodedcommand"]')},
        )
    )

    rules.append(
        _det(
            id_=cid(),
            title="Falcon: Office spawning shell",
            description="Detects Office processes spawning cmd/powershell/script interpreters.",
            platforms=["crowdstrike"],
            sourcetypes=["falcon:process"],
            tactics=["execution"],
            techniques=["T1204"],
            severity="high",
            false_positives=["Legitimate add-ins; tune by user/group and doc origin."],
            references=["https://www.crowdstrike.com/"],
            required_fields=["ImageFileName", "ParentBaseFileName", "CommandLine"],
            query={"crowdstrike": cs_query('ParentBaseFileName in ["winword.exe","excel.exe","powerpnt.exe","outlook.exe"] AND ImageFileName in ["cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe"]')},
        )
    )

    for title, tech, patt in [
        ("Falcon: regsvr32 remote scriptlet", "T1218.010", 'ImageFileName="regsvr32.exe" AND CommandLine CONTAINS_ANY ["http://","https://",".sct","scrobj.dll"]'),
        ("Falcon: mshta remote execution", "T1218.005", 'ImageFileName="mshta.exe" AND CommandLine CONTAINS_ANY ["http://","https://","javascript:","vbscript:"]'),
        ("Falcon: rundll32 suspicious execution", "T1218.011", 'ImageFileName="rundll32.exe" AND CommandLine CONTAINS_ANY ["javascript:","vbscript:","comsvcs.dll",".dll,"]'),
        ("Falcon: schtasks persistence", "T1053.005", 'ImageFileName="schtasks.exe" AND CommandLine CONTAINS_ANY ["/create","/change"]'),
        ("Falcon: sc.exe service creation", "T1543.003", 'ImageFileName="sc.exe" AND CommandLine CONTAINS "create"'),
        ("Falcon: vssadmin delete shadows", "T1490", 'ImageFileName="vssadmin.exe" AND CommandLine CONTAINS_ALL ["delete","shadows"]'),
        ("Falcon: wevtutil clear logs", "T1070.001", 'ImageFileName="wevtutil.exe" AND CommandLine CONTAINS_ALL ["cl"]'),
        ("Falcon: netsh firewall off", "T1562.004", 'ImageFileName="netsh.exe" AND CommandLine CONTAINS_ALL ["advfirewall","state","off"]'),
        ("Falcon: certutil download/decode", "T1105", 'ImageFileName="certutil.exe" AND CommandLine CONTAINS_ANY ["-urlcache","-decode"]'),
        ("Falcon: bitsadmin transfer", "T1105", 'ImageFileName="bitsadmin.exe" AND CommandLine CONTAINS_ANY ["/transfer","/addfile"]'),
    ]:
        rules.append(
            _det(
                id_=cid(),
                title=title,
                description="Starter Falcon IOA/correlation rule candidate.",
                platforms=["crowdstrike"],
                sourcetypes=["falcon:process"],
                tactics=["execution", "defense-evasion"],
                techniques=[tech],
                severity="medium",
                false_positives=["Tune to your environment and allowlist known tooling."],
                references=["https://www.crowdstrike.com/"],
                required_fields=["ImageFileName", "CommandLine", "ParentBaseFileName"],
                query={"crowdstrike": cs_query(patt)},
            )
        )

    for r in rules:
        fname = f"{r['id']}-{_slug(r['title'])}.yaml"
        (out_dir / fname).write_text(_dump_yaml(r), encoding="utf-8")

    return len(rules)


def write_sigma_batch(sigma_dir: Path, splunk_out_dir: Path) -> int:
    sigma_dir.mkdir(parents=True, exist_ok=True)
    splunk_out_dir.mkdir(parents=True, exist_ok=True)

    batch: List[Dict[str, Any]] = []
    converted: List[Dict[str, Any]] = []

    # Normalized sigma-like sources (metadata objects referencing upstream via sigma.path)
    # plus a first batch of "Sigma→Splunk" implementations.
    sigma_sources = [
        {
            "title": "Suspicious PowerShell EncodedCommand",
            "tech": "T1059.001",
            "sigma_path": "SigmaHQ:windows/process_creation/powershell_encodedcommand.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"(powershell\\.exe|pwsh\\.exe).*(-enc|-encodedcommand)\\s+[a-za-z0-9+/=]{50,}")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Office spawns command interpreter",
            "tech": "T1204",
            "sigma_path": "SigmaHQ:windows/process_creation/office_spawns_shell.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval proc=lower(coalesce(NewProcessName, process_path, Image))
| eval parent=lower(coalesce(ParentProcessName, Creator_Process_Name, parent_process_name))
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(parent,"(winword|excel|powerpnt|outlook)\\.exe") AND match(proc,"(cmd|powershell|pwsh|wscript|cscript)\\.exe")
| stats count values(cmd) as commands values(parent) as parents by host, SubjectUserName
""",
        },
        {
            "title": "Regsvr32 remote scriptlet",
            "tech": "T1218.010",
            "sigma_path": "SigmaHQ:windows/process_creation/regsvr32_remote_sct.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"regsvr32\\.exe.*(http|https).*\\.sct") OR match(cmd,"regsvr32\\.exe.*scrobj\\.dll")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Mshta remote execution",
            "tech": "T1218.005",
            "sigma_path": "SigmaHQ:windows/process_creation/mshta_remote.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"mshta\\.exe.*(http|https|javascript:|vbscript:)") 
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Rundll32 comsvcs minidump",
            "tech": "T1003",
            "sigma_path": "SigmaHQ:windows/process_creation/rundll32_comsvcs_minidump.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"rundll32\\.exe.*comsvcs\\.dll.*minidump")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Certutil download",
            "tech": "T1105",
            "sigma_path": "SigmaHQ:windows/process_creation/certutil_urlcache.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"certutil\\.exe.*-urlcache")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Bitsadmin transfer",
            "tech": "T1105",
            "sigma_path": "SigmaHQ:windows/process_creation/bitsadmin_transfer.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"bitsadmin\\.exe.*(/transfer|/addfile|/create)")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Vssadmin delete shadows",
            "tech": "T1490",
            "sigma_path": "SigmaHQ:windows/process_creation/vssadmin_delete_shadows.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"vssadmin\\.exe\\s+delete\\s+shadows")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Wevtutil clear logs",
            "tech": "T1070.001",
            "sigma_path": "SigmaHQ:windows/process_creation/wevtutil_clear.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"wevtutil\\.exe\\s+cl\\s+")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
        {
            "title": "Netsh disable firewall",
            "tech": "T1562.004",
            "sigma_path": "SigmaHQ:windows/process_creation/netsh_firewall_off.yml",
            "spl": r"""
sourcetype=WinEventLog:Security EventCode=4688
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| where match(cmd,"netsh\\.exe.*advfirewall.*state\\s+off")
| stats count values(cmd) as commands by host, SubjectUserName
""",
        },
    ]

    for i, src in enumerate(sigma_sources, start=1):
        title = src["title"]
        tech = src["tech"]
        sigma_path = src["sigma_path"]
        sid = f"DAC-SIG-{i:04d}"
        batch.append(
            _det(
                id_=sid,
                title=title,
                description="Normalized Sigma source reference (metadata-only). Convert using pipelines/convert/sigma_convert.py or author a platform-native query.",
                platforms=["splunk"],
                sourcetypes=["WinEventLog:Security"],
                tactics=["execution"],
                techniques=[tech],
                severity="medium",
                false_positives=["Varies by environment; validate and tune."],
                references=["https://github.com/SigmaHQ/sigma"],
                required_fields=[],
                sigma={"path": sigma_path},
                tags=["sigma", "normalized"],
            )
        )

        # Converted Splunk detection referencing the normalized sigma metadata (real SPL pattern).
        converted.append(
            _det(
                id_=f"DAC-WIN-{(84 + i):04d}",
                title=f"[Sigma→Splunk] {title}",
                description=f"Sigma-derived detection converted/implemented for Splunk. Source: {sid}.",
                platforms=["splunk"],
                sourcetypes=["WinEventLog:Security"],
                tactics=["execution"],
                techniques=[tech],
                severity="medium",
                false_positives=["Tune by allowlisting known admin tooling or software installers."],
                references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688"],
                required_fields=["EventCode", "CommandLine", "NewProcessName"],
                sigma={"path": str((sigma_dir / f"{sid}-{_slug(title)}.yaml").as_posix())},
                query={"splunk": src["spl"]},
            )
        )

    for r in batch:
        (sigma_dir / f"{r['id']}-{_slug(r['title'])}.yaml").write_text(_dump_yaml(r), encoding="utf-8")
    for r in converted:
        (splunk_out_dir / f"{r['id']}-{_slug(r['title'])}.yaml").write_text(_dump_yaml(r), encoding="utf-8")

    return len(batch) + len(converted)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--defender-out", default="detections/defender", help="Output folder for Defender detections")
    ap.add_argument("--crowdstrike-out", default="detections/crowdstrike", help="Output folder for CrowdStrike detections")
    ap.add_argument("--sigma-out", default="detections/sigma", help="Output folder for normalized Sigma detections")
    ap.add_argument("--sigma-splunk-out", default="detections/splunk/windows/sigma_converted", help="Output folder for Sigma→Splunk detections")
    args = ap.parse_args()

    wrote_def = write_defender_pack(Path(args.defender_out).resolve())
    wrote_cs = write_crowdstrike_pack(Path(args.crowdstrike_out).resolve())
    wrote_sigma = write_sigma_batch(Path(args.sigma_out).resolve(), Path(args.sigma_splunk_out).resolve())
    print(f"Wrote Defender={wrote_def}, CrowdStrike={wrote_cs}, SigmaBatch={wrote_sigma}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

