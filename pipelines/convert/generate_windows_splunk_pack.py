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
    sourcetypes: List[str],
    tactics: List[str],
    techniques: List[str],
    severity: str,
    false_positives: List[str],
    references: List[str],
    required_fields: List[str],
    spl: str,
) -> Dict[str, Any]:
    return {
        "id": id_,
        "title": title,
        "description": description,
        "author": "DaC",
        "status": "experimental",
        "platforms": ["splunk"],
        "sourcetypes": sourcetypes,
        "mitre": {"tactics": tactics, "techniques": techniques},
        "severity": severity,
        "false_positives": false_positives,
        "references": references,
        "telemetry_validated": False,
        "required_fields": required_fields,
        "query": {"splunk": spl.strip() + "\n"},
    }


def build_windows_pack() -> List[Dict[str, Any]]:
    sec = "WinEventLog:Security"
    sys = "WinEventLog:System"
    sysmon = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    ps = "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
    wmi = "XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational"
    defender = "XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational"

    out: List[Dict[str, Any]] = []
    n = 1

    def add(d: Dict[str, Any]) -> None:
        nonlocal n
        out.append(d)
        n += 1

    def win_id() -> str:
        return f"DAC-WIN-{n:04d}"

    # Authentication anomalies (4624/4625/4648/4672/4740)
    add(
        _det(
            id_=win_id(),
            title="Excessive failed logons from single source",
            description="Detects bursts of failed logons (4625) from a single source IP which can indicate password spraying or brute force.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1110"],
            severity="medium",
            false_positives=["Misconfigured services or users repeatedly mistyping passwords."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625"],
            required_fields=["EventCode", "IpAddress", "TargetUserName", "host"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4625
| eval src_ip=coalesce(IpAddress, src, src_ip)
| eval user=coalesce(TargetUserName, Account_Name, user)
| stats count as failures dc(user) as users values(user) as user_list by src_ip, host
| where failures >= 25 AND users >= 10
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Multiple failed logons for single account across many hosts",
            description="Detects a single user failing authentication across many hosts, which can indicate credential stuffing or lateral movement attempts.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1110"],
            severity="medium",
            false_positives=["User password expired or account locked causing repeated failures."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625"],
            required_fields=["EventCode", "TargetUserName", "host"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4625
| eval user=coalesce(TargetUserName, Account_Name, user)
| stats count as failures dc(host) as hosts values(host) as host_list by user
| where failures >= 20 AND hosts >= 8
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Brute force followed by successful logon (same source)",
            description="Detects a pattern of multiple 4625 failures followed by a 4624 success from the same source IP to the same host within a short window.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1110"],
            severity="high",
            false_positives=["Users mistyping then succeeding; shared jump hosts."],
            references=[
                "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4625",
                "https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624",
            ],
            required_fields=["EventCode", "IpAddress", "TargetUserName", "host"],
            spl=r"""
sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| eval src_ip=coalesce(IpAddress, src, src_ip)
| eval user=coalesce(TargetUserName, Account_Name, user)
| eval outcome=if(EventCode=4624,"success","failure")
| transaction src_ip, user, host maxspan=15m
| search outcome="failure" outcome="success"
| eval failures=mvcount(mvfilter(outcome="failure"))
| eval successes=mvcount(mvfilter(outcome="success"))
| where failures >= 10 AND successes >= 1
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Successful logon from uncommon source (new src for user)",
            description="Detects a successful logon (4624) where the source IP is new for the user over a lookback period; useful for initial credential compromise triage.",
            sourcetypes=[sec],
            tactics=["initial-access", "credential-access"],
            techniques=["T1078"],
            severity="medium",
            false_positives=["Users traveling or new VPN egress points."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624"],
            required_fields=["EventCode", "IpAddress", "TargetUserName", "_time"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4624
| eval src_ip=coalesce(IpAddress, src, src_ip)
| eval user=coalesce(TargetUserName, Account_Name, user)
| where isnotnull(src_ip) AND isnotnull(user)
| bin _time span=1h
| stats earliest(_time) as first_seen latest(_time) as last_seen values(host) as hosts by user, src_ip
| eventstats earliest(first_seen) as global_first_seen by user, src_ip
| where first_seen = global_first_seen
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Logon with explicit credentials (4648) to remote target",
            description="Detects explicit credential logons (4648) which can indicate lateral movement using runas, psexec, or credential material reuse.",
            sourcetypes=[sec],
            tactics=["lateral-movement"],
            techniques=["T1021.001"],
            severity="medium",
            false_positives=["Legitimate admin tooling using alternate credentials."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4648"],
            required_fields=["EventCode", "TargetServerName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4648
| eval user=coalesce(SubjectUserName, Account_Name, user)
| eval target=coalesce(TargetServerName, dest, ComputerName)
| stats count values(ProcessName) as processes values(target) as targets by user
| where count >= 3
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Special privileges assigned to new logon (4672) for non-admin users",
            description="Detects privileged logon events (4672) for accounts that are not commonly privileged, which can indicate privilege escalation or admin misuse.",
            sourcetypes=[sec],
            tactics=["privilege-escalation"],
            techniques=["T1078"],
            severity="high",
            false_positives=["Newly promoted admins; service accounts."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4672"],
            required_fields=["EventCode", "SubjectUserName", "host"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4672
| eval user=coalesce(SubjectUserName, Account_Name, user)
| search NOT user IN ("Administrator","SYSTEM","LOCAL SERVICE","NETWORK SERVICE")
| stats count values(PrivilegeList) as privileges by user, host
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Account lockout spike (4740) by source host",
            description="Detects spikes in account lockouts, which can indicate password spraying against multiple accounts or misconfigured services.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1110"],
            severity="medium",
            false_positives=["Password policy changes; misconfigured service accounts."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4740"],
            required_fields=["EventCode", "TargetUserName", "CallerComputerName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4740
| eval user=coalesce(TargetUserName, user)
| eval caller=coalesce(CallerComputerName, src, host)
| stats count dc(user) as users values(user) as user_list by caller
| where count >= 10 AND users >= 8
""",
        )
    )

    # Kerberos / NTLM (4768/4769/4771/4776)
    add(
        _det(
            id_=win_id(),
            title="Kerberos pre-auth failures spike (4771) from source",
            description="Detects spikes of Kerberos pre-auth failures that can indicate password guessing or AS-REQ abuse.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1110"],
            severity="medium",
            false_positives=["Time skew; users with expired passwords."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4771"],
            required_fields=["EventCode", "IpAddress", "TargetUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4771
| eval src_ip=coalesce(IpAddress, src, src_ip)
| eval user=coalesce(TargetUserName, Account_Name, user)
| stats count as failures dc(user) as users values(user) as user_list by src_ip
| where failures >= 30 AND users >= 10
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Potential Kerberoasting (high volume TGS requests) (4769)",
            description="Detects high volume Kerberos service ticket requests for many SPNs by a single account, a common Kerberoasting pattern.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1558.003"],
            severity="high",
            false_positives=["Legitimate service discovery or monitoring accounts."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769"],
            required_fields=["EventCode", "Account_Name", "ServiceName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4769
| eval user=coalesce(Account_Name, TargetUserName, user)
| stats count as tgs_requests dc(ServiceName) as spn_count values(ServiceName) as spns by user
| where tgs_requests >= 50 AND spn_count >= 20
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="NTLM authentication failures spike (4776)",
            description="Detects bursts of NTLM authentication failures that can indicate password guessing or legacy auth abuse.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1110"],
            severity="medium",
            false_positives=["Legacy applications with stale passwords."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4776"],
            required_fields=["EventCode", "AccountName", "Workstation"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4776
| eval user=coalesce(AccountName, Account_Name, user)
| eval workstation=coalesce(Workstation, src, host)
| stats count as failures dc(user) as users values(user) as user_list by workstation
| where failures >= 25 AND users >= 10
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Potential AS-REP Roasting (4768 without pre-auth)",
            description="Detects Kerberos AS-REQ events where pre-authentication is not required, which can indicate AS-REP Roasting opportunities or abuse.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1558.004"],
            severity="high",
            false_positives=["Accounts intentionally configured without pre-auth (should be rare)."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4768"],
            required_fields=["EventCode", "TargetUserName", "PreAuthType"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4768
| eval user=coalesce(TargetUserName, Account_Name, user)
| where PreAuthType=0 OR PreAuthType="0"
| stats count values(IpAddress) as src_ips by user
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Kerberos TGS requests using RC4 encryption (4769)",
            description="Detects Kerberos service ticket requests using RC4 (0x17) which can be associated with Kerberoasting and legacy configurations.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1558.003"],
            severity="medium",
            false_positives=["Legacy environments with RC4 enabled; tune by SPN allowlist."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4769"],
            required_fields=["EventCode", "Account_Name", "ServiceName", "TicketEncryptionType"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4769
| eval user=coalesce(Account_Name, TargetUserName, user)
| where TicketEncryptionType="0x17" OR TicketEncryptionType=0x17 OR TicketEncryptionType=23
| stats count as tgs_requests dc(ServiceName) as spn_count values(ServiceName) as spns by user
| where tgs_requests >= 10
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Administrative share access spike (5140) from source",
            description="Detects spikes in access to administrative shares (e.g., ADMIN$, C$), which can indicate lateral movement over SMB.",
            sourcetypes=[sec],
            tactics=["lateral-movement"],
            techniques=["T1021.002"],
            severity="medium",
            false_positives=["Legitimate admin tools, software deployment, patching."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-5140"],
            required_fields=["EventCode", "ShareName", "IpAddress", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=5140
| eval share=lower(coalesce(ShareName, share_name))
| where match(share, "\\\\(admin\\$|c\\$|d\\$|ipc\\$)$")
| eval src_ip=coalesce(IpAddress, src, src_ip)
| eval user=coalesce(SubjectUserName, user)
| stats count dc(share) as shares values(share) as share_list by src_ip, user, host
| where count >= 20
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Service installed (4697) via Security audit",
            description="Detects service installation via Security auditing (4697), which can indicate persistence using new or modified services.",
            sourcetypes=[sec],
            tactics=["persistence"],
            techniques=["T1543.003"],
            severity="high",
            false_positives=["Legitimate software installs."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4697"],
            required_fields=["EventCode", "ServiceName", "ServiceFileName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4697
| eval img=lower(coalesce(ServiceFileName, ImagePath, Message))
| where match(img, "(\\\\users\\\\|\\\\temp\\\\|\\\\appdata\\\\|cmd\\.exe|powershell\\.exe|wscript\\.exe|cscript\\.exe)")
| stats count values(ServiceName) as services values(img) as image_paths by host, SubjectUserName
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Event log service shutdown (1100)",
            description="Detects Event ID 1100 indicating the Windows Event Log service was shut down, which can be used to impair logging.",
            sourcetypes=[sec],
            tactics=["defense-evasion"],
            techniques=["T1562.002"],
            severity="high",
            false_positives=["Planned maintenance or reboot sequences; investigate unexpected occurrences."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-1100"],
            required_fields=["EventCode", "host"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=1100
| stats count by host
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Password reset attempts spike (4724) by actor",
            description="Detects spikes in password reset attempts which can indicate account takeover or helpdesk abuse.",
            sourcetypes=[sec],
            tactics=["credential-access"],
            techniques=["T1098"],
            severity="high",
            false_positives=["Helpdesk bulk resets during incidents or onboarding."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4724"],
            required_fields=["EventCode", "TargetUserName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4724
| eval actor=coalesce(SubjectUserName, src_user)
| eval target=coalesce(TargetUserName, user)
| stats count as resets dc(target) as users values(target) as user_list by actor, host
| where resets >= 5 AND users >= 5
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Privileged service called with SeDebugPrivilege (4673)",
            description="Detects use of SeDebugPrivilege via privileged service calls, which can be associated with credential dumping and process injection workflows.",
            sourcetypes=[sec],
            tactics=["privilege-escalation", "credential-access"],
            techniques=["T1068"],
            severity="high",
            false_positives=["Legitimate debuggers, EDR/AV, and some admin tools."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4673"],
            required_fields=["EventCode", "PrivilegeList", "SubjectUserName", "ProcessName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4673
| eval priv=lower(coalesce(PrivilegeList, Privileges))
| where match(priv, "sedebugprivilege")
| stats count values(ProcessName) as processes values(priv) as privileges by host, SubjectUserName
""",
        )
    )

    # Audit clearing / logging tamper (1102 / 4719)
    add(
        _det(
            id_=win_id(),
            title="Security audit log cleared (1102)",
            description="Detects Event ID 1102 indicating the Security log was cleared, commonly used for defense evasion.",
            sourcetypes=[sec],
            tactics=["defense-evasion"],
            techniques=["T1070.001"],
            severity="high",
            false_positives=["Legitimate log maintenance (should be rare and controlled)."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-1102"],
            required_fields=["EventCode", "SubjectUserName", "host"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=1102
| eval user=coalesce(SubjectUserName, user, Account_Name)
| stats count values(user) as users by host
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Audit policy changed (4719)",
            description="Detects changes to local audit policy (4719), which can be used to impair logging and evade detection.",
            sourcetypes=[sec],
            tactics=["defense-evasion"],
            techniques=["T1562.002"],
            severity="high",
            false_positives=["Planned policy changes via GPO or security tooling."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4719"],
            required_fields=["EventCode", "SubjectUserName", "host"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4719
| eval user=coalesce(SubjectUserName, user, Account_Name)
| stats count values(AuditPolicyChanges) as changes by user, host
""",
        )
    )

    # Scheduled tasks (4698/4702)
    add(
        _det(
            id_=win_id(),
            title="Scheduled task created (4698) with suspicious command",
            description="Detects creation of scheduled tasks where task actions include suspicious LOLBins or PowerShell.",
            sourcetypes=[sec],
            tactics=["persistence"],
            techniques=["T1053.005"],
            severity="high",
            false_positives=["Legitimate software updaters or admin automation."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4698"],
            required_fields=["EventCode", "TaskName", "TaskContent"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4698
| eval task=coalesce(TaskName, Task_Name)
| eval content=coalesce(TaskContent, Message, task_content)
| where match(lower(content), "(powershell|cmd\\.exe|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)")
| stats count values(task) as tasks by host, SubjectUserName
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Scheduled task modified (4702) for persistence",
            description="Detects modifications to scheduled tasks that may indicate persistence through task hijacking.",
            sourcetypes=[sec],
            tactics=["persistence"],
            techniques=["T1053.005"],
            severity="medium",
            false_positives=["Legitimate task updates by administrators."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4702"],
            required_fields=["EventCode", "TaskName", "TaskContent"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4702
| eval task=coalesce(TaskName, Task_Name)
| stats count values(task) as tasks by host, SubjectUserName
| where count >= 3
""",
        )
    )

    # Account / group manipulation (4720/4722/4726/4728/4732/4756/4738)
    add(
        _det(
            id_=win_id(),
            title="Local or domain user account created (4720)",
            description="Detects creation of a new user account; attackers often create accounts for persistence.",
            sourcetypes=[sec],
            tactics=["persistence"],
            techniques=["T1136"],
            severity="high",
            false_positives=["Standard IT provisioning."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4720"],
            required_fields=["EventCode", "TargetUserName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4720
| eval new_user=coalesce(TargetUserName, user)
| eval actor=coalesce(SubjectUserName, src_user)
| stats count values(new_user) as created_users by actor, host
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="User account enabled (4722) shortly after creation",
            description="Detects user enablement events; attackers may create then enable accounts during compromise.",
            sourcetypes=[sec],
            tactics=["persistence"],
            techniques=["T1098"],
            severity="medium",
            false_positives=["Normal provisioning workflows."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4722"],
            required_fields=["EventCode", "TargetUserName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4722
| eval target=coalesce(TargetUserName, user)
| eval actor=coalesce(SubjectUserName, src_user)
| stats count values(target) as enabled_users by actor, host
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="User account deleted (4726)",
            description="Detects deletion of a user account which can be used to hide traces or sabotage access.",
            sourcetypes=[sec],
            tactics=["impact"],
            techniques=["T1531"],
            severity="high",
            false_positives=["Planned deprovisioning."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4726"],
            required_fields=["EventCode", "TargetUserName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4726
| eval target=coalesce(TargetUserName, user)
| eval actor=coalesce(SubjectUserName, src_user)
| stats count values(target) as deleted_users by actor, host
""",
        )
    )

    # Group membership change events (common)
    for ev, group_tech in [
        (4728, "T1098"),  # member added to global security-enabled group
        (4732, "T1098"),  # member added to local security-enabled group
        (4756, "T1098"),  # member added to universal security-enabled group
    ]:
        add(
            _det(
                id_=win_id(),
                title=f"User added to security group (EventCode {ev})",
                description=f"Detects group membership additions (EventCode {ev}); review for privileged groups (e.g., Domain Admins, local Administrators).",
                sourcetypes=[sec],
                tactics=["privilege-escalation", "persistence"],
                techniques=[group_tech],
                severity="high",
                false_positives=["Legitimate group administration."],
                references=[f"https://learn.microsoft.com/windows/security/threat-protection/auditing/event-{ev}"],
                required_fields=["EventCode", "TargetUserName", "SubjectUserName", "GroupName"],
                spl=rf"""
sourcetype=WinEventLog:Security EventCode={ev}
| eval actor=coalesce(SubjectUserName, src_user)
| eval member=coalesce(MemberName, TargetUserName, user)
| eval group=coalesce(GroupName, TargetDomainName, group_name)
| stats count values(member) as members values(group) as groups by actor, host
""",
            )
        )

    add(
        _det(
            id_=win_id(),
            title="User account changed (4738) affecting password or UAC flags",
            description="Detects account property changes that can be used for persistence or privilege manipulation (e.g., enabling delegation or changing UAC-related flags).",
            sourcetypes=[sec],
            tactics=["persistence", "privilege-escalation"],
            techniques=["T1098"],
            severity="medium",
            false_positives=["Normal identity management changes."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4738"],
            required_fields=["EventCode", "TargetUserName", "SubjectUserName"],
            spl=r"""
sourcetype=WinEventLog:Security EventCode=4738
| eval actor=coalesce(SubjectUserName, src_user)
| eval target=coalesce(TargetUserName, user)
| stats count values(ChangedAttributes) as changed_attrs by actor, target, host
""",
        )
    )

    # Process creation (4688) suspicious patterns
    process_patterns = [
        ("Encoded PowerShell command line", "T1059.001", r"(powershell\.exe|pwsh\.exe).*(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{50,}"),
        ("PowerShell download cradle (IEX/Net.WebClient)", "T1105", r"(powershell\.exe|pwsh\.exe).*(IEX|Invoke-Expression|DownloadString|Net\.WebClient|Invoke-WebRequest|iwr|curl|wget)"),
        ("PowerShell hidden window + no profile", "T1059.001", r"(powershell\.exe|pwsh\.exe).*(-nop|-noprofile).*(-w\s+hidden|-windowstyle\s+hidden)"),
        ("PowerShell execution policy bypass", "T1059.001", r"(powershell\.exe|pwsh\.exe).*(-ep\s+bypass|-executionpolicy\s+bypass)"),
        ("PowerShell suspicious obfuscation (frombase64string)", "T1027", r"(powershell\.exe|pwsh\.exe).*(frombase64string|\\[char\\]|-join\\s*\\(|\\bxor\\b)"),
        ("Suspicious rundll32 execution", "T1218.011", r"rundll32\.exe.*\.(dll|cpl),"),
        ("Rundll32 comsvcs MiniDump (LSASS dump)", "T1003", r"rundll32\.exe.*comsvcs\.dll.*minidump"),
        ("Suspicious regsvr32 execution", "T1218.010", r"regsvr32\.exe.*(/i:|/u|scrobj\.dll)"),
        ("Suspicious mshta execution", "T1218.005", r"mshta\.exe.*(http|https|javascript:|vbscript:)"),
        ("InstallUtil execution (living-off-the-land)", "T1218.004", r"installutil\.exe.*(/logfile=|/u)"),
        ("MSBuild execution (trusted developer utility)", "T1127.001", r"msbuild\.exe.*\.(xml|proj)"),
        ("MsiExec remote install (http/https)", "T1218.007", r"msiexec\.exe.*(/i|/qn).*(http|https)"),
        ("Certutil downloading or decoding", "T1105", r"certutil\.exe.*(-urlcache|-decode|-encode)"),
        ("Curl/Wget downloading to disk", "T1105", r"(curl|wget)\.exe.*(http|https)"),
        ("Bitsadmin transfer", "T1105", r"bitsadmin\.exe.*(/transfer|/addfile|/create)"),
        ("WMI via wmic process", "T1047", r"wmic\.exe.*(process call create|/node:|shadowcopy)"),
        ("Schtasks creating a task", "T1053.005", r"schtasks\.exe.*(/create|/change)"),
        ("SC create service", "T1543.003", r"sc\.exe\s+create\s+"),
        ("SC stop or disable security services", "T1562.001", r"sc\.exe\s+(stop|config)\s+(windefend|wscsvc|sense|wdnissvc)"),
        ("Netsh add portproxy (pivot)", "T1572", r"netsh\.exe.*interface\s+portproxy\s+add"),
        ("Net user add", "T1136", r"net(\.exe)?\s+user\s+.*\s+/add"),
        ("Net localgroup administrators add", "T1098", r"net(\.exe)?\s+localgroup\s+administrators\s+.+\s+/add"),
        ("Net group domain admins add", "T1098", r"net(\.exe)?\s+group\s+\"?domain admins\"?.*(/add|/domain)"),
        ("Nltest domain trust discovery", "T1482", r"nltest\.exe.*(/domain_trusts|/trusted_domains|/dclist:)"),
        ("Wevtutil clear logs", "T1070.001", r"wevtutil\.exe\s+cl\s+"),
        ("Wevtutil disable Security log", "T1562.002", r"wevtutil\.exe\s+sl\s+security\s+/e:false"),
        ("Vssadmin delete shadows", "T1490", r"vssadmin\.exe\s+delete\s+shadows"),
        ("Wbadmin delete catalog or system state", "T1490", r"wbadmin\.exe.*(delete\\s+catalog|delete\\s+systemstatebackup)"),
        ("Bcdedit disable recovery", "T1562.001", r"bcdedit\.exe.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"),
        ("Netsh disable firewall", "T1562.004", r"netsh\.exe.*advfirewall.*state\s+off"),
        ("Reg add Run key persistence", "T1547.001", r"reg(\.exe)?\s+add\s+.*\\\\currentversion\\\\run"),
        ("Reg add IFEO debugger hijack", "T1546.012", r"reg(\.exe)?\s+add\s+.*image\\s+file\\s+execution\\s+options.*\\\\debugger"),
        ("Procdump targeting LSASS", "T1003", r"procdump(\.exe)?\s+.*(-ma|-mm).*lsass"),
        ("Comsvcs MiniDump via rundll32 (alt form)", "T1003", r"rundll32\.exe.*minidump.*lsass"),
        ("Cscript/Wscript executing from user-writable path", "T1059.005", r"(cscript|wscript)\.exe.*\\\\(users|programdata)\\\\.*\\\\(temp|appdata)\\\\"),
        ("Rundll32 javascript/vbscript execution", "T1218.011", r"rundll32\.exe.*(javascript:|vbscript:)"),
        ("Regsvr32 remote scriptlet", "T1218.010", r"regsvr32\.exe.*(http|https).*\\.sct"),
        ("Attrib hide artifacts (hidden/system)", "T1564.001", r"attrib\.exe.*\\+h.*\\+s"),
        ("Icacls grant broad permissions", "T1222.001", r"icacls\.exe.*(/grant|/grant:r).*everyone"),
        ("Taskkill security tooling", "T1562.001", r"taskkill\.exe.*(/im|/pid).*(msmpeng|sense|csfalcon|crowdstrike|windefend)"),
        ("Bitsadmin delete jobs (cleanup)", "T1070", r"bitsadmin\.exe.*(/reset|/delete)"),
        ("Disable Windows Defender via PowerShell cmdlets", "T1562.001", r"(powershell\.exe|pwsh\.exe).*(Set-MpPreference|Add-MpPreference).*(-DisableRealtimeMonitoring|-ExclusionPath|-ExclusionProcess)"),
    ]

    for title_suffix, tech, regex in process_patterns:
        add(
            _det(
                id_=win_id(),
                title=f"Suspicious process creation: {title_suffix} (4688)",
                description=f"Detects 4688 process creation events matching a known suspicious pattern: {title_suffix}.",
                sourcetypes=[sec],
                tactics=["execution", "defense-evasion"],
                techniques=[tech],
                severity="high" if tech in ("T1070.001", "T1562.001", "T1490") else "medium",
                false_positives=["Administrative scripts or software installers may match; tune by allowlisting known management hosts/accounts."],
                references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688"],
                required_fields=["EventCode", "NewProcessName", "CommandLine", "ParentProcessName", "SubjectUserName"],
                spl=rf"""
sourcetype=WinEventLog:Security EventCode=4688
| eval proc=lower(coalesce(NewProcessName, process_path, Image))
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| eval parent=lower(coalesce(ParentProcessName, Creator_Process_Name, parent_process_name))
| where match(cmd, "{regex}")
| stats count values(proc) as processes values(parent) as parents values(cmd) as commands by host, SubjectUserName
""",
            )
        )

    # Service install (7045) from System log
    add(
        _det(
            id_=win_id(),
            title="New service installed (7045) with suspicious image path",
            description="Detects service installation events where the service image path is suspicious (temp/user-writable paths or command interpreters).",
            sourcetypes=[sys],
            tactics=["persistence"],
            techniques=["T1543.003"],
            severity="high",
            false_positives=["Legitimate software installs; tune by publisher/path allowlists."],
            references=["https://learn.microsoft.com/windows/security/threat-protection/auditing/event-7045"],
            required_fields=["EventCode", "ServiceName", "ImagePath", "host"],
            spl=r"""
sourcetype=WinEventLog:System EventCode=7045
| eval img=lower(coalesce(ImagePath, ServiceFileName, service_image_path))
| where match(img, "(\\\\users\\\\|\\\\temp\\\\|\\\\appdata\\\\|cmd\\.exe|powershell\\.exe|wscript\\.exe|cscript\\.exe)")
| stats count values(ServiceName) as services values(img) as image_paths by host
""",
        )
    )

    # PowerShell Operational (4104 script block logging) if available
    add(
        _det(
            id_=win_id(),
            title="PowerShell script block contains download/execution patterns (4104)",
            description="Detects suspicious PowerShell script blocks (4104) indicative of download cradles or obfuscation.",
            sourcetypes=[ps],
            tactics=["execution"],
            techniques=["T1059.001"],
            severity="high",
            false_positives=["Legitimate automation scripts; tune by signed scripts/paths."],
            references=["https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_script_blocks"],
            required_fields=["EventCode", "ScriptBlockText", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| eval sb=lower(coalesce(ScriptBlockText, Message))
| where match(sb, "(downloadstring|invoke-webrequest|iwr|new-object\\s+net\\.webclient|frombase64string|iex|invoke-expression|join\\(.*char\\()")
| stats count values(sb) as scriptblocks by host, UserId
""",
        )
    )

    # WMI Activity (5857-5861) - suspicious consumers / remote
    add(
        _det(
            id_=win_id(),
            title="WMI activity indicates remote process execution (WMI-Activity)",
            description="Detects WMI activity events that can indicate remote execution or persistence via WMI.",
            sourcetypes=[wmi],
            tactics=["execution", "persistence"],
            techniques=["T1047"],
            severity="medium",
            false_positives=["Legitimate WMI usage by monitoring and management systems."],
            references=["https://learn.microsoft.com/windows/win32/wmisdk/wmi-start-page"],
            required_fields=["EventCode", "Operation", "ClientMachine", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-WMI-Activity/Operational" (EventCode=5857 OR EventCode=5858 OR EventCode=5859 OR EventCode=5860 OR EventCode=5861)
| eval op=lower(coalesce(Operation, Message))
| eval client=coalesce(ClientMachine, ClientMachineName, src, src_host)
| where isnotnull(client)
| stats count values(op) as operations by host, client, UserId
""",
        )
    )

    # Windows Defender operational (5001 / 5007 etc) - basic impairment signals
    add(
        _det(
            id_=win_id(),
            title="Windows Defender disabled or configuration changed (Defender Operational)",
            description="Detects Defender operational events associated with disabling or configuration changes that may indicate defense evasion.",
            sourcetypes=[defender],
            tactics=["defense-evasion"],
            techniques=["T1562.001"],
            severity="high",
            false_positives=["IT-driven Defender policy changes."],
            references=["https://learn.microsoft.com/microsoft-365/security/defender-endpoint/troubleshoot-microsoft-defender-antivirus"],
            required_fields=["EventCode", "Message", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Windows Defender/Operational" (EventCode=5001 OR EventCode=5007 OR EventCode=5010 OR EventCode=5012)
| eval msg=lower(coalesce(Message))
| stats count values(msg) as messages by host
""",
        )
    )

    # Sysmon rules (optional, if sourcetype present)
    add(
        _det(
            id_=win_id(),
            title="Sysmon: Office spawns shell or PowerShell",
            description="Detects Sysmon process creation where Office applications spawn cmd/powershell/wscript/cscript, commonly associated with macro-based execution.",
            sourcetypes=[sysmon],
            tactics=["execution"],
            techniques=["T1204"],
            severity="high",
            false_positives=["Legitimate add-ins or automation; tune by allowlisting known templates/macros."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "Image", "ParentImage", "CommandLine", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval img=lower(coalesce(Image))
| eval parent=lower(coalesce(ParentImage))
| eval cmd=lower(coalesce(CommandLine))
| where match(parent,"(winword|excel|powerpnt|outlook)\\.exe") AND match(img,"(cmd|powershell|pwsh|wscript|cscript)\\.exe")
| stats count values(cmd) as commands values(parent) as parents by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: PowerShell encoded command line",
            description="Detects Sysmon process creation for PowerShell with EncodedCommand usage.",
            sourcetypes=[sysmon],
            tactics=["execution"],
            techniques=["T1059.001"],
            severity="high",
            false_positives=["Some admin scripts use -EncodedCommand; tune with allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "Image", "CommandLine", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval img=lower(coalesce(Image))
| eval cmd=lower(coalesce(CommandLine))
| where match(img,"(powershell|pwsh)\\.exe") AND match(cmd,"(-enc|-encodedcommand)\\s+[a-za-z0-9+/=]{50,}")
| stats count values(cmd) as commands by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: LOLBins initiating outbound network connections",
            description="Detects Sysmon network connections initiated by common LOLBins often used for tool transfer or staging.",
            sourcetypes=[sysmon],
            tactics=["command-and-control"],
            techniques=["T1105"],
            severity="medium",
            false_positives=["Legitimate admin tooling and package managers; tune by destination allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "Image", "DestinationIp", "DestinationPort", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| eval img=lower(coalesce(Image))
| where match(img,"(powershell|pwsh|mshta|rundll32|regsvr32|bitsadmin|certutil)\\.exe")
| stats count dc(DestinationIp) as dest_ips values(DestinationPort) as ports by host, User, img
| where count >= 10 AND dest_ips >= 5
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: CreateRemoteThread (possible injection)",
            description="Detects Sysmon CreateRemoteThread events which are commonly associated with code injection techniques.",
            sourcetypes=[sysmon],
            tactics=["defense-evasion"],
            techniques=["T1055"],
            severity="high",
            false_positives=["Some security products and accessibility tools may inject; tune by known signers."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "SourceImage", "TargetImage", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| eval src=lower(coalesce(SourceImage))
| eval tgt=lower(coalesce(TargetImage))
| stats count values(src) as sources values(tgt) as targets by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: Process access to LSASS (credential dumping signal)",
            description="Detects Sysmon process access events targeting LSASS, which can indicate credential dumping.",
            sourcetypes=[sysmon],
            tactics=["credential-access"],
            techniques=["T1003"],
            severity="critical",
            false_positives=["Some EDR/AV solutions access LSASS; tune by signer and process allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "TargetImage", "SourceImage", "GrantedAccess", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| eval tgt=lower(coalesce(TargetImage))
| eval src=lower(coalesce(SourceImage))
| where match(tgt,"\\\\lsass\\.exe$")
| stats count values(src) as sources values(GrantedAccess) as access by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: File created in Startup folder (persistence)",
            description="Detects creation of executable/script content in Startup folders which is a common persistence technique.",
            sourcetypes=[sysmon],
            tactics=["persistence"],
            techniques=["T1547.001"],
            severity="high",
            false_positives=["Legitimate software adding startup entries; tune by publisher/path allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "TargetFilename", "Image", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| eval file=lower(coalesce(TargetFilename))
| eval img=lower(coalesce(Image))
| where match(file,"\\\\(programdata|users)\\\\.*\\\\start menu\\\\programs\\\\startup\\\\") AND match(file,"\\.(exe|dll|ps1|vbs|js|lnk|bat|cmd)$")
| stats count values(file) as files values(img) as images by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: Registry Run key persistence (CurrentVersion\\\\Run)",
            description="Detects registry value sets in Run/RunOnce keys which can indicate persistence.",
            sourcetypes=[sysmon],
            tactics=["persistence"],
            techniques=["T1547.001"],
            severity="high",
            false_positives=["Legitimate software auto-start entries; tune by key/value allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "TargetObject", "Details", "Image", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| eval obj=lower(coalesce(TargetObject))
| eval img=lower(coalesce(Image))
| where match(obj,"\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run(once)?\\\\")
| stats count values(obj) as registry_paths values(Details) as details values(img) as images by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: Defender policy registry modifications",
            description="Detects registry modifications under Windows Defender policy keys that can indicate attempts to impair defenses.",
            sourcetypes=[sysmon],
            tactics=["defense-evasion"],
            techniques=["T1562.001"],
            severity="high",
            false_positives=["Legitimate policy enforcement (GPO/Intune); tune by management hosts."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "TargetObject", "Image", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
| eval obj=lower(coalesce(TargetObject))
| eval img=lower(coalesce(Image))
| where match(obj,"\\\\software\\\\policies\\\\microsoft\\\\windows defender\\\\") OR match(obj,"\\\\software\\\\microsoft\\\\windows defender\\\\")
| stats count values(obj) as registry_paths values(img) as images by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: Suspicious DLL load from user-writable path",
            description="Detects DLL loads from user-writable paths (Temp/AppData) which can indicate DLL search order hijacking or sideloading.",
            sourcetypes=[sysmon],
            tactics=["persistence", "defense-evasion"],
            techniques=["T1574.002"],
            severity="medium",
            false_positives=["Some applications legitimately load plugins from user directories; tune by signer and process allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "ImageLoaded", "Image", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=7
| eval loaded=lower(coalesce(ImageLoaded))
| eval img=lower(coalesce(Image))
| where match(loaded,"\\\\(users|programdata)\\\\.*\\\\(temp|appdata)\\\\") AND match(loaded,"\\.dll$")
| stats count values(loaded) as loaded_dlls values(img) as images by host, User
""",
        )
    )

    add(
        _det(
            id_=win_id(),
            title="Sysmon: Suspicious DNS queries (long subdomains / risky TLDs)",
            description="Detects DNS queries with long or high-entropy-looking domains and selected risky TLDs as a lightweight signal for dynamic resolution.",
            sourcetypes=[sysmon],
            tactics=["command-and-control"],
            techniques=["T1568"],
            severity="medium",
            false_positives=["CDNs and legitimate long domains; tune with allowlists."],
            references=["https://learn.microsoft.com/sysinternals/downloads/sysmon"],
            required_fields=["EventCode", "QueryName", "Image", "host"],
            spl=r"""
sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22
| eval q=lower(coalesce(QueryName, query))
| eval img=lower(coalesce(Image))
| where len(q) >= 35 OR match(q,"\\.(top|xyz|gq|work|click|country|zip|mov)$")
| stats count as queries dc(q) as domains values(q) as domain_list by host, User, img
| where domains >= 10
""",
        )
    )

    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="detections/splunk/windows", help="Output folder")
    args = ap.parse_args()
    out_dir = Path(args.output).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write detections to subfolders by sourcetype class for navigability.
    sec_dir = out_dir / "security"
    sys_dir = out_dir / "system"
    sysmon_dir = out_dir / "sysmon"
    ps_dir = out_dir / "powershell"
    wmi_dir = out_dir / "wmi"
    defender_dir = out_dir / "defender"
    for d in [sec_dir, sys_dir, sysmon_dir, ps_dir, wmi_dir, defender_dir]:
        d.mkdir(parents=True, exist_ok=True)

    detections = build_windows_pack()
    for det in detections:
        st = det.get("sourcetypes", ["unknown"])
        st0 = st[0] if st else "unknown"
        if st0 == "WinEventLog:Security":
            folder = sec_dir
        elif st0 == "WinEventLog:System":
            folder = sys_dir
        elif "Sysmon" in st0:
            folder = sysmon_dir
        elif "PowerShell" in st0:
            folder = ps_dir
        elif "WMI-Activity" in st0 or "WMI" in st0:
            folder = wmi_dir
        elif "Windows Defender" in st0:
            folder = defender_dir
        else:
            folder = out_dir

        filename = f"{det['id']}-{_slug(det['title'])}.yaml"
        (folder / filename).write_text(_dump_yaml(det), encoding="utf-8")

    print(f"Wrote {len(detections)} Windows Splunk detections under {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

