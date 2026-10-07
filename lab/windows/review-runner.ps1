# Reads the lab indexer and writes one human-review record.
# A hit is not a validated detection. telemetry_validated stays false
# until a person accepts the record.

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\lab\reviews | Out-Null

function Enable-LocalSplunkTrust {
    if (-not ("DacLabTrustAll" -as [type])) {
        Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class DacLabTrustAll : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object DacLabTrustAll
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
}

function Invoke-SplunkSearch {
    param([Parameter(Mandatory = $true)][string]$Search)
    $pwPath = "C:\lab\secrets\splunk-password.txt"
    if (-not (Test-Path $pwPath)) { throw "no splunk password file" }
    $pw = (Get-Content -Raw $pwPath).Trim()
    $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("admin:$pw"))
    Enable-LocalSplunkTrust
    $body = @{
        search      = $Search
        exec_mode   = "oneshot"
        output_mode = "json"
    }
    return Invoke-RestMethod -Uri "https://127.0.0.1:8089/services/search/jobs" -Method Post -Body $body -Headers @{ Authorization = "Basic $pair" }
}

function Get-Count {
    param($Response)
    if ($null -eq $Response.results -or $Response.results.Count -eq 0) { return 0 }
    $sum = 0
    foreach ($row in $Response.results) {
        if ($row.count) { $sum += [int]$row.count }
    }
    if ($sum -eq 0 -and $Response.results.Count -gt 0) { return [int]$Response.results.Count }
    return $sum
}

$ruleId = "DAC-WIN-0334"
$verdict = "logging_ready"
$note = "Security 4688 and Sysmon 1 are arriving with a command line. No odbcconf REGSVR, response-file, INSTALLDRIVER, or configsysdsn event is in the last day. That is expected until you choose to run the technique."
$security = 0
$sysmon = 0
$withCmd = 0
$hits = 0
$sample = ""

try {
    $security = Get-Count (Invoke-SplunkSearch 'search sourcetype="XmlWinEventLog:Security" EventCode=4688 earliest=-30m | stats count')
    $sysmon = Get-Count (Invoke-SplunkSearch 'search sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-30m | stats count')
    $withCmd = Get-Count (Invoke-SplunkSearch 'search sourcetype="XmlWinEventLog:Security" EventCode=4688 earliest=-30m CommandLine=* NOT CommandLine="" | stats count')
    $detect = @'
search ((sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Security) EventCode=4688) OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) earliest=-1d
| eval cmd=lower(coalesce(CommandLine, Process_Command_Line, cmdline))
| eval proc=lower(coalesce(NewProcessName, Image, process_path, process))
| eval parent=lower(coalesce(ParentProcessName, Creator_Process_Name, parent_process_name, ParentImage))
| where match(proc, "(^|\\)odbcconf\.exe$") AND match(cmd, "(regsvr|installdriver|configsysdsn|(^|\s)[-/]f(\s|$))")
| stats count values(proc) as processes values(parent) as parents values(cmd) as commands by host
'@
    $hitResp = Invoke-SplunkSearch $detect
    $hits = Get-Count $hitResp
    if ($hitResp.results -and $hitResp.results.Count -gt 0 -and $hitResp.results[0].commands) {
        $sample = [string]$hitResp.results[0].commands
    }

    if ($security -eq 0) {
        $verdict = "no_4688"
        $note = "No Security 4688 in the last 30 minutes. Process Creation auditing is off, or Splunk is not reading the Security channel yet."
    }
    elseif ($withCmd -eq 0) {
        $verdict = "command_line_missing"
        $note = "4688 is arriving but CommandLine is empty. ProcessCreationIncludeCmdLine_Enabled is not in effect. Argument rules cannot be judged."
    }
    elseif ($sysmon -eq 0) {
        $verdict = "no_sysmon"
        $note = "4688 with a command line is arriving. Sysmon Event ID 1 is not. Rules that need OriginalFileName or ParentCommandLine are not testable yet."
    }
    elseif ($hits -gt 0) {
        $verdict = "hit"
        $note = "DAC-WIN-0334 matched $hits host row(s). This does not validate the rule. Confirm the command was your lab test, then leave telemetry_validated false until you accept it."
    }
}
catch {
    $verdict = "splunk_unreachable"
    $note = "The review runner could not search https://127.0.0.1:8089. Splunk is not installed or not up. $($_.Exception.Message)"
}

$record = [ordered]@{
    time          = (Get-Date).ToUniversalTime().ToString("o")
    rule_id       = $ruleId
    status        = "awaiting_human"
    verdict       = $verdict
    security_4688 = $security
    sysmon_1      = $sysmon
    command_line  = $withCmd
    hit_rows      = $hits
    sample        = $sample
    note          = $note
}
$json = $record | ConvertTo-Json -Compress
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$json | Set-Content -Encoding ascii "C:\lab\reviews\review-$stamp.json"
$json | Set-Content -Encoding ascii "C:\lab\reviews\latest.json"

if (-not [System.Diagnostics.EventLog]::SourceExists("dac-lab")) {
    New-EventLog -LogName Application -Source "dac-lab"
}
Write-EventLog -LogName Application -Source "dac-lab" -EventId 1000 -EntryType Information -Message "DAC lab review $ruleId verdict=$verdict hits=$hits. $note"

Write-Output $json
