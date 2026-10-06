# One Windows lab host: process-creation auditing, Sysmon Event ID 1, Splunk.
# Safe to re-run. Does not execute a detection test beyond "odbcconf /?",
# which does not match DAC-WIN-0334.

param(
    [string]$SplunkPassword = "",
    [string]$SplunkMsiUrl = ""
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path C:\lab, C:\lab\secrets, C:\lab\reviews, C:\lab\splunk | Out-Null

function Write-LabLog([string]$Message) {
    $line = "{0} {1}" -f (Get-Date).ToUniversalTime().ToString("o"), $Message
    Add-Content -Path C:\lab\bootstrap.log -Value $line
    Write-Output $line
}

Write-LabLog "audit policy: process creation success, include command line"
auditpol.exe /set /subcategory:"Process Creation" /success:enable | Out-Null
$auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $auditKey -Force | Out-Null
New-ItemProperty -Path $auditKey -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null

$sysmonExe = "C:\lab\Sysmon64.exe"
if (-not (Test-Path $sysmonExe)) {
    Write-LabLog "download sysmon"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\lab\Sysmon.zip"
    Expand-Archive -Path "C:\lab\Sysmon.zip" -DestinationPath "C:\lab\sysmon" -Force
    Copy-Item "C:\lab\sysmon\Sysmon64.exe" $sysmonExe -Force
}
$sysmonCfg = "C:\lab\sysmon-process-create.xml"
if (-not (Test-Path $sysmonCfg)) {
    throw "Missing $sysmonCfg. deploy.sh should have written it."
}
Write-LabLog "install sysmon config (process create only)"
$sysmonXml = Get-Content -Raw $sysmonCfg
$sysmonOk = $false
foreach ($schema in @("4.90", "4.82", "4.50")) {
    $tryXml = $sysmonXml -replace 'schemaversion="[^"]+"', "schemaversion=`"$schema`""
    Set-Content -Path $sysmonCfg -Value $tryXml -Encoding ascii
    $already = Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue
    if ($already) {
        & $sysmonExe -c $sysmonCfg
    }
    else {
        & $sysmonExe -accepteula -i $sysmonCfg
    }
    if ($LASTEXITCODE -eq 0) {
        $sysmonOk = $true
        Write-LabLog "sysmon schema $schema accepted"
        break
    }
}
if (-not $sysmonOk) {
    $help = & $sysmonExe -s 2>&1 | Out-String
    throw "Sysmon rejected the config. Sysmon said: $help"
}

Write-LabLog "generate a benign 4688 and Sysmon 1 (odbcconf /? does not match DAC-WIN-0334)"
$odbc = Join-Path $env:SystemRoot "System32\odbcconf.exe"
if (Test-Path $odbc) {
    Start-Process -FilePath $odbc -ArgumentList "/?" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
}

$splunkHome = "C:\Program Files\Splunk"
if ($SplunkMsiUrl -and -not (Test-Path "$splunkHome\bin\splunk.exe")) {
    if (-not $SplunkPassword) { throw "SplunkPassword is required when SplunkMsiUrl is set" }
    Set-Content -Path "C:\lab\secrets\splunk-password.txt" -Value $SplunkPassword -Encoding ascii
    icacls.exe "C:\lab\secrets\splunk-password.txt" /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" | Out-Null
    Write-LabLog "download splunk msi"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $SplunkMsiUrl -OutFile "C:\lab\splunk.msi"
    Write-LabLog "install splunk"
    $install = Start-Process -FilePath msiexec.exe -Wait -PassThru -ArgumentList @(
        "/i", "C:\lab\splunk.msi",
        "AGREETOLICENSE=Yes",
        "SPLUNKUSERNAME=admin",
        "SPLUNKPASSWORD=$SplunkPassword",
        "LAUNCHSPLUNK=1",
        "/quiet",
        "/norestart",
        "/l*v", "C:\lab\splunk-install.log"
    )
    if ($install.ExitCode -ne 0 -and $install.ExitCode -ne 3010) {
        throw "Splunk msiexec exit $($install.ExitCode). See C:\lab\splunk-install.log"
    }
}

if (Test-Path "$splunkHome\bin\splunk.exe") {
    $pwFile = "C:\lab\secrets\splunk-password.txt"
    if (-not (Test-Path $pwFile)) {
        if (-not $SplunkPassword) { throw "Splunk is installed but C:\lab\secrets\splunk-password.txt is missing" }
        Set-Content -Path $pwFile -Value $SplunkPassword -Encoding ascii
        icacls.exe $pwFile /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(R)" | Out-Null
    }
    $local = Join-Path $splunkHome "etc\system\local"
    New-Item -ItemType Directory -Force -Path $local | Out-Null
    foreach ($name in @("inputs.conf", "props.conf", "transforms.conf")) {
        $src = Join-Path "C:\lab\splunk" $name
        if (Test-Path $src) {
            Copy-Item $src (Join-Path $local $name) -Force
        }
    }
    Write-LabLog "restart splunkd so the new inputs load"
    Restart-Service Splunkd -ErrorAction SilentlyContinue
    Start-Service Splunkd
    New-NetFirewallRule -DisplayName "Splunk Web lab" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow -ErrorAction SilentlyContinue | Out-Null

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\lab\review-runner.ps1"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Days 3650)
    Unregister-ScheduledTask -TaskName "dac-lab-review" -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName "dac-lab-review" -Action $action -Trigger $trigger -User "SYSTEM" -RunLevel Highest | Out-Null
    Write-LabLog "scheduled dac-lab-review every 30 minutes"
    $deadline = (Get-Date).AddMinutes(3)
    do {
        Start-Sleep -Seconds 5
        $up = Get-NetTCPConnection -LocalPort 8089 -State Listen -ErrorAction SilentlyContinue
    } while (-not $up -and (Get-Date) -lt $deadline)
}
else {
    Write-LabLog "splunk not installed. Re-run with SplunkMsiUrl after the trial download page gives you an MSI link."
}

if (Test-Path "C:\lab\review-runner.ps1") {
    Write-LabLog "first review"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\lab\review-runner.ps1
}

Write-LabLog "bootstrap done"
