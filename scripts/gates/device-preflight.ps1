[CmdletBinding()]
param(
    [string]$EvidenceDir = (Join-Path $env:TEMP 'OpenWearSync\device-preflight'),
    [switch]$HotspotIsolationObserved
)

$ErrorActionPreference = 'Stop'

# START_MODULE_CONTRACT
#   PURPOSE: Collect non-root Android device evidence before physical acceptance.
#   SCOPE: Diagnostic-only ADB/logcat/perf capture; this gate never proves PASS.
#   DEPENDS: adb, optional connected Wear OS watch and Android phone.
#   LINKS: M-HARDWARE-ACCEPTANCE, V-M-HARDWARE-ACCEPTANCE, docs/implementation/device-acceptance.md
# END_MODULE_CONTRACT
#
# START_MODULE_MAP
#   Invoke-Adb - runs a bounded, read-only adb command and captures its output
#   Save-DeviceEvidence - writes metadata, battery, thermal, CPU and logcat traces
#   gate status - emits PENDING or BLOCKED; PASS is deliberately unreachable
# END_MODULE_MAP

function Invoke-Adb {
    param(
        [Parameter(Mandatory = $true)][string]$Serial,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = & adb -s $Serial @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    [pscustomobject]@{ ExitCode = $exitCode; Output = @($output) }
}

function Save-DeviceEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Serial,
        [Parameter(Mandatory = $true)][string]$DeviceDir,
        [Parameter(Mandatory = $true)][string]$CapturedAtUtc
    )
    $safeSerial = ($Serial -replace '[^A-Za-z0-9_.-]', '_')
    $metadata = Invoke-Adb -Serial $Serial -Arguments @('shell', 'getprop')
    $battery = Invoke-Adb -Serial $Serial -Arguments @('shell', 'dumpsys', 'battery')
    $thermal = Invoke-Adb -Serial $Serial -Arguments @('shell', 'dumpsys', 'thermalservice')
    $cpu = Invoke-Adb -Serial $Serial -Arguments @('shell', 'dumpsys', 'cpuinfo')
    $logcat = Invoke-Adb -Serial $Serial -Arguments @('logcat', '-d', '-v', 'threadtime', '-t', '250')

    Set-Content -LiteralPath (Join-Path $DeviceDir "$safeSerial.getprop.txt") -Value $metadata.Output -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $DeviceDir "$safeSerial.battery.txt") -Value $battery.Output -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $DeviceDir "$safeSerial.thermal.txt") -Value $thermal.Output -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $DeviceDir "$safeSerial.cpu.txt") -Value $cpu.Output -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $DeviceDir "$safeSerial.logcat.txt") -Value $logcat.Output -Encoding UTF8

    [pscustomobject]@{
        Serial = $Serial
        CapturedAtUtc = $CapturedAtUtc
        GetPropExitCode = $metadata.ExitCode
        BatteryExitCode = $battery.ExitCode
        ThermalExitCode = $thermal.ExitCode
        CpuExitCode = $cpu.ExitCode
        LogcatExitCode = $logcat.ExitCode
        EvidencePrefix = $safeSerial
    }
}

$capturedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$runId = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$runDir = Join-Path $EvidenceDir $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$status = 'PENDING'
$reasons = New-Object System.Collections.Generic.List[string]
if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    $status = 'PENDING'
    $reasons.Add('adb is not installed or is not on PATH; no physical-device evidence was collected.')
    Set-Content -LiteralPath (Join-Path $runDir 'run.txt') -Value "capturedAtUtc=$capturedAt`nstatus=$status`nreason=$($reasons -join ' ')" -Encoding UTF8
    Write-Output "DEVICE_PREFLIGHT status=$status capturedAtUtc=$capturedAt evidenceDir=$runDir"
    Write-Output "REASON $($reasons -join ' ')"
    exit 0
}

$adbDevices = & adb devices 2>&1
if ($LASTEXITCODE -ne 0) {
    $status = 'PENDING'
    $reasons.Add('adb devices failed; transport state is unknown.')
    Set-Content -LiteralPath (Join-Path $runDir 'adb-devices.txt') -Value $adbDevices -Encoding UTF8
} else {
    Set-Content -LiteralPath (Join-Path $runDir 'adb-devices.txt') -Value $adbDevices -Encoding UTF8
}

$attached = @($adbDevices | Where-Object { $_ -match '^([^\s]+)\s+device$' } | ForEach-Object { ($_ -split '\s+')[0] })
$records = @()
if ($attached.Count -eq 0) {
    $reasons.Add('no authorized adb device is attached; real-watch and hotspot gates remain PENDING.')
} else {
    $reasons.Add("$($attached.Count) authorized adb device(s) attached; capture is diagnostic only and manual field tests remain required.")
    foreach ($serial in $attached) {
        $records += Save-DeviceEvidence -Serial $serial -DeviceDir $runDir -CapturedAtUtc $capturedAt
    }
}

if ($HotspotIsolationObserved) {
    $status = 'BLOCKED'
    $reasons.Add('hotspot station-to-station isolation was explicitly observed; use the documented alternate topology review.')
}

$manifest = [pscustomobject]@{
    CapturedAtUtc = $capturedAt
    Status = $status
    Host = $env:COMPUTERNAME
    PowerShell = $PSVersionTable.PSVersion.ToString()
    Devices = @($records)
    Notes = @($reasons)
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $runDir 'manifest.json') -Encoding UTF8
Set-Content -LiteralPath (Join-Path $runDir 'run.txt') -Value "capturedAtUtc=$capturedAt`nstatus=$status`nreason=$($reasons -join ' ')" -Encoding UTF8

Write-Output "DEVICE_PREFLIGHT status=$status capturedAtUtc=$capturedAt evidenceDir=$runDir"
foreach ($reason in $reasons) { Write-Output "REASON $reason" }
Write-Output 'PASS is intentionally unreachable: this command supplies evidence and does not certify physical acceptance.'
exit 0
