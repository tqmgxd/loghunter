$flags = @()
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Note: Non-elevated session - Security event log reading may be incomplete. Read-only mode, no changes will be applied." -ForegroundColor DarkYellow
}

Write-Host "SYSTEM BOOT TIME" -ForegroundColor Cyan
$os = Get-CimInstance Win32_OperatingSystem
$boot = $os.LastBootUpTime
$uptime = (Get-Date) - $boot
Write-Host "  Last Boot (WMI): $boot"
Write-Host "  Uptime (WMI): $($uptime.Days) days, $($uptime.Hours):$($uptime.Minutes):$($uptime.Seconds)"

$coreEventIds = 6005,6006,6008,6013,1074,41,12,13,104,7036,1102,4616
$coreEvents = Get-WinEvent -FilterHashtable @{LogName='System','Security'; Id=$coreEventIds} -MaxEvents 400 -ErrorAction SilentlyContinue
$bootEvents = $coreEvents | Where-Object { $_.LogName -eq 'System' -and $_.Id -in 6005,6006,6008,6013,1074,41,12,13 }

$lastStart12    = $bootEvents | Where-Object { $_.Id -eq 12 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastStop13     = $bootEvents | Where-Object { $_.Id -eq 13 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-General' } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastEvtStart6005 = $bootEvents | Where-Object { $_.Id -eq 6005 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastEvtStop6006  = $bootEvents | Where-Object { $_.Id -eq 6006 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastDirty6008    = $bootEvents | Where-Object { $_.Id -eq 6008 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$lastUnexpected41 = $bootEvents | Where-Object { $_.Id -eq 41 }   | Sort-Object TimeCreated -Descending | Select-Object -First 1
$last1074      = $bootEvents | Where-Object { $_.Id -eq 1074 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
$last6013      = $bootEvents | Where-Object { $_.Id -eq 6013 } | Sort-Object TimeCreated -Descending | Select-Object -First 1

$reliableBoot = $null
$reliableSource = $null
if ($lastStart12) {
    $reliableBoot = $lastStart12.TimeCreated
    $reliableSource = "Event ID 12 (Kernel-General, kernel startup)"
} elseif ($lastEvtStart6005) {
    $reliableBoot = $lastEvtStart6005.TimeCreated
    $reliableSource = "Event ID 6005 (Event Log service started)"
} else {
    $reliableBoot = $boot
    $reliableSource = "WMI Win32_OperatingSystem.LastBootUpTime (no Event 12/6005 available)"
}

Write-Host "  Last Boot (most reliable): $reliableBoot" -ForegroundColor Green
Write-Host "  Source: $reliableSource"

$deltaWmi = [math]::Abs(($reliableBoot - $boot).TotalSeconds)
if ($deltaWmi -gt 60) {
    Write-Host "  Discrepancy between Event boot time and WMI boot time: $([math]::Round($deltaWmi,1))s" -ForegroundColor Red
    $flags += "Last Boot Time from event log ($reliableSource) differs by more than 60s from WMI report - possible system clock tampering or log manipulation"
}

if ($lastUnexpected41 -and $lastUnexpected41.TimeCreated -lt $reliableBoot -and ((New-TimeSpan -Start $lastUnexpected41.TimeCreated -End $reliableBoot).TotalMinutes -lt 15)) {
    Write-Host "  Unclean shutdown detected prior to last boot (Event ID 41 - Kernel-Power): $($lastUnexpected41.TimeCreated)" -ForegroundColor Yellow
    $flags += "Abnormal/unplanned shutdown detected (Event ID 41, Kernel-Power) shortly before last boot - possible crash, power drop, or hard reset"
}

if ($lastDirty6008) {
    Write-Host "  Previous unexpected shutdown detected (Event ID 6008): $($lastDirty6008.TimeCreated)" -ForegroundColor Yellow
    $flags += "Previous unexpected shutdown detected (Event ID 6008) - system was not properly shut down in a past instance"
}

if ($last1074) {
    Write-Host "  Last user-initiated shutdown/reboot (Event ID 1074): $($last1074.TimeCreated)"
}
if ($lastEvtStop6006) {
    Write-Host "  Last clean shutdown logged (Event ID 6006): $($lastEvtStop6006.TimeCreated)"
}
if ($last6013) {
    Write-Host "  Last daily uptime report (Event ID 6013): $($last6013.TimeCreated)"
}
if (-not $bootEvents) {
    Write-Host "  No boot/shutdown events (6005/6006/6008/6013/1074/41/12/13) found in System log" -ForegroundColor DarkGray
}

$explorer = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Select-Object -First 1
if ($explorer) {
    $explorerStart = $explorer.CreationDate
    $delay = $explorerStart - $reliableBoot
    $suspicious = $delay.TotalMinutes -gt 5
    $c = if ($suspicious) { 'Red' } else { 'Green' }
    Write-Host "  Explorer.exe started: $explorerStart ($([math]::Round($delay.TotalSeconds,1))s after boot)" -ForegroundColor $c
    if ($suspicious) { $flags += "Explorer.exe started more than 5 minutes after boot - possible manual/delayed launch or anomalous session" }
} else {
    Write-Host "  Explorer.exe is not running" -ForegroundColor Red
    $flags += "explorer.exe is not running"
}

Write-Host "`nCONNECTED DRIVES" -ForegroundColor Cyan
Get-CimInstance Win32_LogicalDisk | ForEach-Object {
    Write-Host "  $($_.DeviceID) $($_.FileSystem)"
}

Write-Host "`nSERVICE STATUS" -ForegroundColor Cyan
$svcNames = @{
    SysMain   = "Superfetch/SysMain"
    PcaSvc    = "Program Compatibility Assistant"
    Bam       = "Background Activity Moderator"
    Schedule  = "Task Scheduler"
    EventLog  = "Windows Event Log"
    Dusmsvc   = "Data Usage"
    DPS       = "Diagnostic Policy Service"
    CDPSvc    = "Connected Devices Platform"
}
foreach ($name in $svcNames.Keys) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "  $name : NOT FOUND" -ForegroundColor DarkGray
        continue
    }
    $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host "  $name ($($svcNames[$name])): $($svc.Status) / StartType=$($svc.StartType)" -ForegroundColor $color
    if ($svc.StartType -eq 'Disabled') {
        $flags += "$name is set to Disabled (start type), not just stopped - strong anomaly"
    } elseif ($svc.Status -ne 'Running') {
        $flags += "$name is stopped (may be normal or indicate tampering)"
    }
}

Write-Host "`nREGISTRY" -ForegroundColor Cyan
$cmdDisabled = (Get-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\System" -Name DisableCMD -ErrorAction SilentlyContinue).DisableCMD
Write-Host "  CMD Disabled policy: $(if ($cmdDisabled) {$cmdDisabled} else {'Not Set'})"
if ($cmdDisabled -eq 1 -or $cmdDisabled -eq 2) { $flags += "CMD is disabled via Group Policy" }

$psLog = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
Write-Host "  PowerShell ScriptBlock Logging: $(if ($psLog -eq 1) {'Enabled'} else {'Disabled/Not Set'})"
if ($psLog -ne 1) { $flags += "PowerShell ScriptBlock Logging not enabled - reduces visibility on executed commands" }

$prefetch = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -ErrorAction SilentlyContinue).EnablePrefetcher
Write-Host "  Prefetch Enabled: $(if ($prefetch -gt 0) {'Enabled'} else {'Disabled'})"
if ($prefetch -eq 0) { $flags += "Prefetch disabled - reduces evidence of program execution" }

Write-Host "`nEVENT LOGS" -ForegroundColor Cyan
$sysCleared = $coreEvents | Where-Object { $_.LogName -eq 'System' -and $_.Id -eq 104 }
$shutdown = $last1074, $lastEvtStop6006 | Where-Object { $_ } | Sort-Object TimeCreated -Descending | Select-Object -First 1

$secCleared = $coreEvents | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 1102 }
$timeChange = $coreEvents | Where-Object { $_.LogName -eq 'Security' -and $_.Id -eq 4616 } | Select-Object -First 1

if ($secCleared) {
    foreach ($e in $secCleared) { Write-Host "  Security log cleared at: $($e.TimeCreated)" -ForegroundColor Red }
    $flags += "Security event log was cleared manually (Event ID 1102) - CRITICAL: if this matches check-up time, BAN for log clearing"
} else {
    Write-Host "  Security log: no clearance registered (Event ID 1102 not found)"
}

if ($sysCleared) {
    foreach ($e in $sysCleared) { Write-Host "  System log cleared at: $($e.TimeCreated)" -ForegroundColor Red }
    $flags += "System event log was cleared manually (Event ID 104) - CRITICAL: if this matches check-up time, BAN for log clearing"
} else {
    Write-Host "  System log: no clearance registered (Event ID 104 not found)"
}

if ($shutdown) { Write-Host "  Last PC Shutdown at: $($shutdown.TimeCreated)" }

if ($timeChange) {
    Write-Host "  System time changed at: $($timeChange.TimeCreated)" -ForegroundColor Yellow
    $flags += "Manual system clock change detected (Event ID 4616) - possible attempt to alter timestamps to disguise logs"
}

Write-Host "`nPROCESS CREATION (Event ID 4688)" -ForegroundColor Cyan
$procEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 50 -ErrorAction SilentlyContinue
if ($procEvents) {
    $suspiciousProcPattern = 'cmd\.exe|powershell\.exe|pwsh\.exe|\.bat$|\.ps1$|cheat|inject'
    $suspiciousProcs = $procEvents | Where-Object { $_.Message -match $suspiciousProcPattern }
    foreach ($e in ($suspiciousProcs | Select-Object -First 10)) {
        $nameLine = ($e.Message -split "`n" | Select-String 'New Process Name' | Select-Object -First 1)
        Write-Host "  $($e.TimeCreated): $($nameLine -replace '^\s+','')" -ForegroundColor Yellow
    }
    if ($suspiciousProcs) {
        $flags += "Suspicious process executions detected (cmd/powershell/script .bat/.ps1/cheat) via Event ID 4688 - $($suspiciousProcs.Count) occurrences"
    } else {
        $flags += "No suspicious processes detected among recent 4688 events"
    }
} else {
    Write-Host "  No 4688 events found (Process Creation Auditing likely disabled on this PC)" -ForegroundColor DarkGray
}

Write-Host "`nSERVICE STATE CHANGES (Event ID 7036)" -ForegroundColor Cyan
$svcEvents = $coreEvents | Where-Object { $_.LogName -eq 'System' -and $_.Id -eq 7036 }
if ($svcEvents) {
    $criticalSvcPattern = 'Windows Event Log|Windows Defender|Security Center|Sense|WinDefend'
    $criticalSvcStops = $svcEvents | Where-Object { $_.Message -match $criticalSvcPattern -and $_.Message -match 'stopped' }
    foreach ($e in ($criticalSvcStops | Select-Object -First 10)) {
        $msgOneLine = $e.Message -replace "`n", ' '
        Write-Host "  $($e.TimeCreated): $msgOneLine" -ForegroundColor Red
    }
    if ($criticalSvcStops) {
        $flags += "Forced shutdown of critical logging/security services detected (Event ID 7036) - $($criticalSvcStops.Count) occurrences"
    } else {
        Write-Host "  No suspicious critical service stops among recent 7036 events"
    }
} else {
    Write-Host "  No 7036 events found" -ForegroundColor DarkGray
}

Write-Host "`nUSB REMOVABLE STORAGE (Event ID 2003/2102)" -ForegroundColor Cyan
$usbEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DriverFrameworks-UserMode/Operational'; Id=2003,2102} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($usbEvents) {
    foreach ($e in $usbEvents) {
        $action = if ($e.Id -eq 2003) { 'Inserted' } else { 'Removed' }
        Write-Host "  $($e.TimeCreated): USB Drive $action (Event ID $($e.Id))" -ForegroundColor Yellow
    }
    $flags += "Detected $($usbEvents.Count) USB insertion/removal events (ID 2003/2102) - check if timing matches screen-check time (possible cheat flash drive)"
} else {
    Write-Host "  No USB events found in DriverFrameworks-UserMode/Operational log" -ForegroundColor DarkGray
}

$fsutilPath = "$env:WINDIR\System32\fsutil.exe"
$usn = & $fsutilPath usn queryjournal C: 2>&1
$lastDeleted = $null
if ($usn -match "not found" -or $usn -match "non trovato" -or $LASTEXITCODE -ne 0) {
    Write-Host "  USN Journal: not found/empty" -ForegroundColor Red
    $flags += "USN Journal absent - may have been deleted (fsutil usn deletejournal) to wipe filesystem traces"
} else {
    Write-Host "  USN Journal: present"
    $nextUsnLine = $usn | Select-String "Next Usn"
    if ($nextUsnLine -and $isAdmin) {
        $nextUsn = ($nextUsnLine -replace '\D', '')
        $startUsn = [int64]$nextUsn - 1500000
        if ($startUsn -lt 0) { $startUsn = 0 }
        $raw = & $fsutilPath usn readjournal C: startusn=$startUsn 2>&1
        $blocks = ($raw -join "`n") -split "(?=Usn\s*:)"
        $deletions = foreach ($b in $blocks) {
            if ($b -match 'Reason\s*:\s*.*FileDelete') {
                $fn = if ($b -match 'File name\s*:\s*(.+)') { $matches[1].Trim() } else { $null }
                $ts = if ($b -match 'Time [Ss]tamp\s*:\s*(.+)') { $matches[1].Trim() } else { $null }
                if ($fn -and $ts) {
                    [PSCustomObject]@{ FileName = $fn; TimeStamp = ($ts -as [datetime]) }
                }
            }
        }
        $lastDeleted = $deletions | Sort-Object TimeStamp -Descending | Select-Object -First 1
    } elseif (-not $isAdmin) {
        Write-Host "  (Administrator session required to read journal details and list the last deleted file)" -ForegroundColor DarkYellow
    }
}

Write-Host "`nPREFETCH" -ForegroundColor Cyan
$pfPath = "$env:WINDIR\Prefetch"
Write-Host "  Enabled: $(if ($prefetch -gt 0) {'Yes'} else {'No'})"
if (Test-Path $pfPath) {
    Write-Host "  Path: $pfPath"
} else {
    Write-Host "  Path not found (folder renamed/moved or access denied)" -ForegroundColor Yellow
    $flags += "Prefetch folder not found at standard path"
}

Write-Host "`nSTARTUP ITEMS" -ForegroundColor Cyan
$startupItems = Get-CimInstance Win32_StartupCommand
$suspiciousPathPattern = 'AppData\\Local\\Temp|\\Temp\\|Downloads'
foreach ($s in $startupItems) {
    $isSuspicious = $s.Command -match $suspiciousPathPattern
    $c = if ($isSuspicious) { 'Red' } else { 'DarkGray' }
    Write-Host "  [$($s.Location)] $($s.Name): $($s.Command)" -ForegroundColor $c
    if ($isSuspicious) { $flags += "Suspicious startup entry: $($s.Name) ($($s.Command))" }
}

Write-Host "`nRECYCLE BIN" -ForegroundColor Cyan
$shell = New-Object -ComObject Shell.Application
$recycleBin = $shell.Namespace(0xA)
$items = $recycleBin.Items()
Write-Host "  Total Items: $($items.Count)"
if ($items.Count -gt 0) {
    if ($items.Count -gt 500) {
        Write-Host "  Too many items ($($items.Count)) for a fast check - skipping date sorting" -ForegroundColor DarkGray
    } else {
        $lastItem = $items | Sort-Object { $recycleBin.GetDetailsOf($_, 2) -as [datetime] } -Descending | Select-Object -First 1
        if ($lastItem) {
            Write-Host "  Last deleted file still in Recycle Bin: $($lastItem.Name)"
            Write-Host "  Deletion Date: $($recycleBin.GetDetailsOf($lastItem, 2))"
        }
    }
} else {
    Write-Host "  Recycle Bin empty" -ForegroundColor Yellow
    $flags += "Recycle Bin is completely empty - possible recent manual purge (verify consistency with regular use)"
}
if ($lastDeleted) {
    Write-Host "  Last file deletion detected from USN Journal: $($lastDeleted.FileName) at $($lastDeleted.TimeStamp)" -ForegroundColor Yellow
} elseif ($isAdmin) {
    Write-Host "  No file deletions detected in analyzed journal range" -ForegroundColor DarkGray
}

Write-Host "`nSYSTEM BINARY INTEGRITY (calc.exe)" -ForegroundColor Cyan
$calcPath = "$env:WINDIR\System32\calc.exe"
if (Test-Path $calcPath) {
    $calcFile = Get-Item $calcPath
    $sig = Get-AuthenticodeSignature -FilePath $calcPath
    Write-Host "  Path: $calcPath"
    Write-Host "  Last Modified: $($calcFile.LastWriteTime)"
    Write-Host "  Size: $([math]::Round($calcFile.Length/1KB,2)) KB"
    $sigColor = if ($sig.Status -eq 'Valid') { 'Green' } else { 'Red' }
    Write-Host "  Digital Signature: $($sig.Status)" -ForegroundColor $sigColor
    if ($sig.Status -ne 'Valid') { $flags += "calc.exe lacks a valid digital signature (Status=$($sig.Status)) - possible binary planting/replacement" }
} else {
    Write-Host "  calc.exe not found at standard path - might be renamed or moved" -ForegroundColor Yellow
    $flags += "calc.exe absent from standard System32 path - verify if renamed or replaced"
}

Write-Host "`nCONSOLE HOST HISTORY" -ForegroundColor Cyan
$histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histPath) {
    $hist = Get-Item $histPath
    Write-Host "  Last Modified: $($hist.LastWriteTime)"
    Write-Host "  Size: $([math]::Round($hist.Length/1KB,2)) KB"
    if ($hist.Length -eq 0) { $flags += "ConsoleHost_history.txt exists but is empty - possible manual wipe of PowerShell history" }
} else {
    Write-Host "  File not found" -ForegroundColor Yellow
    $flags += "ConsoleHost_history.txt absent - PowerShell history was never created or was removed"
}

Write-Host "`nVERDICT" -ForegroundColor Cyan
if ($flags.Count -eq 0) {
    Write-Host "  No anomalies detected on these indicators." -ForegroundColor Green
} else {
    Write-Host "  $($flags.Count) anomalies detected:" -ForegroundColor Red
    $flags | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
}