# Diagnose What Happened Overnight
Write-Host "=== Overnight System Diagnosis ===" -ForegroundColor Cyan

# 1. Check Windows Update history
Write-Host "`n1. Recent Windows Updates:" -ForegroundColor Yellow
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $historyCount = $searcher.GetTotalHistoryCount()
    $updates = $searcher.QueryHistory(0, [Math]::Min(10, $historyCount))

    foreach ($update in $updates) {
        Write-Host "  $($update.Date) - $($update.Title)" -ForegroundColor $(if ($update.ResultCode -eq 2) { "Green" } else { "Red" })
    }
} catch {
    Write-Host "  Could not retrieve update history: $_" -ForegroundColor Red
}

# 2. Check graphics driver info
Write-Host "`n2. Graphics Driver Information:" -ForegroundColor Yellow
Get-WmiObject Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, Status | Format-List

# 3. Check for recent driver changes
Write-Host "3. Recent Driver Events (last 24 hours):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 200 -ErrorAction SilentlyContinue |
  Where-Object { $_.ProviderName -like '*DriverFrameworks*' -or $_.ProviderName -like '*Display*' } |
  Select-Object TimeCreated, ProviderName, Message | Format-List

# 4. Check system power events (sleep/wake)
Write-Host "4. Sleep/Wake Events (last 24 hours):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1,42,107; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Message | Format-List

# 5. Check running background tasks related to updates
Write-Host "5. Running Update/Maintenance Tasks:" -ForegroundColor Yellow
Get-ScheduledTask | Where-Object { $_.State -eq 'Running' -and ($_.TaskName -like '*Update*' -or $_.TaskName -like '*Maintenance*') } |
  Select-Object TaskName, State | Format-Table

# 6. Check if any processes are holding display configuration
Write-Host "6. Graphics-related Processes:" -ForegroundColor Yellow
Get-Process | Where-Object { $_.ProcessName -like '*dwm*' -or $_.ProcessName -like '*explorer*' -or $_.ProcessName -like '*nvidia*' -or $_.ProcessName -like '*amd*' -or $_.ProcessName -like '*intel*' } |
  Select-Object ProcessName, Id, StartTime | Format-Table

Write-Host "`n=== End Diagnosis ===" -ForegroundColor Cyan
