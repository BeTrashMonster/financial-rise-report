# Simple setup for autonomous agent scheduled task
$TaskName = "FinancialRISE-AutonomousAgent"
$BashPath = "C:\Program Files\Git\bin\bash.exe"
$ScriptPath = "C:\Users\Admin\src\autonomous-agent.sh"

Write-Host "Setting up autonomous agent scheduled task..." -ForegroundColor Green
Write-Host ""

# Remove existing task if present
$Existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($Existing) {
    Write-Host "Removing existing task..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Create action
$Action = New-ScheduledTaskAction -Execute $BashPath -Argument "-c 'cd /c/Users/Admin/src && ./autonomous-agent.sh'" -WorkingDirectory "C:\Users\Admin\src"

# Create trigger - every 30 minutes for 12 hours
$StartTime = Get-Date
$Trigger = New-ScheduledTaskTrigger -Once -At $StartTime -RepetitionInterval (New-TimeSpan -Minutes 30) -RepetitionDuration (New-TimeSpan -Hours 12)

# Create settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

# Create principal
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

# Register task
Write-Host "Creating scheduled task..." -ForegroundColor Cyan
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous agent - runs every 30 minutes" -ErrorAction Stop | Out-Null

Write-Host ""
Write-Host "SUCCESS! Task created." -ForegroundColor Green
Write-Host ""
Write-Host "Schedule: Every 30 minutes for 12 hours" -ForegroundColor Yellow
Write-Host "Start time: $($StartTime.ToString('HH:mm'))" -ForegroundColor Yellow
Write-Host "End time: $($StartTime.AddHours(12).ToString('HH:mm'))" -ForegroundColor Yellow
Write-Host ""
Write-Host "View status: Get-ScheduledTask -TaskName '$TaskName'" -ForegroundColor White
Write-Host "Stop task: Disable-ScheduledTask -TaskName '$TaskName'" -ForegroundColor White
Write-Host "Remove task: Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false" -ForegroundColor White
Write-Host ""
