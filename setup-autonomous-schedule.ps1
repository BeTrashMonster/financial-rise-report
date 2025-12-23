# setup-autonomous-schedule.ps1 - Schedule autonomous agent to run every 30 minutes for 12 hours

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     AUTONOMOUS AGENT - SCHEDULED TASK SETUP                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Configuration
$TaskName = "FinancialRISE-AutonomousAgent"
$ScriptPath = "C:\Users\Admin\src\autonomous-agent.sh"
$BashPath = "C:\Program Files\Git\bin\bash.exe"
$LogDir = "C:\Users\Admin\src\agent-logs"
$Duration = 12 # hours
$Interval = 30 # minutes

# Calculate end time
$StartTime = Get-Date
$EndTime = $StartTime.AddHours($Duration)

Write-Host "📋 Configuration:" -ForegroundColor Yellow
Write-Host "  Task Name: $TaskName"
Write-Host "  Script: $ScriptPath"
Write-Host "  Start Time: $($StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "  End Time: $($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Host "  Interval: Every $Interval minutes"
Write-Host "  Duration: $Duration hours"
Write-Host ""

# Check if task already exists
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($ExistingTask) {
    Write-Host "⚠️  Task '$TaskName' already exists. Removing..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "✓ Removed existing task" -ForegroundColor Green
    Write-Host ""
}

# Create the action (run bash script)
$Action = New-ScheduledTaskAction -Execute $BashPath -Argument "-c 'cd /c/Users/Admin/src && ./autonomous-agent.sh'" -WorkingDirectory "C:\Users\Admin\src"

# Create the trigger (every 30 minutes for 12 hours)
$Trigger = New-ScheduledTaskTrigger -Once -At $StartTime -RepetitionInterval (New-TimeSpan -Minutes $Interval) -RepetitionDuration (New-TimeSpan -Hours $Duration)

# Create settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

# Create the principal (run as current user)
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

# Register the task
Write-Host "🔧 Creating scheduled task..." -ForegroundColor Cyan

try {
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description "Autonomous agent for Financial RISE roadmap - runs every 30 minutes" -ErrorAction Stop | Out-Null

    Write-Host "✅ Scheduled task created successfully!" -ForegroundColor Green
    Write-Host ""

    # Display schedule
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host "📅 EXECUTION SCHEDULE:" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host ""

    $CurrentTime = $StartTime
    $ExecutionNumber = 1

    while ($CurrentTime -le $EndTime) {
        Write-Host "  #$($ExecutionNumber.ToString().PadLeft(2)) - $($CurrentTime.ToString('HH:mm:ss'))" -ForegroundColor White
        $CurrentTime = $CurrentTime.AddMinutes($Interval)
        $ExecutionNumber++
    }

    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host ""
    Write-Host "📊 Total executions: $($ExecutionNumber - 1)" -ForegroundColor Cyan
    Write-Host "📁 Logs directory: $LogDir" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host ""
    Write-Host "🎯 MANAGEMENT COMMANDS:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  View status:" -ForegroundColor White
    Write-Host "    powershell .\manage-autonomous-schedule.ps1 status"
    Write-Host ""
    Write-Host "  Stop task:" -ForegroundColor White
    Write-Host "    powershell .\manage-autonomous-schedule.ps1 stop"
    Write-Host ""
    Write-Host "  View logs:" -ForegroundColor White
    Write-Host "    powershell .\manage-autonomous-schedule.ps1 logs"
    Write-Host ""
    Write-Host "  Remove task:" -ForegroundColor White
    Write-Host "    powershell .\manage-autonomous-schedule.ps1 remove"
    Write-Host ""
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Gray
    Write-Host ""
    Write-Host "✅ Setup complete! The autonomous agent will run automatically." -ForegroundColor Green
    Write-Host "   First execution: $($StartTime.ToString('HH:mm:ss'))" -ForegroundColor Green
    Write-Host "   Final execution: ~$($EndTime.ToString('HH:mm:ss'))" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "❌ Error creating scheduled task:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "💡 Try running PowerShell as Administrator" -ForegroundColor Yellow
    exit 1
}
