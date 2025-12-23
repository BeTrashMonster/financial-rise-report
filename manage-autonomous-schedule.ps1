# manage-autonomous-schedule.ps1 - Manage the autonomous agent scheduled task
#
# Usage:
#   .\manage-autonomous-schedule.ps1 status
#   .\manage-autonomous-schedule.ps1 start
#   .\manage-autonomous-schedule.ps1 stop
#   .\manage-autonomous-schedule.ps1 remove
#   .\manage-autonomous-schedule.ps1 logs

param(
    [Parameter(Position=0)]
    [ValidateSet("status", "start", "stop", "remove", "logs", "history")]
    [string]$Action = "status"
)

$TaskName = "FinancialRISE-AutonomousAgent"
$LogDir = "C:\Users\Admin\src\agent-logs"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     AUTONOMOUS AGENT - TASK MANAGER                        ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

switch ($Action) {
    "status" {
        Write-Host "📊 Task Status:" -ForegroundColor Yellow
        Write-Host ""

        $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($Task) {
            Write-Host "  Name: $($Task.TaskName)" -ForegroundColor White
            Write-Host "  State: $($Task.State)" -ForegroundColor $(if ($Task.State -eq "Ready") { "Green" } else { "Yellow" })
            Write-Host ""

            $Info = Get-ScheduledTaskInfo -TaskName $TaskName
            Write-Host "  Last Run: $($Info.LastRunTime)" -ForegroundColor White
            Write-Host "  Last Result: $($Info.LastTaskResult)" -ForegroundColor $(if ($Info.LastTaskResult -eq 0) { "Green" } else { "Red" })
            Write-Host "  Next Run: $($Info.NextRunTime)" -ForegroundColor White
            Write-Host "  Run Count: $($Info.NumberOfMissedRuns)" -ForegroundColor White
            Write-Host ""

            # Show trigger details
            $Trigger = $Task.Triggers[0]
            Write-Host "  Schedule:" -ForegroundColor Yellow
            Write-Host "    Repetition Interval: $($Trigger.Repetition.Interval)" -ForegroundColor White
            Write-Host "    Repetition Duration: $($Trigger.Repetition.Duration)" -ForegroundColor White
            Write-Host "    Start Time: $($Trigger.StartBoundary)" -ForegroundColor White
            if ($Trigger.EndBoundary) {
                Write-Host "    End Time: $($Trigger.EndBoundary)" -ForegroundColor White
            }
        } else {
            Write-Host "  ⚠️  Task not found. Run setup-autonomous-schedule.ps1 to create it." -ForegroundColor Yellow
        }
        Write-Host ""
    }

    "start" {
        Write-Host "▶️  Starting task..." -ForegroundColor Yellow
        Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host "✅ Task enabled and ready to run" -ForegroundColor Green
        Write-Host ""
    }

    "stop" {
        Write-Host "⏸️  Stopping task..." -ForegroundColor Yellow
        Disable-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        Write-Host "✅ Task disabled (will not run automatically)" -ForegroundColor Green
        Write-Host ""
    }

    "remove" {
        Write-Host "🗑️  Removing task..." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Are you sure you want to remove the scheduled task? (Y/N): " -NoNewline -ForegroundColor Red
        $Confirm = Read-Host
        if ($Confirm -eq "Y" -or $Confirm -eq "y") {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            Write-Host "✅ Task removed" -ForegroundColor Green
        } else {
            Write-Host "❌ Cancelled" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    "logs" {
        Write-Host "📋 Recent Agent Logs:" -ForegroundColor Yellow
        Write-Host ""

        $Logs = Get-ChildItem $LogDir -Filter "*.log" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 10

        if ($Logs) {
            foreach ($Log in $Logs) {
                $SizeKB = [math]::Round($Log.Length / 1KB, 1)
                $Time = $Log.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "  $Time - $($Log.Name) ($SizeKB KB)" -ForegroundColor White
            }
            Write-Host ""
            Write-Host "Latest log:" -ForegroundColor Yellow
            Write-Host "  $($Logs[0].FullName)" -ForegroundColor Cyan
            Write-Host ""
            Write-Host "View with: Get-Content '$($Logs[0].FullName)'" -ForegroundColor Gray
        } else {
            Write-Host "  No logs found in $LogDir" -ForegroundColor Yellow
        }
        Write-Host ""
    }

    "history" {
        Write-Host "📜 Task History:" -ForegroundColor Yellow
        Write-Host ""

        # Get task history from Event Viewer
        $Events = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-TaskScheduler/Operational'
            ID = 100,102,103,110,111,200,201
        } -MaxEvents 50 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$TaskName*" } |
        Select-Object -First 20

        if ($Events) {
            foreach ($Event in $Events) {
                $Icon = switch ($Event.Id) {
                    100 { "▶️" }  # Task started
                    102 { "✅" }  # Task completed
                    103 { "❌" }  # Task failed
                    110 { "📅" }  # Task triggered
                    111 { "⏰" }  # Task missed
                    200 { "🔧" }  # Action started
                    201 { "✓" }  # Action completed
                    default { "📌" }
                }

                $Color = if ($Event.LevelDisplayName -eq "Error") { "Red" }
                         elseif ($Event.LevelDisplayName -eq "Warning") { "Yellow" }
                         else { "Green" }

                Write-Host "$Icon $($Event.TimeCreated.ToString('HH:mm:ss')) - $($Event.Message.Split("`n")[0].Substring(0, [Math]::Min(80, $Event.Message.Length)))" -ForegroundColor $Color
            }
        } else {
            Write-Host "  No history found. Task may not have run yet." -ForegroundColor Yellow
        }
        Write-Host ""
    }
}
