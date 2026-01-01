# Fix Display and Clipboard Issues
Write-Host "=== Display and Clipboard Fix Script ===" -ForegroundColor Cyan

# 1. Check current display configuration
Write-Host "`n1. Current Display Configuration:" -ForegroundColor Yellow
Add-Type -AssemblyName System.Windows.Forms
$screens = [System.Windows.Forms.Screen]::AllScreens
foreach ($screen in $screens) {
    Write-Host "  Device: $($screen.DeviceName)"
    Write-Host "  Bounds: $($screen.Bounds)"
    Write-Host "  Primary: $($screen.Primary)"
    Write-Host ""
}

# 2. Check monitor devices
Write-Host "2. Monitor Devices:" -ForegroundColor Yellow
Get-PnpDevice -Class Monitor | Select-Object Status, FriendlyName, InstanceId | Format-Table -AutoSize

# 3. Try to extend displays
Write-Host "3. Attempting to extend displays..." -ForegroundColor Yellow
try {
    $result = Start-Process -FilePath "DisplaySwitch.exe" -ArgumentList "/extend" -Wait -PassThru
    Write-Host "  DisplaySwitch result: $($result.ExitCode)" -ForegroundColor Green
} catch {
    Write-Host "  Failed to run DisplaySwitch: $_" -ForegroundColor Red
}

# 4. Force display detection
Write-Host "4. Forcing display detection..." -ForegroundColor Yellow
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class DisplayHelper {
    [DllImport("user32.dll")]
    public static extern int SendMessage(int hWnd, int hMsg, int wParam, int lParam);
}
"@
$result = [DisplayHelper]::SendMessage(0xffff, 0x112, 0xF170, 2)
Write-Host "  Detection result: $result" -ForegroundColor Green

# 5. Check display configuration again
Write-Host "`n5. Updated Display Configuration:" -ForegroundColor Yellow
Start-Sleep -Seconds 2
$screens = [System.Windows.Forms.Screen]::AllScreens
foreach ($screen in $screens) {
    Write-Host "  Device: $($screen.DeviceName)"
    Write-Host "  Bounds: $($screen.Bounds)"
    Write-Host "  Primary: $($screen.Primary)"
    Write-Host ""
}

# 6. Test clipboard
Write-Host "6. Testing Clipboard:" -ForegroundColor Yellow
try {
    $testText = "Clipboard test - " + (Get-Date).ToString()
    Set-Clipboard -Value $testText
    $clipboardContent = Get-Clipboard
    if ($clipboardContent -eq $testText) {
        Write-Host "  Clipboard is working correctly!" -ForegroundColor Green
        Write-Host "  Content: $clipboardContent"
    } else {
        Write-Host "  Clipboard test failed - content mismatch" -ForegroundColor Red
    }
} catch {
    Write-Host "  Clipboard error: $_" -ForegroundColor Red
}

Write-Host "`n=== Script Complete ===" -ForegroundColor Cyan
Write-Host "If second monitor still not working, try:" -ForegroundColor Yellow
Write-Host "  1. Press Win+P and select 'Extend'" -ForegroundColor Yellow
Write-Host "  2. Right-click desktop > Display settings" -ForegroundColor Yellow
Write-Host "  3. Check physical cable connections" -ForegroundColor Yellow
Write-Host "  4. Try Win+Ctrl+Shift+B to restart graphics driver" -ForegroundColor Yellow
