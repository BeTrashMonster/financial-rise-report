# Intel Graphics Driver Update Helper
Write-Host "=== Intel Graphics Driver Update Helper ===" -ForegroundColor Cyan

# Get current driver info
Write-Host "`nCurrent Graphics Driver:" -ForegroundColor Yellow
$gpu = Get-WmiObject Win32_VideoController
Write-Host "  Name: $($gpu.Name)"
Write-Host "  Driver Version: $($gpu.DriverVersion)"
Write-Host "  Driver Date: $($gpu.DriverDate.Substring(0,8))" -ForegroundColor Red
Write-Host "  ^^^ This driver is from 2015! ^^^" -ForegroundColor Red

# Get hardware ID for driver lookup
Write-Host "`nHardware Information:" -ForegroundColor Yellow
$videoDevice = Get-WmiObject Win32_PnPEntity | Where-Object { $_.PNPClass -eq 'Display' }
foreach ($device in $videoDevice) {
    Write-Host "  Device ID: $($device.DeviceID)"
    Write-Host "  Hardware ID: $($device.HardwareID)"
}

Write-Host "`n=== Recommended Actions ===" -ForegroundColor Cyan
Write-Host "1. MANUAL UPDATE (Recommended):" -ForegroundColor Yellow
Write-Host "   a. Go to: https://www.intel.com/content/www/us/en/download-center/home.html"
Write-Host "   b. Search for 'Intel HD Graphics Driver'"
Write-Host "   c. Download the latest driver for your processor generation"
Write-Host "   d. Install and restart your computer"
Write-Host ""
Write-Host "2. AUTOMATIC UPDATE (Try this first):" -ForegroundColor Yellow
Write-Host "   a. Open Device Manager (devmgmt.msc)"
Write-Host "   b. Expand 'Display adapters'"
Write-Host "   c. Right-click 'Intel(R) HD Graphics Family'"
Write-Host "   d. Select 'Update driver'"
Write-Host "   e. Choose 'Search automatically for drivers'"
Write-Host ""
Write-Host "3. WINDOWS UPDATE:" -ForegroundColor Yellow
Write-Host "   a. Settings > Update & Security > Windows Update"
Write-Host "   b. Click 'Check for updates'"
Write-Host "   c. Look for optional driver updates"
Write-Host ""
Write-Host "4. TEMPORARY WORKAROUND (Until driver is updated):" -ForegroundColor Yellow
Write-Host "   After updating the driver, if the second monitor still doesn't work:"
Write-Host "   - Restart the computer (full restart, not sleep/wake)"
Write-Host "   - Check cable connections"
Write-Host "   - Try a different video port if available"

Write-Host "`n=== Would you like me to open Device Manager? ===" -ForegroundColor Cyan
$response = Read-Host "Open Device Manager now? (y/n)"
if ($response -eq 'y') {
    Start-Process devmgmt.msc
    Write-Host "Device Manager opened. Follow step 2 above." -ForegroundColor Green
}

Write-Host "`nNote: A 2015 graphics driver is the root cause of your display issue." -ForegroundColor Red
Write-Host "Updating to a modern driver will fix the sleep/wake display problems." -ForegroundColor Green
