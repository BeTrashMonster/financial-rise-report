# WSL Setup Script for Financial RISE Project
# Run this in PowerShell as Administrator

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "WSL Setup for Financial RISE Project" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To run as Administrator:" -ForegroundColor Yellow
    Write-Host "1. Right-click PowerShell" -ForegroundColor Yellow
    Write-Host "2. Select 'Run as Administrator'" -ForegroundColor Yellow
    Write-Host "3. Navigate to: cd C:\Users\Admin\src" -ForegroundColor Yellow
    Write-Host "4. Run: .\setup-wsl.ps1" -ForegroundColor Yellow
    pause
    exit 1
}

Write-Host "Step 1: Installing WSL and Ubuntu..." -ForegroundColor Green
Write-Host "This will install WSL 2 and Ubuntu 22.04 LTS" -ForegroundColor Gray
Write-Host ""

try {
    # Install WSL with Ubuntu
    wsl --install -d Ubuntu-22.04

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host "WSL Installation Started!" -ForegroundColor Green
    Write-Host "==================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT: Your computer will need to restart!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "After restart:" -ForegroundColor Cyan
    Write-Host "1. Ubuntu will launch automatically" -ForegroundColor White
    Write-Host "2. Create a Linux username (lowercase, no spaces)" -ForegroundColor White
    Write-Host "3. Create a password (you won't see it as you type)" -ForegroundColor White
    Write-Host "4. After setup completes, run: cd C:\Users\Admin\src" -ForegroundColor White
    Write-Host "5. Then run: .\wsl-project-setup.sh" -ForegroundColor White
    Write-Host ""

    $restart = Read-Host "Ready to restart now? (y/n)"
    if ($restart -eq 'y' -or $restart -eq 'Y') {
        Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
        Start-Sleep -Seconds 10
        Restart-Computer
    } else {
        Write-Host ""
        Write-Host "Remember to restart your computer to complete WSL installation!" -ForegroundColor Yellow
        Write-Host ""
    }

} catch {
    Write-Host "Error during installation: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "If WSL is already installed, you may see this error." -ForegroundColor Yellow
    Write-Host "Try running: wsl --list --verbose" -ForegroundColor Yellow
    Write-Host ""
    pause
}
