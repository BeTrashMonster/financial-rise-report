# PowerShell script to encode the service account key for GitHub Secrets
# Run this after setup-gcp-infrastructure.sh completes

$keyFile = "github-actions-key.json"

if (Test-Path $keyFile) {
    Write-Host "Reading service account key..." -ForegroundColor Green
    $keyContent = Get-Content $keyFile -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($keyContent)
    $encoded = [System.Convert]::ToBase64String($bytes)

    # Save to file
    $encoded | Out-File "github-actions-key-base64.txt" -NoNewline

    Write-Host "`n✅ Service account key encoded successfully!" -ForegroundColor Green
    Write-Host "`nEncoded key saved to: github-actions-key-base64.txt" -ForegroundColor Yellow
    Write-Host "`nCopy the contents of this file and paste it as the GCP_SA_KEY secret in GitHub." -ForegroundColor Cyan
    Write-Host "GitHub Secrets URL: https://github.com/BeTrashMonster/financial-rise-report/settings/secrets/actions" -ForegroundColor Cyan

    # Also copy to clipboard if available
    if (Get-Command "Set-Clipboard" -ErrorAction SilentlyContinue) {
        $encoded | Set-Clipboard
        Write-Host "`n📋 Encoded key copied to clipboard!" -ForegroundColor Green
    }
} else {
    Write-Host "❌ Error: github-actions-key.json not found" -ForegroundColor Red
    Write-Host "Make sure you run setup-gcp-infrastructure.sh first" -ForegroundColor Yellow
}
