# Verify Secret Manager Contents
Write-Host "========================================="
Write-Host "SECRET MANAGER VERIFICATION"
Write-Host "========================================="
Write-Host ""

Write-Host "Checking all versions of production secret..."
Write-Host ""

# List all versions
Write-Host "Available versions:"
gcloud secrets versions list financial-rise-production-env --project=financial-rise-prod

Write-Host ""
Write-Host "========================================="
Write-Host "VERSION 3 CONTENTS (first 20 lines):"
Write-Host "========================================="
gcloud secrets versions access 3 --secret=financial-rise-production-env --project=financial-rise-prod | Select-Object -First 20

Write-Host ""
Write-Host "========================================="
Write-Host "LATEST VERSION CONTENTS (first 20 lines):"
Write-Host "========================================="
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | Select-Object -First 20

Write-Host ""
Write-Host "========================================="
Write-Host "CHECKING JWT_REFRESH_SECRET SPECIFICALLY:"
Write-Host "========================================="
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | Select-String "JWT_REFRESH_SECRET"

Write-Host ""
Write-Host "Verification complete."
