# Run database migrations on production
# This script fixes the 500 error by ensuring database tables exist

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "PRODUCTION DATABASE MIGRATIONS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Connecting to production VM..." -ForegroundColor Yellow

# Run migrations using the compiled JavaScript files
$command = @"
cd /opt/financial-rise && docker compose -f docker-compose.prod.yml exec -T backend sh -c 'cd /app && npm run build && npx typeorm migration:run -d dist/config/typeorm.config.js'
"@

gcloud compute ssh financial-rise-production-vm `
  --zone=us-central1-a `
  --project=financial-rise-prod `
  --tunnel-through-iap `
  --command=$command

Write-Host ""
Write-Host "✅ Migrations complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Testing registration endpoint..." -ForegroundColor Yellow

$body = @{
    email = "test@financialrise.com"
    password = "TestPass123!"
    first_name = "Test"
    last_name = "User"
    role = "consultant"
} | ConvertTo-Json

$response = Invoke-RestMethod -Uri "http://34.72.61.170/api/v1/auth/register" `
    -Method Post `
    -Body $body `
    -ContentType "application/json" `
    -ErrorAction SilentlyContinue

if ($response.access_token) {
    Write-Host "✅ Registration working!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Account created:" -ForegroundColor Green
    Write-Host "  Email: test@financialrise.com"
    Write-Host "  Password: TestPass123!"
} else {
    Write-Host "Response:" -ForegroundColor Yellow
    $response | ConvertTo-Json
}
