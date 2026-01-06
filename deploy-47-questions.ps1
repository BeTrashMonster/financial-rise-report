# Deploy 47-question structure from assessment-questions.json to production
# This replaces the old 66-question structure with the new unified format

Write-Host "🚀 Deploying 47-question structure to production..." -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  WARNING: This will DELETE all existing questions and responses!" -ForegroundColor Yellow
Write-Host "   - All assessment responses will be lost" -ForegroundColor Yellow
Write-Host "   - This is a destructive operation" -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Are you sure you want to continue? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "❌ Deployment cancelled" -ForegroundColor Red
    exit 1
}

# Set database environment variables for production
$env:DB_HOST = '34.134.76.171'
$env:DB_PORT = '5432'
$env:DB_USERNAME = 'financial_rise'
$env:DB_PASSWORD = 'ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE='
$env:DB_NAME = 'financial_rise_production'
$env:DB_SSL = 'true'

# Navigate to backend directory
Set-Location financial-rise-app\backend

Write-Host ""
Write-Host "📝 Running seed:questions script..." -ForegroundColor Cyan
npm run seed:questions

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Seeding failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Check the results
Write-Host ""
Write-Host "📊 Verifying question counts..." -ForegroundColor Cyan

$env:PGPASSWORD = $env:DB_PASSWORD
$query = @"
SELECT
  'Total questions:' as metric,
  COUNT(*)::text as count
FROM questions
UNION ALL
SELECT 'Phase questions:', COUNT(*)::text FROM questions WHERE question_type = 'phase'
UNION ALL
SELECT 'Phase+DISC questions:', COUNT(*)::text FROM questions WHERE question_type = 'phase_and_disc'
UNION ALL
SELECT 'Multiple choice questions:', COUNT(*)::text FROM questions WHERE question_type = 'multiple_choice'
UNION ALL
SELECT 'Rating questions:', COUNT(*)::text FROM questions WHERE question_type = 'rating'
UNION ALL
SELECT 'Metadata questions:', COUNT(*)::text FROM questions WHERE question_type = 'metadata';
"@

Write-Host $query | psql -h $env:DB_HOST -U $env:DB_USERNAME -d $env:DB_NAME

Write-Host ""
Write-Host "✅ 47-question deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Next steps:" -ForegroundColor Cyan
Write-Host "  1. Test the assessment workflow end-to-end"
Write-Host "  2. Verify multiple_choice question (BUILD-007) renders correctly"
Write-Host "  3. Verify rating question (SYS-009) renders correctly"
Write-Host "  4. Test auto-save functionality"
Write-Host "  5. Test submission and DISC/phase calculation"
Write-Host ""
