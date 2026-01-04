# Deploy CORS Fix to Production
# This script builds the backend with updated CORS configuration and pushes to GCR

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "DEPLOYING CORS FIX TO PRODUCTION" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$PROJECT_ID = "financial-rise-prod"
$REGION = "us-central1"
$IMAGE_NAME = "backend"
$REGISTRY = "$REGION-docker.pkg.dev/$PROJECT_ID/financial-rise-docker"
$IMAGE_TAG = "$REGISTRY/${IMAGE_NAME}:latest"

Write-Host "Step 1: Building backend Docker image with CORS fix..." -ForegroundColor Yellow
Set-Location financial-rise-app\backend

docker build -t $IMAGE_TAG .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Backend image built successfully!" -ForegroundColor Green
Write-Host ""

Write-Host "Step 2: Pushing image to Google Container Registry..." -ForegroundColor Yellow
docker push $IMAGE_TAG

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker push failed!" -ForegroundColor Red
    Write-Host "You may need to run: gcloud auth configure-docker $REGION-docker.pkg.dev" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Image pushed to GCR successfully!" -ForegroundColor Green
Write-Host ""

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "DEPLOYMENT READY!" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps in GCP Console SSH:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Pull the new image:" -ForegroundColor White
Write-Host "   docker pull $IMAGE_TAG" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Stop the current backend:" -ForegroundColor White
Write-Host "   docker stop financial-rise-backend-prod" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Remove the old container:" -ForegroundColor White
Write-Host "   docker rm financial-rise-backend-prod" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Start the new backend:" -ForegroundColor White
Write-Host "   cd /opt/financial-rise" -ForegroundColor Gray
Write-Host "   docker compose -f docker-compose.prod.yml up -d backend" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Verify CORS origins:" -ForegroundColor White
Write-Host "   docker logs financial-rise-backend-prod | grep CORS" -ForegroundColor Gray
Write-Host ""
Write-Host "You should see 5 origins instead of 3!" -ForegroundColor Green
Write-Host ""
