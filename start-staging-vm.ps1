# Start Staging VM
Write-Host "Starting staging VM..."
Write-Host ""

gcloud compute instances start financial-rise-staging-vm `
  --zone=us-central1-a `
  --project=financial-rise-prod

Write-Host ""
Write-Host "Waiting for VM to be RUNNING..."
Start-Sleep -Seconds 10

Write-Host ""
Write-Host "Checking VM status:"
gcloud compute instances describe financial-rise-staging-vm `
  --zone=us-central1-a `
  --project=financial-rise-prod `
  --format="get(status)"

Write-Host ""
Write-Host "✅ Staging VM started"
