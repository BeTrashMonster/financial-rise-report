# Get backend container logs from production VM
gcloud compute ssh financial-rise-prod-vm `
  --zone=us-central1-a `
  --project=financial-rise-prod `
  --command="docker logs financial-rise-backend-prod --tail 100 2>&1"
