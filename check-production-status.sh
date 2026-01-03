#!/bin/bash
# Check production VM status and logs

echo "========================================="
echo "PRODUCTION STATUS CHECK"
echo "========================================="
echo ""

echo "1. Checking container status..."
echo "-----------------------------------"
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command="docker ps -a"

echo ""
echo "2. Checking backend logs (last 50 lines)..."
echo "-----------------------------------"
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command="docker logs financial-rise-backend-prod --tail 50"

echo ""
echo "3. Checking frontend logs (last 30 lines)..."
echo "-----------------------------------"
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command="docker logs financial-rise-frontend-prod --tail 30"

echo ""
echo "4. Testing health endpoints directly from VM..."
echo "-----------------------------------"
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command="
    echo 'Backend health:'
    curl -s http://localhost:4000/api/v1/health || echo 'Backend not responding'
    echo ''
    echo 'Frontend health:'
    curl -s -I http://localhost:80/ | head -5 || echo 'Frontend not responding'
  "

echo ""
echo "========================================="
echo "STATUS CHECK COMPLETE"
echo "========================================="
