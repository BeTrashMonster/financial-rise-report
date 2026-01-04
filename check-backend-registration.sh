#!/bin/bash
# Check backend logs and test registration endpoint

set -e

echo "========================================"
echo "CHECKING BACKEND LOGS"
echo "========================================"
echo ""

echo "Fetching recent backend logs from production VM..."
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command='docker logs financial-rise-backend-prod --tail=100 2>&1' \
  2>/dev/null | tail -50

echo ""
echo "========================================"
echo "TESTING REGISTRATION ENDPOINT"
echo "========================================"
echo ""

echo "Testing POST /api/v1/auth/register..."
curl -X POST "http://34.72.61.170/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"TestPass123!","first_name":"Test","last_name":"User","role":"consultant"}' \
  -w "\n\nHTTP Status: %{http_code}\n"

echo ""
echo "Fetching logs after registration attempt..."
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command='docker logs financial-rise-backend-prod --tail=20 2>&1' \
  2>/dev/null
