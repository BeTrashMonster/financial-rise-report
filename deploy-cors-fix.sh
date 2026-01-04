#!/bin/bash
# Deploy CORS fix to production VM
# Run this in your GCP Console SSH terminal

set -e

echo "========================================="
echo "DEPLOYING CORS FIX"
echo "========================================="
echo ""

echo "Step 1: Pulling latest image from GCR..."
docker pull us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker/backend:latest

echo ""
echo "Step 2: Stopping current backend..."
docker stop financial-rise-backend-prod || true

echo ""
echo "Step 3: Removing old container..."
docker rm financial-rise-backend-prod || true

echo ""
echo "Step 4: Starting new backend with CORS fix..."
cd /opt/financial-rise
docker compose -f docker-compose.prod.yml up -d backend

echo ""
echo "Step 5: Waiting for backend to start..."
sleep 10

echo ""
echo "Step 6: Checking CORS configuration..."
docker logs financial-rise-backend-prod 2>&1 | grep "CORS: Whitelisted origin"

echo ""
echo "========================================="
echo "DEPLOYMENT COMPLETE!"
echo "========================================="
echo ""
echo "You should see 5 whitelisted origins above:"
echo "  1. http://localhost:3001"
echo "  2. http://localhost:5173"
echo "  3. https://financialrise.org"
echo "  4. http://34.72.61.170"
echo "  5. http://getoffthemoneyshametrain.com"
echo ""
echo "Now try logging in at: http://34.72.61.170/login"
echo ""
