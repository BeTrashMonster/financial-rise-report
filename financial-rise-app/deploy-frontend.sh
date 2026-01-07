#!/bin/bash

#################################################
# Financial RISE - Frontend Deployment Script
#
# This script deploys frontend changes to production
# by SSHing into the GCP VM, rebuilding the Docker
# image, and restarting the containers.
#################################################

set -e  # Exit on error

echo "========================================="
echo "Financial RISE - Frontend Deployment"
echo "========================================="
echo ""

# Configuration
PROJECT_ID="financial-rise-prod"
VM_NAME="financial-rise-vm"
ZONE="us-central1-a"
DOMAIN="getoffthemoneyshametrain.com"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo "❌ Error: gcloud CLI is not installed or not in PATH"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

echo "✅ gcloud CLI found"
echo ""

# Check if authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "."; then
    echo "❌ Error: Not authenticated with gcloud"
    echo "Run: gcloud auth login"
    exit 1
fi

echo "✅ Authenticated with gcloud"
echo ""

# Set project
echo "Setting GCP project to: $PROJECT_ID"
gcloud config set project $PROJECT_ID
echo ""

# SSH into the VM and run deployment commands
echo "🚀 Connecting to production server..."
echo "VM: $VM_NAME"
echo "Zone: $ZONE"
echo ""

gcloud compute ssh $VM_NAME --zone=$ZONE --command="
set -e

echo '========================================='
echo '  Running deployment on production VM'
echo '========================================='
echo ''

# Navigate to project directory
cd /opt/financial-rise-app || cd ~/financial-rise-app || {
    echo '❌ Error: Could not find project directory'
    exit 1
}

echo '📂 Current directory:'
pwd
echo ''

# Pull latest code
echo '📥 Pulling latest code from Git...'
git fetch origin
git pull origin main
echo ''

# Check if docker-compose exists
if ! command -v docker &> /dev/null; then
    echo '❌ Error: Docker is not installed on the VM'
    exit 1
fi

echo '✅ Docker found'
echo ''

# Rebuild frontend Docker image
echo '🔨 Rebuilding frontend Docker image...'
docker compose -f docker-compose.prod.yml build frontend
echo ''

# Restart frontend container
echo '🔄 Restarting frontend container...'
docker compose -f docker-compose.prod.yml up -d frontend
echo ''

# Check container status
echo '📊 Container status:'
docker compose -f docker-compose.prod.yml ps
echo ''

# Check frontend logs
echo '📝 Recent frontend logs:'
docker compose -f docker-compose.prod.yml logs --tail=20 frontend
echo ''

echo '========================================='
echo '  Deployment completed on production VM'
echo '========================================='
"

EXIT_CODE=$?

echo ""
echo "========================================="
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Deployment completed successfully!"
    echo ""
    echo "🌐 Frontend URL: https://$DOMAIN"
    echo ""
    echo "Next steps:"
    echo "1. Test the site at: https://$DOMAIN"
    echo "2. Try completing an assessment"
    echo "3. Check browser console for errors"
    echo ""
    echo "To view live logs:"
    echo "  gcloud compute ssh $VM_NAME --zone=$ZONE --command=\"docker compose -f /opt/financial-rise-app/docker-compose.prod.yml logs -f frontend\""
else
    echo "❌ Deployment failed with exit code: $EXIT_CODE"
    echo ""
    echo "To troubleshoot:"
    echo "1. SSH into the VM:"
    echo "   gcloud compute ssh $VM_NAME --zone=$ZONE"
    echo "2. Check Docker logs:"
    echo "   cd /opt/financial-rise-app"
    echo "   docker compose -f docker-compose.prod.yml logs frontend"
    echo "3. Check container status:"
    echo "   docker compose -f docker-compose.prod.yml ps"
fi
echo "========================================="

exit $EXIT_CODE
