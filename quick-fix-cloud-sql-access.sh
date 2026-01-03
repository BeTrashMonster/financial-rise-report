#!/bin/bash
# Quick fix: Add production VM to Cloud SQL authorized networks

set -e

echo "========================================="
echo "QUICK FIX: AUTHORIZE VM FOR CLOUD SQL"
echo "========================================="
echo ""

PROJECT_ID="financial-rise-prod"
INSTANCE_NAME="financial-rise-production-db"

echo "Step 1: Getting production VM's public IP..."
VM_IP=$(gcloud compute instances describe financial-rise-production-vm \
  --zone=us-central1-a \
  --project=$PROJECT_ID \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo "Production VM public IP: $VM_IP"
echo ""

echo "Step 2: Adding VM IP to Cloud SQL authorized networks..."
gcloud sql instances patch $INSTANCE_NAME \
  --authorized-networks=$VM_IP \
  --project=$PROJECT_ID

echo ""
echo "✅ VM authorized to access Cloud SQL"
echo ""

echo "Waiting for change to take effect..."
sleep 10

echo ""
echo "========================================="
echo "QUICK FIX COMPLETE"
echo "========================================="
echo ""
echo "The backend should now be able to connect to Cloud SQL."
echo "Test by restarting the backend container:"
echo "  gcloud compute ssh financial-rise-production-vm --zone=us-central1-a --project=financial-rise-prod --command='cd /opt/financial-rise && docker compose -f docker-compose.prod.yml restart backend'"
echo ""
echo "NOTE: This is a temporary fix using public IP."
echo "For production, run: bash fix-cloud-sql-private-ip.sh"
