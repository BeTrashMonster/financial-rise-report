#!/bin/bash
# Configure Cloud SQL with private IP properly

set -e

echo "========================================="
echo "CONFIGURING CLOUD SQL PRIVATE IP"
echo "========================================="
echo ""

# Variables
PROJECT_ID="financial-rise-prod"
INSTANCE_NAME="financial-rise-production-db"
NETWORK="financial-rise-vpc"
REGION="us-central1"

echo "Step 1: Check if Service Networking API is enabled..."
gcloud services enable servicenetworking.googleapis.com --project=$PROJECT_ID
echo "✅ Service Networking API enabled"
echo ""

echo "Step 2: Allocate IP range for VPC peering..."
# Check if range already exists
if gcloud compute addresses describe google-managed-services-$NETWORK --global --project=$PROJECT_ID &>/dev/null; then
  echo "IP range already exists"
else
  gcloud compute addresses create google-managed-services-$NETWORK \
    --global \
    --purpose=VPC_PEERING \
    --prefix-length=16 \
    --network=$NETWORK \
    --project=$PROJECT_ID
  echo "✅ IP range allocated"
fi
echo ""

echo "Step 3: Create VPC peering connection..."
# Check if peering already exists
if gcloud services vpc-peerings list --network=$NETWORK --project=$PROJECT_ID 2>/dev/null | grep -q "servicenetworking"; then
  echo "VPC peering already exists"
else
  gcloud services vpc-peerings connect \
    --service=servicenetworking.googleapis.com \
    --ranges=google-managed-services-$NETWORK \
    --network=$NETWORK \
    --project=$PROJECT_ID
  echo "✅ VPC peering created"
fi
echo ""

echo "Step 4: Update Cloud SQL instance to use private IP..."
echo "WARNING: This will restart the database instance!"
echo "Press Ctrl+C to cancel, or Enter to continue..."
read

gcloud sql instances patch $INSTANCE_NAME \
  --network=projects/$PROJECT_ID/global/networks/$NETWORK \
  --no-assign-ip \
  --project=$PROJECT_ID

echo ""
echo "✅ Cloud SQL configured with private IP"
echo ""

echo "Step 5: Waiting for instance to be ready..."
gcloud sql operations wait \
  --project=$PROJECT_ID \
  $(gcloud sql operations list --instance=$INSTANCE_NAME --project=$PROJECT_ID --limit=1 --format="value(name)")

echo ""
echo "Step 6: Getting new private IP..."
PRIVATE_IP=$(gcloud sql instances describe $INSTANCE_NAME \
  --project=$PROJECT_ID \
  --format="value(ipAddresses.filter(type:PRIVATE).ipAddress.firstof())")

echo "✅ Cloud SQL Private IP: $PRIVATE_IP"
echo ""

echo "========================================="
echo "CONFIGURATION COMPLETE"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Update .env DATABASE_HOST to: $PRIVATE_IP"
echo "2. Update Secret Manager with new IP"
echo "3. Redeploy application"
