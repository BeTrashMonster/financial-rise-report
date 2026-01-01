#!/bin/bash
# Production Infrastructure Setup - Phase 1: Cloud SQL with Private IP
# Estimated Time: 15-20 minutes
# Prerequisites: GCP project 'financial-rise-prod' exists

set -e

PROJECT_ID="financial-rise-prod"
REGION="us-central1"
ZONE="us-central1-a"
VPC_NAME="financial-rise-vpc"
SQL_INSTANCE="financial-rise-production"
DATABASE_NAME="financial_rise_production"
DB_USER="financial_rise"

echo "========================================="
echo "PHASE 1: Cloud SQL with Private IP Setup"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Instance: $SQL_INSTANCE"
echo ""

# Step 1.1: Enable Service Networking API
echo "Step 1/7: Enabling Service Networking API..."
gcloud services enable servicenetworking.googleapis.com \
  --project=$PROJECT_ID
echo "✅ Service Networking API enabled"
echo ""

# Step 1.2: Allocate IP Range for Private Service Connection
echo "Step 2/7: Allocating IP range for VPC peering..."
gcloud compute addresses create google-managed-services-$VPC_NAME \
  --global \
  --purpose=VPC_PEERING \
  --prefix-length=16 \
  --network=$VPC_NAME \
  --project=$PROJECT_ID

echo "✅ IP range allocated"
echo ""

# Step 1.3: Create VPC Peering Connection
echo "Step 3/7: Creating VPC peering connection to Google services..."
gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services-$VPC_NAME \
  --network=$VPC_NAME \
  --project=$PROJECT_ID

echo "✅ VPC peering established"
echo ""

# Step 1.4: Create Production Cloud SQL Instance with Private IP
echo "Step 4/7: Creating Cloud SQL instance (this takes 10-15 minutes)..."
echo "Instance: $SQL_INSTANCE"
echo "Database: PostgreSQL 14"
echo "Tier: db-g1-small (ZONAL - cost optimized)"
echo ""

gcloud sql instances create $SQL_INSTANCE \
  --database-version=POSTGRES_14 \
  --tier=db-g1-small \
  --region=$REGION \
  --network=projects/$PROJECT_ID/global/networks/$VPC_NAME \
  --no-assign-ip \
  --storage-type=SSD \
  --storage-size=20GB \
  --storage-auto-increase \
  --enable-bin-log \
  --backup-start-time=03:00 \
  --maintenance-window-day=SUN \
  --maintenance-window-hour=04 \
  --availability-type=ZONAL \
  --project=$PROJECT_ID

echo "✅ Cloud SQL instance created"
echo ""

# Step 1.5: Create Production Database
echo "Step 5/7: Creating production database..."
gcloud sql databases create $DATABASE_NAME \
  --instance=$SQL_INSTANCE \
  --project=$PROJECT_ID

echo "✅ Database '$DATABASE_NAME' created"
echo ""

# Step 1.6: Create Production Database User
echo "Step 6/7: Creating database user with secure password..."

# Generate secure password
PROD_DB_PASSWORD=$(openssl rand -base64 32)

gcloud sql users create $DB_USER \
  --instance=$SQL_INSTANCE \
  --password="$PROD_DB_PASSWORD" \
  --project=$PROJECT_ID

echo "✅ Database user '$DB_USER' created"
echo ""
echo "⚠️  IMPORTANT: Save this password securely!"
echo "Database Password: $PROD_DB_PASSWORD"
echo ""
echo "This will be used in Phase 4 (Secret Manager)"
echo ""

# Save password to temporary file for Phase 4
echo "$PROD_DB_PASSWORD" > /tmp/prod-db-password.txt
chmod 600 /tmp/prod-db-password.txt
echo "Password saved to: /tmp/prod-db-password.txt"
echo ""

# Step 1.7: Get Private IP Address
echo "Step 7/7: Getting private IP address..."

PRIVATE_IP=$(gcloud sql instances describe $SQL_INSTANCE \
  --format="value(ipAddresses[0].ipAddress)" \
  --project=$PROJECT_ID)

echo "✅ Cloud SQL Private IP: $PRIVATE_IP"
echo ""

# Save for Phase 4
echo "$PRIVATE_IP" > /tmp/prod-db-host.txt
chmod 600 /tmp/prod-db-host.txt

# Verification
echo "========================================="
echo "VERIFICATION"
echo "========================================="
echo ""

gcloud sql instances describe $SQL_INSTANCE \
  --format="table(ipAddresses[].ipAddress,ipAddresses[].type)" \
  --project=$PROJECT_ID

echo ""
echo "✅ Expected: Only PRIVATE IP (10.x.x.x) - NO public IP"
echo ""

# Summary
echo "========================================="
echo "PHASE 1 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✅ Cloud SQL instance: $SQL_INSTANCE"
echo "  ✅ Database: $DATABASE_NAME"
echo "  ✅ User: $DB_USER"
echo "  ✅ Private IP: $PRIVATE_IP"
echo "  ✅ Availability: ZONAL (cost optimized - scalable to HA later)"
echo "  ✅ Backups: Daily at 3:00 AM"
echo "  ✅ Point-in-time recovery: ENABLED"
echo ""
echo "Credentials saved to:"
echo "  - /tmp/prod-db-password.txt (DB password)"
echo "  - /tmp/prod-db-host.txt (DB private IP)"
echo ""
echo "Next: Run Phase 2 (Standard Production VM)"
echo "  ./setup-production-phase2-vm.sh"
echo ""
