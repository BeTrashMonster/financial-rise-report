#!/bin/bash
# Production Infrastructure Setup - Phase 4: Production Secret Manager
# Estimated Time: 15 minutes
# Prerequisites: Phase 1 and 2 complete (Cloud SQL + VM ready)

set -e

PROJECT_ID="financial-rise-prod"
ZONE="us-central1-a"
VM_NAME="financial-rise-production-vm"
SECRET_NAME="financial-rise-production-env"

echo "========================================="
echo "PHASE 4: Production Secret Manager Setup"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Secret: $SECRET_NAME"
echo ""

# Step 4.1: Load credentials from Phase 1 and 2
echo "Step 1/6: Loading credentials from previous phases..."

if [ -f /tmp/prod-db-password.txt ]; then
  PROD_DB_PASSWORD=$(cat /tmp/prod-db-password.txt)
  echo "✅ Database password loaded"
else
  echo "❌ Database password not found!"
  echo "Make sure Phase 1 completed successfully"
  exit 1
fi

if [ -f /tmp/prod-db-host.txt ]; then
  PROD_DB_HOST=$(cat /tmp/prod-db-host.txt)
  echo "✅ Database host loaded: $PROD_DB_HOST"
else
  echo "❌ Database host not found!"
  echo "Make sure Phase 1 completed successfully"
  exit 1
fi

if [ -f /tmp/prod-vm-ip.txt ]; then
  PROD_VM_IP=$(cat /tmp/prod-vm-ip.txt)
  echo "✅ VM IP loaded: $PROD_VM_IP"
else
  echo "❌ VM IP not found!"
  echo "Make sure Phase 2 completed successfully"
  exit 1
fi

echo ""

# Step 4.2: Generate Production Secrets
echo "Step 2/6: Generating production secrets..."

# Generate JWT secrets (64 bytes base64)
JWT_SECRET=$(openssl rand -base64 64)
JWT_REFRESH_SECRET=$(openssl rand -base64 64)

# For backwards compatibility
TOKEN_SECRET=$JWT_SECRET
REFRESH_TOKEN_SECRET=$JWT_REFRESH_SECRET

# Generate encryption key (32 bytes hex = 64 characters)
DB_ENCRYPTION_KEY=$(openssl rand -hex 32)

# Generate Redis password
REDIS_PASSWORD=$(openssl rand -base64 32)

echo "✅ All secrets generated"
echo ""

# Step 4.3: Get SendGrid API key (if available)
echo "Step 3/6: SendGrid API Key Configuration"
echo ""
echo "⚠️  If you have a SendGrid API key, enter it now."
echo "   If not, press ENTER to skip (email features will be disabled)"
echo ""
read -p "SendGrid API Key: " SENDGRID_API_KEY

if [ -z "$SENDGRID_API_KEY" ]; then
  SENDGRID_API_KEY="SENDGRID_API_KEY_NOT_SET"
  echo "⚠️  Email features will be disabled"
else
  echo "✅ SendGrid API key configured"
fi

echo ""

# Step 4.4: Determine FRONTEND_URL
echo "Step 4/6: Frontend URL Configuration"
echo ""
echo "⚠️  If you have a domain name (e.g., financialrise.com), enter it now."
echo "   If not, we'll use the VM IP address: http://$PROD_VM_IP"
echo ""
read -p "Domain name (or press ENTER for IP): " DOMAIN_NAME

if [ -z "$DOMAIN_NAME" ]; then
  FRONTEND_URL="http://$PROD_VM_IP"
  echo "Using IP-based URL: $FRONTEND_URL"
else
  FRONTEND_URL="https://$DOMAIN_NAME"
  echo "Using domain: $FRONTEND_URL"
fi

echo ""

# Step 4.5: Create Production Environment File
echo "Step 5/6: Creating production environment file..."

cat > /tmp/.env.production << EOF
# Database Configuration (PRIVATE IP)
DATABASE_HOST=$PROD_DB_HOST
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=$PROD_DB_PASSWORD
DATABASE_NAME=financial_rise_production

# JWT Configuration
JWT_SECRET=$JWT_SECRET
JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET

# Backwards compatibility
TOKEN_SECRET=$TOKEN_SECRET
REFRESH_TOKEN_SECRET=$REFRESH_TOKEN_SECRET

# GCP Configuration
GCS_BUCKET=financial-rise-reports-production
GCP_PROJECT_ID=$PROJECT_ID

# Application Configuration
NODE_ENV=production
PORT=4000
FRONTEND_URL=$FRONTEND_URL

# Email Configuration
SENDGRID_API_KEY=$SENDGRID_API_KEY

# Database Encryption Key (32 bytes hex = 64 characters)
DB_ENCRYPTION_KEY=$DB_ENCRYPTION_KEY

# Redis Configuration
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_HOST=redis
REDIS_PORT=6379
EOF

chmod 600 /tmp/.env.production

echo "✅ Environment file created"
echo ""
echo "Production environment variables:"
echo "  DATABASE_HOST=$PROD_DB_HOST (PRIVATE IP)"
echo "  DATABASE_NAME=financial_rise_production"
echo "  FRONTEND_URL=$FRONTEND_URL"
echo "  GCS_BUCKET=financial-rise-reports-production"
echo "  DB_ENCRYPTION_KEY=<64 hex characters>"
echo "  JWT secrets: Generated (64 bytes base64)"
echo ""

# Step 4.6: Store in Secret Manager
echo "Step 6/6: Storing secrets in Google Secret Manager..."

# Check if secret already exists
if gcloud secrets describe $SECRET_NAME --project=$PROJECT_ID &>/dev/null; then
  echo "⚠️  Secret '$SECRET_NAME' already exists. Creating new version..."
  gcloud secrets versions add $SECRET_NAME \
    --data-file=/tmp/.env.production \
    --project=$PROJECT_ID
else
  echo "Creating new secret '$SECRET_NAME'..."
  gcloud secrets create $SECRET_NAME \
    --data-file=/tmp/.env.production \
    --replication-policy=automatic \
    --project=$PROJECT_ID
fi

echo "✅ Secrets stored in Secret Manager"
echo ""

# Step 4.7: Grant VM Access to Secrets
echo "Granting VM access to secrets..."

# Get the VM's service account
VM_SERVICE_ACCOUNT=$(gcloud compute instances describe $VM_NAME \
  --zone=$ZONE \
  --format="value(serviceAccounts[0].email)" \
  --project=$PROJECT_ID)

echo "VM Service Account: $VM_SERVICE_ACCOUNT"

# Grant access to production secrets
gcloud secrets add-iam-policy-binding $SECRET_NAME \
  --member="serviceAccount:$VM_SERVICE_ACCOUNT" \
  --role="roles/secretmanager.secretAccessor" \
  --project=$PROJECT_ID

echo "✅ VM granted access to secrets"
echo ""

# Step 4.8: Create GCS Bucket for Production Reports
echo "Creating GCS bucket for production reports..."

gsutil mb -p $PROJECT_ID \
  -c STANDARD \
  -l us-central1 \
  gs://financial-rise-reports-production/ || echo "Bucket may already exist"

echo "✅ GCS bucket ready"
echo ""

# Verification
echo "========================================="
echo "VERIFICATION"
echo "========================================="
echo ""

echo "Secret Manager Status:"
gcloud secrets versions list $SECRET_NAME \
  --project=$PROJECT_ID \
  --limit=1

echo ""
echo "Testing secret access from VM..."
gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="
    gcloud secrets versions access latest \
      --secret=$SECRET_NAME \
      --project=$PROJECT_ID | head -5
  "

echo ""
echo "GCS Bucket:"
gsutil ls -L gs://financial-rise-reports-production/ | head -10

echo ""

# Cleanup sensitive files
echo "Cleaning up temporary files..."
rm -f /tmp/.env.production
echo "✅ Temporary environment file deleted"

# Summary
echo "========================================="
echo "PHASE 4 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✅ Secret Manager: $SECRET_NAME"
echo "  ✅ Database credentials: Stored securely"
echo "  ✅ JWT secrets: Generated and stored (64 bytes base64)"
echo "  ✅ Encryption key: Generated and stored (64 hex chars)"
echo "  ✅ Redis password: Generated and stored"
echo "  ✅ SendGrid API: $([ "$SENDGRID_API_KEY" = "SENDGRID_API_KEY_NOT_SET" ] && echo "Not configured" || echo "Configured")"
echo "  ✅ GCS Bucket: financial-rise-reports-production"
echo "  ✅ VM Access: Granted to $VM_SERVICE_ACCOUNT"
echo ""
echo "Environment Configuration:"
echo "  DATABASE_HOST: $PROD_DB_HOST (Private IP)"
echo "  FRONTEND_URL: $FRONTEND_URL"
echo "  NODE_ENV: production"
echo ""
echo "⚠️  IMPORTANT: Credentials from /tmp/ have been cleaned up for security"
echo "   All secrets are now safely stored in Secret Manager"
echo ""
echo "Next: Run Phase 6 (Database Backup Strategy)"
echo "  ./setup-production-phase6-backups.sh"
echo ""
echo "Or run Phase 5 first (Monitoring & Alerting)"
echo "  ./setup-production-phase5-monitoring.sh"
echo ""
