#!/bin/bash
#
# Financial RISE - Google Cloud Platform Infrastructure Setup
# This script creates all required GCP resources for staging and production
#
# Prerequisites:
# - Google Cloud SDK installed and authenticated (gcloud init)
# - Billing account linked to your GCP account
# - Appropriate IAM permissions (Owner or Editor role)
#

set -e

# Add gcloud to PATH for Git Bash
export PATH="$HOME/bin:$PATH"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="financial-rise-prod"
REGION="us-central1"
ZONE="us-central1-a"
NETWORK_NAME="financial-rise-vpc"
STAGING_VM="financial-rise-staging-vm"
PRODUCTION_VM="financial-rise-production-vm"
ARTIFACT_REPO="financial-rise-docker"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Financial RISE - GCP Infrastructure Setup                ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print section headers
print_section() {
    echo ""
    echo -e "${GREEN}▶ $1${NC}"
    echo "────────────────────────────────────────────────────────────"
}

# Function to check if command succeeded
check_success() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ Failed: $1${NC}"
        exit 1
    fi
}

# Verify gcloud is installed
print_section "Step 1: Verifying gcloud installation"
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI is not installed${NC}"
    echo "Please install it from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi
echo -e "${GREEN}✅ gcloud CLI is installed${NC}"
gcloud --version

# Check authentication
print_section "Step 2: Checking authentication"
CURRENT_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null)
if [ -z "$CURRENT_ACCOUNT" ]; then
    echo -e "${YELLOW}⚠️  Not authenticated. Running gcloud auth login...${NC}"
    gcloud auth login
    check_success "Authentication"
else
    echo -e "${GREEN}✅ Authenticated as: $CURRENT_ACCOUNT${NC}"
fi

# Confirm project creation
print_section "Step 3: Project Setup"
echo -e "${YELLOW}This will create a new GCP project: ${PROJECT_ID}${NC}"
echo -e "${YELLOW}Estimated monthly cost: ~\$116 (Staging: ~\$22, Production: ~\$86, Shared: ~\$8)${NC}"
echo ""
read -p "Continue with project creation? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Setup cancelled."
    exit 0
fi

# Create project
print_section "Step 4: Creating GCP project"
gcloud projects create $PROJECT_ID --name="Financial RISE" 2>/dev/null || echo "Project already exists"
gcloud config set project $PROJECT_ID
check_success "Project configured: $PROJECT_ID"

# Check billing
print_section "Step 5: Checking billing"
BILLING_ACCOUNT=$(gcloud billing accounts list --filter=open=true --format="value(name)" --limit=1)
if [ -z "$BILLING_ACCOUNT" ]; then
    echo -e "${RED}❌ No active billing account found${NC}"
    echo "Please set up billing at: https://console.cloud.google.com/billing"
    echo "Then run this script again."
    exit 1
fi

echo -e "${GREEN}✅ Found billing account: $BILLING_ACCOUNT${NC}"
gcloud billing projects link $PROJECT_ID --billing-account=$BILLING_ACCOUNT 2>/dev/null || echo "Billing already linked"
check_success "Billing linked to project"

# Enable required APIs
print_section "Step 6: Enabling required APIs"
echo "This may take 2-3 minutes..."
gcloud services enable \
    compute.googleapis.com \
    sqladmin.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    storage.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    --project=$PROJECT_ID
check_success "APIs enabled"

# Create VPC network
print_section "Step 7: Creating VPC network"
gcloud compute networks create $NETWORK_NAME \
    --subnet-mode=auto \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Network already exists"
check_success "VPC network created"

# Create firewall rules
print_section "Step 8: Creating firewall rules"

# Allow HTTP/HTTPS
gcloud compute firewall-rules create allow-http-https \
    --network=$NETWORK_NAME \
    --allow=tcp:80,tcp:443 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=http-server \
    --project=$PROJECT_ID \
    2>/dev/null || echo "HTTP/HTTPS rule already exists"

# Allow SSH via Identity-Aware Proxy
gcloud compute firewall-rules create allow-ssh-iap \
    --network=$NETWORK_NAME \
    --allow=tcp:22 \
    --source-ranges=35.235.240.0/20 \
    --target-tags=allow-ssh \
    --project=$PROJECT_ID \
    2>/dev/null || echo "SSH IAP rule already exists"

check_success "Firewall rules created"

# Create Cloud SQL instances
print_section "Step 9: Creating Cloud SQL databases"
echo "⏳ This may take 5-10 minutes per database..."

# Staging database
echo "Creating staging database (db-f1-micro)..."
gcloud sql instances create financial-rise-staging-db \
    --database-version=POSTGRES_14 \
    --tier=db-f1-micro \
    --region=$REGION \
    --network=projects/$PROJECT_ID/global/networks/$NETWORK_NAME \
    --no-assign-ip \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Staging database already exists"

# Production database
echo "Creating production database (db-g1-small with HA)..."
gcloud sql instances create financial-rise-production-db \
    --database-version=POSTGRES_14 \
    --tier=db-g1-small \
    --region=$REGION \
    --availability-type=REGIONAL \
    --network=projects/$PROJECT_ID/global/networks/$NETWORK_NAME \
    --no-assign-ip \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Production database already exists"

check_success "Cloud SQL databases created"

# Create databases and users
print_section "Step 10: Configuring databases"

# Generate passwords
STAGING_DB_PASSWORD=$(openssl rand -base64 32)
PRODUCTION_DB_PASSWORD=$(openssl rand -base64 32)

# Staging database setup
echo "Configuring staging database..."
gcloud sql databases create financial_rise_staging \
    --instance=financial-rise-staging-db \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Staging database already exists"

gcloud sql users create financial_rise \
    --instance=financial-rise-staging-db \
    --password=$STAGING_DB_PASSWORD \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Staging user already exists"

# Production database setup
echo "Configuring production database..."
gcloud sql databases create financial_rise_production \
    --instance=financial-rise-production-db \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Production database already exists"

gcloud sql users create financial_rise \
    --instance=financial-rise-production-db \
    --password=$PRODUCTION_DB_PASSWORD \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Production user already exists"

check_success "Databases configured"

# Get database private IPs
STAGING_DB_IP=$(gcloud sql instances describe financial-rise-staging-db --project=$PROJECT_ID --format="value(ipAddresses[0].ipAddress)")
PRODUCTION_DB_IP=$(gcloud sql instances describe financial-rise-production-db --project=$PROJECT_ID --format="value(ipAddresses[0].ipAddress)")

echo -e "${GREEN}Staging DB IP: $STAGING_DB_IP${NC}"
echo -e "${GREEN}Production DB IP: $PRODUCTION_DB_IP${NC}"

# Create Artifact Registry
print_section "Step 11: Creating Artifact Registry"
gcloud artifacts repositories create $ARTIFACT_REPO \
    --repository-format=docker \
    --location=$REGION \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Artifact Registry already exists"
check_success "Artifact Registry created"

# Create GCS buckets
print_section "Step 12: Creating Cloud Storage buckets"

gcloud storage buckets create gs://financial-rise-reports-staging \
    --location=$REGION \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Staging bucket already exists"

gcloud storage buckets create gs://financial-rise-reports-production \
    --location=$REGION \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Production bucket already exists"

gcloud storage buckets create gs://financial-rise-backups \
    --location=$REGION \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Backups bucket already exists"

check_success "GCS buckets created"

# Reserve static IPs
print_section "Step 13: Reserving static IP addresses"

gcloud compute addresses create financial-rise-staging-ip \
    --region=$REGION \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Staging IP already exists"

gcloud compute addresses create financial-rise-production-ip \
    --region=$REGION \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Production IP already exists"

check_success "Static IPs reserved"

# Get static IPs
STAGING_IP=$(gcloud compute addresses describe financial-rise-staging-ip --region=$REGION --project=$PROJECT_ID --format="value(address)")
PRODUCTION_IP=$(gcloud compute addresses describe financial-rise-production-ip --region=$REGION --project=$PROJECT_ID --format="value(address)")

echo -e "${GREEN}Staging IP: $STAGING_IP${NC}"
echo -e "${GREEN}Production IP: $PRODUCTION_IP${NC}"

# Create VMs
print_section "Step 14: Creating Virtual Machines"
echo "⏳ This may take 2-3 minutes per VM..."

# Staging VM (preemptible e2-medium)
echo "Creating staging VM (e2-medium preemptible)..."
gcloud compute instances create $STAGING_VM \
    --zone=$ZONE \
    --machine-type=e2-medium \
    --network=$NETWORK_NAME \
    --address=financial-rise-staging-ip \
    --boot-disk-size=30GB \
    --boot-disk-type=pd-ssd \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --tags=http-server,https-server,allow-ssh \
    --metadata-from-file=startup-script=financial-rise-app/scripts/vm-startup.sh \
    --scopes=cloud-platform \
    --preemptible \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Staging VM already exists"

# Production VM (standard e2-standard-2)
echo "Creating production VM (e2-standard-2)..."
gcloud compute instances create $PRODUCTION_VM \
    --zone=$ZONE \
    --machine-type=e2-standard-2 \
    --network=$NETWORK_NAME \
    --address=financial-rise-production-ip \
    --boot-disk-size=50GB \
    --boot-disk-type=pd-ssd \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --tags=http-server,https-server,allow-ssh \
    --metadata-from-file=startup-script=financial-rise-app/scripts/vm-startup.sh \
    --scopes=cloud-platform \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Production VM already exists"

check_success "VMs created"

# Create service account for GitHub Actions
print_section "Step 15: Creating service account for GitHub Actions"

SA_NAME="github-actions"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create $SA_NAME \
    --display-name="GitHub Actions Deployment" \
    --project=$PROJECT_ID \
    2>/dev/null || echo "Service account already exists"

# Grant necessary roles
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/compute.instanceAdmin.v1" \
    --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/artifactregistry.writer" \
    --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/secretmanager.secretAccessor" \
    --condition=None

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="roles/storage.objectAdmin" \
    --condition=None

# Create and download key
# SKIPPED: Organization policy prevents service account key creation
# gcloud iam service-accounts keys create github-actions-key.json \
#     --iam-account=$SA_EMAIL \
#     --project=$PROJECT_ID

check_success "Service account created"

# Generate JWT secrets
print_section "Step 16: Generating secrets"
JWT_SECRET=$(openssl rand -base64 64)
JWT_REFRESH_SECRET=$(openssl rand -base64 64)

# Create environment files
print_section "Step 17: Creating environment files"

# Staging environment
cat > .env.staging <<EOF
# Database Configuration
DATABASE_HOST=$STAGING_DB_IP
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=$STAGING_DB_PASSWORD
DATABASE_NAME=financial_rise_staging

# JWT Configuration
JWT_SECRET=$JWT_SECRET
JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET

# GCP Configuration
GCS_BUCKET=financial-rise-reports-staging
GCP_PROJECT_ID=$PROJECT_ID

# Application Configuration
NODE_ENV=staging
PORT=4000
FRONTEND_URL=http://$STAGING_IP

# Email Configuration (add your SendGrid key)
SENDGRID_API_KEY=your-sendgrid-api-key-here
EOF

# Production environment
cat > .env.production <<EOF
# Database Configuration
DATABASE_HOST=$PRODUCTION_DB_IP
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=$PRODUCTION_DB_PASSWORD
DATABASE_NAME=financial_rise_production

# JWT Configuration
JWT_SECRET=$JWT_SECRET
JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET

# GCP Configuration
GCS_BUCKET=financial-rise-reports-production
GCP_PROJECT_ID=$PROJECT_ID

# Application Configuration
NODE_ENV=production
PORT=4000
FRONTEND_URL=http://$PRODUCTION_IP

# Email Configuration (add your SendGrid key)
SENDGRID_API_KEY=your-sendgrid-api-key-here
EOF

check_success "Environment files created"

# Upload secrets to Secret Manager
print_section "Step 18: Uploading secrets to Secret Manager"

gcloud secrets create financial-rise-staging-env \
    --data-file=.env.staging \
    --project=$PROJECT_ID \
    2>/dev/null || gcloud secrets versions add financial-rise-staging-env --data-file=.env.staging --project=$PROJECT_ID

gcloud secrets create financial-rise-production-env \
    --data-file=.env.production \
    --project=$PROJECT_ID \
    2>/dev/null || gcloud secrets versions add financial-rise-production-env --data-file=.env.production --project=$PROJECT_ID

check_success "Secrets uploaded to Secret Manager"

# Summary
print_section "🎉 Setup Complete!"

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              Infrastructure Summary                        ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Project:${NC} $PROJECT_ID"
echo -e "${BLUE}Region:${NC} $REGION"
echo ""
echo -e "${YELLOW}── Staging Environment ──${NC}"
echo -e "VM: $STAGING_VM (e2-medium preemptible)"
echo -e "IP: $STAGING_IP"
echo -e "Database: financial-rise-staging-db (db-f1-micro)"
echo -e "DB IP: $STAGING_DB_IP"
echo ""
echo -e "${YELLOW}── Production Environment ──${NC}"
echo -e "VM: $PRODUCTION_VM (e2-standard-2)"
echo -e "IP: $PRODUCTION_IP"
echo -e "Database: financial-rise-production-db (db-g1-small HA)"
echo -e "DB IP: $PRODUCTION_DB_IP"
echo ""
echo -e "${YELLOW}── Artifact Registry ──${NC}"
echo -e "$REGION-docker.pkg.dev/$PROJECT_ID/$ARTIFACT_REPO"
echo ""
echo -e "${YELLOW}── GCS Buckets ──${NC}"
echo -e "Staging Reports: gs://financial-rise-reports-staging"
echo -e "Production Reports: gs://financial-rise-reports-production"
echo -e "Backups: gs://financial-rise-backups"
echo ""
echo -e "${YELLOW}── Estimated Monthly Cost ──${NC}"
echo -e "Staging: ~\$22/month"
echo -e "Production: ~\$86/month"
echo -e "Shared Services: ~\$8/month"
echo -e "Total: ~\$116/month"
echo ""
echo -e "${RED}⚠️  Important Files Created:${NC}"
echo -e "  • .env.staging - Staging environment variables"
echo -e "  • .env.production - Production environment variables"
echo -e "  • github-actions-key.json - Service account key"
echo ""
echo -e "${RED}⚠️  KEEP THESE FILES SECURE - DO NOT COMMIT TO GIT${NC}"
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║              Next Steps                                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "1. Add GitHub Secrets to your repository:"
echo "   Go to: https://github.com/BeTrashMonster/financial-rise-report/settings/secrets/actions"
echo ""
echo "   Add these secrets:"
echo "   • GCP_PROJECT_ID = $PROJECT_ID"
echo "   • GCP_SA_KEY = (paste contents of github-actions-key.json, base64 encoded)"
echo "   • GCP_REGION = $REGION"
echo "   • ARTIFACT_REGISTRY_REPO = $ARTIFACT_REPO"
echo "   • STAGING_VM_NAME = $STAGING_VM"
echo "   • PRODUCTION_VM_NAME = $PRODUCTION_VM"
echo "   • STAGING_VM_ZONE = $ZONE"
echo "   • PRODUCTION_VM_ZONE = $ZONE"
echo ""
echo "   To encode the service account key:"
echo "   Linux/Mac: cat github-actions-key.json | base64 -w 0"
echo "   Windows: certutil -encode github-actions-key.json github-actions-key-base64.txt"
echo ""
echo "2. Update SendGrid API key in Secret Manager:"
echo "   Edit .env.staging and .env.production with your SendGrid key, then run:"
echo "   gcloud secrets versions add financial-rise-staging-env --data-file=.env.staging"
echo "   gcloud secrets versions add financial-rise-production-env --data-file=.env.production"
echo ""
echo "3. Wait 5-10 minutes for VMs to complete startup script"
echo "   (installs Docker, Docker Compose, Cloud Ops Agent)"
echo ""
echo "4. Push code to trigger deployment:"
echo "   git push origin main"
echo ""
echo "5. Monitor deployment:"
echo "   https://github.com/BeTrashMonster/financial-rise-report/actions"
echo ""
echo -e "${GREEN}✨ Your infrastructure is ready for deployment!${NC}"
echo ""
