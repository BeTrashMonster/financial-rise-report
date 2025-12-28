#!/bin/bash
#
# Set up Workload Identity Federation for GitHub Actions
# This allows GitHub Actions to authenticate to GCP without service account keys
#

set -e

PROJECT_ID="financial-rise-prod"
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
POOL_NAME="github-actions-pool"
PROVIDER_NAME="github-provider"
SERVICE_ACCOUNT="github-actions@${PROJECT_ID}.iam.gserviceaccount.com"
REPO="BeTrashMonster/financial-rise-report"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Workload Identity Federation Setup                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Project: $PROJECT_ID"
echo "Project Number: $PROJECT_NUMBER"
echo "Repository: $REPO"
echo ""

# Enable required API
echo "▶ Enabling IAM Credentials API..."
gcloud services enable iamcredentials.googleapis.com --project=$PROJECT_ID
echo "✅ API enabled"
echo ""

# Create Workload Identity Pool
echo "▶ Creating Workload Identity Pool..."
gcloud iam workload-identity-pools create $POOL_NAME \
    --project=$PROJECT_ID \
    --location="global" \
    --display-name="GitHub Actions Pool" \
    2>/dev/null || echo "Pool already exists"
echo "✅ Pool created"
echo ""

# Create Workload Identity Provider
echo "▶ Creating GitHub OIDC Provider..."
gcloud iam workload-identity-pools providers create-oidc $PROVIDER_NAME \
    --project=$PROJECT_ID \
    --location="global" \
    --workload-identity-pool=$POOL_NAME \
    --display-name="GitHub Provider" \
    --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    2>/dev/null || echo "Provider already exists"
echo "✅ Provider created"
echo ""

# Allow GitHub Actions from your repo to impersonate the service account
echo "▶ Granting workload identity binding..."
gcloud iam service-accounts add-iam-policy-binding $SERVICE_ACCOUNT \
    --project=$PROJECT_ID \
    --role="roles/iam.workloadIdentityUser" \
    --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_NAME/attribute.repository/$REPO"
echo "✅ Binding granted"
echo ""

# Get the Workload Identity Provider resource name
WIP_RESOURCE="projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_NAME/providers/$PROVIDER_NAME"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║   Setup Complete!                                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Add these secrets to GitHub:"
echo "https://github.com/$REPO/settings/secrets/actions"
echo ""
echo "GCP_PROJECT_ID:"
echo "$PROJECT_ID"
echo ""
echo "GCP_PROJECT_NUMBER:"
echo "$PROJECT_NUMBER"
echo ""
echo "GCP_WORKLOAD_IDENTITY_PROVIDER:"
echo "$WIP_RESOURCE"
echo ""
echo "GCP_SERVICE_ACCOUNT:"
echo "$SERVICE_ACCOUNT"
echo ""
echo "GCP_REGION:"
echo "us-central1"
echo ""
echo "ARTIFACT_REGISTRY_REPO:"
echo "financial-rise-docker"
echo ""
echo "STAGING_VM_NAME:"
echo "financial-rise-staging-vm"
echo ""
echo "PRODUCTION_VM_NAME:"
echo "financial-rise-production-vm"
echo ""
echo "STAGING_VM_ZONE:"
echo "us-central1-a"
echo ""
echo "PRODUCTION_VM_ZONE:"
echo "us-central1-a"
echo ""
echo "══════════════════════════════════════════════════════════════"
echo ""

# Save to file for easy reference
cat > github-secrets.txt <<EOF
Add these secrets to GitHub:
https://github.com/$REPO/settings/secrets/actions

GCP_PROJECT_ID = $PROJECT_ID
GCP_PROJECT_NUMBER = $PROJECT_NUMBER
GCP_WORKLOAD_IDENTITY_PROVIDER = $WIP_RESOURCE
GCP_SERVICE_ACCOUNT = $SERVICE_ACCOUNT
GCP_REGION = us-central1
ARTIFACT_REGISTRY_REPO = financial-rise-docker
STAGING_VM_NAME = financial-rise-staging-vm
PRODUCTION_VM_NAME = financial-rise-production-vm
STAGING_VM_ZONE = us-central1-a
PRODUCTION_VM_ZONE = us-central1-a
EOF

echo "✅ Secret values saved to: github-secrets.txt"
echo ""
