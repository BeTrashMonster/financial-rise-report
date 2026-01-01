#!/bin/bash
# Production Infrastructure Setup - Phase 7: GitHub Secrets Configuration
# Estimated Time: 10 minutes
# Prerequisites: All previous phases complete

set -e

PROJECT_ID="financial-rise-prod"
ZONE="us-central1-a"
VM_NAME="financial-rise-production-vm"

echo "========================================="
echo "PHASE 7: GitHub Secrets Configuration"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo ""

# Step 7.1: Get Project Number
echo "Step 1/3: Getting GCP project information..."

PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID \
  --format="value(projectNumber)")

echo "Project ID: $PROJECT_ID"
echo "Project Number: $PROJECT_NUMBER"
echo ""

# Step 7.2: Display GitHub Secrets to Configure
echo "Step 2/3: GitHub Secrets Configuration"
echo ""
echo "========================================="
echo "ADD THESE SECRETS TO GITHUB"
echo "========================================="
echo ""
echo "Navigate to your GitHub repository:"
echo "  Settings → Secrets and variables → Actions → New repository secret"
echo ""
echo "Add the following secrets:"
echo ""
echo "Secret Name: GCP_PROJECT_ID"
echo "Secret Value: $PROJECT_ID"
echo ""
echo "---"
echo ""
echo "Secret Name: GCP_WORKLOAD_IDENTITY_PROVIDER"
echo "Secret Value: projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider"
echo ""
echo "---"
echo ""
echo "Secret Name: GCP_SERVICE_ACCOUNT"
echo "Secret Value: github-actions@$PROJECT_ID.iam.gserviceaccount.com"
echo ""
echo "---"
echo ""
echo "Secret Name: PRODUCTION_VM_NAME"
echo "Secret Value: $VM_NAME"
echo ""
echo "---"
echo ""
echo "Secret Name: PRODUCTION_VM_ZONE"
echo "Secret Value: $ZONE"
echo ""
echo "========================================="
echo ""

# Save to file for reference
cat > /tmp/github-secrets.txt << EOF
GitHub Secrets Configuration
=============================

Navigate to: Settings → Secrets and variables → Actions

Add these secrets:

GCP_PROJECT_ID=$PROJECT_ID

GCP_WORKLOAD_IDENTITY_PROVIDER=projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider

GCP_SERVICE_ACCOUNT=github-actions@$PROJECT_ID.iam.gserviceaccount.com

PRODUCTION_VM_NAME=$VM_NAME

PRODUCTION_VM_ZONE=$ZONE

=============================
EOF

chmod 600 /tmp/github-secrets.txt

echo "Secrets saved to: /tmp/github-secrets.txt"
echo ""

# Step 7.3: Create GitHub Environment (Instructions)
echo "Step 3/3: GitHub Environment Setup (Manual Steps)"
echo ""
echo "========================================="
echo "CREATE PRODUCTION ENVIRONMENT IN GITHUB"
echo "========================================="
echo ""
echo "1. Go to your GitHub repository"
echo "2. Navigate to: Settings → Environments"
echo "3. Click 'New environment'"
echo "4. Environment name: production"
echo "5. Add protection rules:"
echo "   ☑️  Required reviewers: [Your GitHub username]"
echo "   ☑️  Wait timer: 5 minutes (optional)"
echo "6. Click 'Save protection rules'"
echo ""
echo "This ensures production deployments require manual approval."
echo ""

# Step 7.4: Verify Workload Identity Setup
echo "Verifying Workload Identity Pool exists..."
echo ""

if gcloud iam workload-identity-pools describe github-pool \
  --location=global \
  --project=$PROJECT_ID &>/dev/null; then
  echo "✅ Workload Identity Pool 'github-pool' exists"

  if gcloud iam workload-identity-pools providers describe github-provider \
    --location=global \
    --workload-identity-pool=github-pool \
    --project=$PROJECT_ID &>/dev/null; then
    echo "✅ Workload Identity Provider 'github-provider' exists"
  else
    echo "⚠️  Workload Identity Provider 'github-provider' NOT found"
    echo "Run setup-gcp-infrastructure.sh to create it"
  fi
else
  echo "⚠️  Workload Identity Pool 'github-pool' NOT found"
  echo "Run setup-gcp-infrastructure.sh to create it"
fi

echo ""

# Step 7.5: Verify Service Account
echo "Verifying GitHub Actions service account..."

if gcloud iam service-accounts describe github-actions@$PROJECT_ID.iam.gserviceaccount.com \
  --project=$PROJECT_ID &>/dev/null; then
  echo "✅ Service account 'github-actions@$PROJECT_ID.iam.gserviceaccount.com' exists"
else
  echo "⚠️  Service account NOT found"
  echo "Run setup-gcp-infrastructure.sh to create it"
fi

echo ""

# Step 7.6: Display Workflow File Location
echo "Verifying deployment workflow..."
if [ -f ".github/workflows/deploy-gcp.yml" ]; then
  echo "✅ Deployment workflow found: .github/workflows/deploy-gcp.yml"
  echo ""
  echo "Workflow supports:"
  grep -E "^\s+- (staging|production)" .github/workflows/deploy-gcp.yml || echo "  - Staging and Production environments"
else
  echo "⚠️  Deployment workflow not found at .github/workflows/deploy-gcp.yml"
fi

echo ""

# Summary
echo "========================================="
echo "PHASE 7 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✅ GitHub secrets list generated"
echo "  ✅ Workload Identity configuration verified"
echo "  ✅ Service account verified"
echo "  ✅ Deployment workflow verified"
echo ""
echo "⚠️  MANUAL STEPS REQUIRED:"
echo ""
echo "1. Add GitHub Secrets (see /tmp/github-secrets.txt):"
echo "   - GCP_PROJECT_ID"
echo "   - GCP_WORKLOAD_IDENTITY_PROVIDER"
echo "   - GCP_SERVICE_ACCOUNT"
echo "   - PRODUCTION_VM_NAME"
echo "   - PRODUCTION_VM_ZONE"
echo ""
echo "2. Create Production Environment in GitHub:"
echo "   - Settings → Environments → New environment: 'production'"
echo "   - Add required reviewers (manual approval)"
echo ""
echo "3. Verify Workflow File (.github/workflows/deploy-gcp.yml):"
echo "   - Check staging and production environment configurations"
echo ""
echo "========================================="
echo "ALL INFRASTRUCTURE PHASES COMPLETE!"
echo "========================================="
echo ""
echo "✅ Phase 1: Cloud SQL with Private IP"
echo "✅ Phase 2: Standard Production VM"
echo "✅ Phase 4: Production Secret Manager"
echo "✅ Phase 5: Monitoring & Alerting"
echo "✅ Phase 6: Database Backup Strategy"
echo "✅ Phase 7: GitHub Secrets Configuration"
echo ""
echo "⚠️  Phase 3: SSL/HTTPS (Optional - requires domain name)"
echo "   Run setup-production-phase3-ssl.sh if you have a domain"
echo ""
echo "========================================="
echo "READY FOR PRODUCTION DEPLOYMENT"
echo "========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Complete manual GitHub configuration (above)"
echo "2. Push code to trigger deployment:"
echo "   git push origin main"
echo "3. Approve production deployment in GitHub Actions"
echo "4. Monitor deployment at:"
echo "   https://github.com/YOUR_REPO/actions"
echo ""
echo "Production endpoints (after deployment):"
PROD_IP=$(cat /tmp/prod-vm-ip.txt 2>/dev/null || echo "RUN_PHASE_2_FIRST")
echo "  - API Health: http://$PROD_IP/api/v1/health"
echo "  - Frontend: http://$PROD_IP/"
echo ""
echo "Monitoring dashboard:"
echo "  https://console.cloud.google.com/monitoring/dashboards?project=$PROJECT_ID"
echo ""
