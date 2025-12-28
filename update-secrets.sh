#!/bin/bash
#
# Update Secret Manager with latest environment variables
# Run this after modifying .env.staging or .env.production
#

set -e

PROJECT_ID="financial-rise-prod"

echo "================================"
echo "Updating Secret Manager Secrets"
echo "================================"
echo ""

# Check if environment files exist
if [ ! -f ".env.staging" ]; then
    echo "❌ Error: .env.staging not found"
    exit 1
fi

if [ ! -f ".env.production" ]; then
    echo "❌ Error: .env.production not found"
    exit 1
fi

# Update staging secret
echo "📤 Updating staging environment secret..."
gcloud secrets versions add financial-rise-staging-env \
    --data-file=.env.staging \
    --project=$PROJECT_ID

if [ $? -eq 0 ]; then
    echo "✅ Staging secret updated successfully"
else
    echo "❌ Failed to update staging secret"
    exit 1
fi

# Update production secret
echo ""
echo "📤 Updating production environment secret..."
gcloud secrets versions add financial-rise-production-env \
    --data-file=.env.production \
    --project=$PROJECT_ID

if [ $? -eq 0 ]; then
    echo "✅ Production secret updated successfully"
else
    echo "❌ Failed to update production secret"
    exit 1
fi

echo ""
echo "================================"
echo "✅ All secrets updated!"
echo "================================"
echo ""
echo "Next steps:"
echo "1. Deploy to staging: git push origin main"
echo "2. Or manually pull secrets on VMs:"
echo "   gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --command='cd /opt/financial-rise && gcloud secrets versions access latest --secret=financial-rise-staging-env > .env'"
echo ""
