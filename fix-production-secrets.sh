#!/bin/bash
# Fix Production Secrets - Add quotes around values
# Run this in WSL where you ran the production setup

set -e

echo "Fixing production secrets in Secret Manager..."
echo ""

# Get current secret
echo "Step 1: Retrieving current secret..."
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod > /tmp/prod-secret-current.env

echo "✅ Retrieved current secret"
echo ""

# Fix: Add quotes around ALL values (handles +, /, = characters in base64)
echo "Step 2: Adding quotes around all values..."
awk -F= '{print $1"=\""$2"\""}' /tmp/prod-secret-current.env > /tmp/prod-secret-fixed.env

echo "✅ Fixed secret format"
echo ""

# Show diff
echo "Step 3: Showing changes (first 10 lines)..."
echo "BEFORE:"
head -10 /tmp/prod-secret-current.env
echo ""
echo "AFTER:"
head -10 /tmp/prod-secret-fixed.env
echo ""

# Update Secret Manager
echo "Step 4: Updating Secret Manager with fixed version..."
gcloud secrets versions add financial-rise-production-env \
  --data-file=/tmp/prod-secret-fixed.env \
  --project=financial-rise-prod

echo "✅ Secret Manager updated with properly quoted values"
echo ""

# Cleanup
rm -f /tmp/prod-secret-current.env /tmp/prod-secret-fixed.env

echo "========================================="
echo "SECRET FIX COMPLETE ✅"
echo "========================================="
echo ""
echo "Next: Trigger a new deployment"
echo "  git commit --allow-empty -m 'Trigger deployment with fixed secrets'"
echo "  git push origin main"
echo ""
