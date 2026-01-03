#!/bin/bash
# Verify Secret Manager and fix the .env parsing issue

set -e

echo "========================================="
echo "SECRET MANAGER VERIFICATION & FIX"
echo "========================================="
echo ""

# Check if version 3 exists
echo "Step 1: Listing all secret versions..."
gcloud secrets versions list financial-rise-production-env --project=financial-rise-prod
echo ""

# Check version 3 contents
echo "Step 2: Checking VERSION 3 contents..."
echo "----------------------------------------"
gcloud secrets versions access 3 --secret=financial-rise-production-env --project=financial-rise-prod | head -15
echo ""

# Check latest version contents
echo "Step 3: Checking LATEST version contents..."
echo "----------------------------------------"
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | head -15
echo ""

# Check JWT_REFRESH_SECRET specifically
echo "Step 4: Checking JWT_REFRESH_SECRET line..."
echo "----------------------------------------"
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | grep "JWT_REFRESH_SECRET"
echo ""

# Start staging VM
echo "Step 5: Starting staging VM..."
echo "----------------------------------------"
gcloud compute instances start financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod || echo "VM may already be running"
echo ""

# Wait for VM
sleep 5

# Check VM status
echo "Step 6: Checking VM status..."
gcloud compute instances describe financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --format="get(status)"
echo ""

echo "========================================="
echo "VERIFICATION COMPLETE"
echo "========================================="
echo ""

# Now check if the secret has the malformed quotes issue
echo "Analyzing secret format..."
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod > /tmp/current-secret.env

if grep -q '=\\"' /tmp/current-secret.env; then
  echo "⚠️  FOUND ESCAPED QUOTES in secret!"
  echo "The secret contains =\"...\" which causes the Docker Compose error."
  echo ""
  echo "Creating properly formatted version 4..."

  # Remove all quotes and re-add them cleanly
  sed 's/[\"\\]//g' /tmp/current-secret.env | sed 's/^\([^=]*\)=\(.*\)$/\1="\2"/' | grep -v '^$' > /tmp/secret-v4.env

  echo "Preview of fixed secret (first 15 lines):"
  head -15 /tmp/secret-v4.env
  echo ""

  echo "Updating Secret Manager to version 4..."
  gcloud secrets versions add financial-rise-production-env \
    --data-file=/tmp/secret-v4.env \
    --project=financial-rise-prod

  echo "✅ Secret Manager updated to version 4"
  rm -f /tmp/current-secret.env /tmp/secret-v4.env

elif grep -q '="' /tmp/current-secret.env; then
  echo "✅ Secret format looks correct (uses clean quotes)"
  echo ""
  echo "Sample lines:"
  head -5 /tmp/current-secret.env
  echo ""
  echo "The secret format is correct. The issue may be elsewhere."
  rm -f /tmp/current-secret.env
else
  echo "⚠️  Secret has NO QUOTES - this will also cause issues!"
  echo ""
  echo "Creating properly formatted version 4..."
  sed 's/^\([^=]*\)=\(.*\)$/\1="\2"/' /tmp/current-secret.env | grep -v '^$' > /tmp/secret-v4.env

  echo "Preview:"
  head -15 /tmp/secret-v4.env

  gcloud secrets versions add financial-rise-production-env \
    --data-file=/tmp/secret-v4.env \
    --project=financial-rise-prod

  echo "✅ Updated to version 4"
  rm -f /tmp/current-secret.env /tmp/secret-v4.env
fi

echo ""
echo "========================================="
echo "NEXT STEP: Trigger deployment"
echo "========================================="
echo "git commit --allow-empty -m 'Deploy with verified secrets'"
echo "git push origin main"
