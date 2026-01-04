#!/bin/bash
# Comprehensive secret diagnostics and fix
# Run this in WSL where you have gcloud configured

set -e

echo "========================================="
echo "PRODUCTION SECRET DIAGNOSTICS & FIX"
echo "========================================="
echo ""

echo "Step 1: Checking current secret versions..."
echo "-------------------------------------------"
gcloud secrets versions list financial-rise-production-env --project=financial-rise-prod
echo ""

echo "Step 2: Retrieving LATEST secret for analysis..."
echo "-------------------------------------------"
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod > /tmp/current-prod-secret.env

echo "First 15 lines of current secret:"
head -15 /tmp/current-prod-secret.env
echo ""

echo "Step 3: Checking for formatting issues..."
echo "-------------------------------------------"

# Check for escaped quotes
if grep -q '\\"' /tmp/current-prod-secret.env; then
  echo "❌ FOUND ESCAPED QUOTES (\\\")"
  echo "This is the root cause of the Docker Compose error!"
  echo ""
  grep '\\"' /tmp/current-prod-secret.env | head -5
  echo ""
  FIX_NEEDED=true
elif grep -q '=""' /tmp/current-prod-secret.env; then
  echo "❌ FOUND EMPTY QUOTED VALUES"
  FIX_NEEDED=true
elif ! grep -q '="' /tmp/current-prod-secret.env; then
  echo "❌ NO QUOTES FOUND - values must be quoted for special characters"
  FIX_NEEDED=true
else
  echo "✅ Secret format appears correct"
  echo ""
  echo "JWT_REFRESH_SECRET line:"
  grep "JWT_REFRESH_SECRET" /tmp/current-prod-secret.env
  echo ""
  FIX_NEEDED=false
fi

if [ "$FIX_NEEDED" = "true" ]; then
  echo ""
  echo "Step 4: Creating CLEAN secret from scratch..."
  echo "-------------------------------------------"

  # Create completely fresh secret with proper formatting
  cat > /tmp/prod-secret-clean.env << 'EOF'
DATABASE_HOST="34.134.76.171"
DATABASE_PORT="5432"
DATABASE_USER="financial_rise"
DATABASE_PASSWORD="ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE="
DATABASE_NAME="financial_rise_production"
JWT_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
JWT_REFRESH_SECRET="nKqbXDP7aWiWRMKjHFIqijE/ZCEH1rPhRGf3BJExRbpgGyvHwm+H3p0F988oY3bzNRpc8sfc1zWS2lJCbyq+kA=="
TOKEN_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
REFRESH_TOKEN_SECRET="nKqbXDP7aWiWRMKjHFIqijE/ZCEH1rPhRGf3BJExRbpgGyvHwm+H3p0F988oY3bzNRpc8sfc1zWS2lJCbyq+kA=="
GCS_BUCKET="financial-rise-reports-production"
GCP_PROJECT_ID="financial-rise-prod"
NODE_ENV="production"
PORT="4000"
FRONTEND_URL="https://getoffthemoneyshametrain.com"
SENDGRID_API_KEY="SENDGRID_API_KEY_NOT_SET"
DB_ENCRYPTION_KEY="e0940e7c8aacdf19a470d085472fc75bcfe006c438ab1f0300f812365d19e5af"
REDIS_PASSWORD="placeholder-redis-password"
REDIS_HOST="redis"
REDIS_PORT="6379"
EOF

  echo "✅ Created clean secret file"
  echo ""
  echo "Preview (first 15 lines):"
  head -15 /tmp/prod-secret-clean.env
  echo ""

  # Verify no escaped quotes
  if grep -q '\\"' /tmp/prod-secret-clean.env; then
    echo "❌ ERROR: Clean file still has escaped quotes!"
    exit 1
  fi

  echo "✅ Verified: No escaped quotes in new secret"
  echo ""

  echo "Step 5: Updating Secret Manager..."
  echo "-------------------------------------------"
  gcloud secrets versions add financial-rise-production-env \
    --data-file=/tmp/prod-secret-clean.env \
    --project=financial-rise-prod

  echo ""
  echo "✅ Secret Manager updated!"
  echo ""

  # Verify the update
  echo "Step 6: Verifying update..."
  echo "-------------------------------------------"
  gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod > /tmp/verify-secret.env

  if grep -q '\\"' /tmp/verify-secret.env; then
    echo "❌ WARNING: Secret Manager still has escaped quotes!"
    echo "This may be a Secret Manager encoding issue."
    echo ""
    grep '\\"' /tmp/verify-secret.env | head -3
  else
    echo "✅ Secret Manager verification passed!"
    echo ""
    echo "JWT_REFRESH_SECRET line:"
    grep "JWT_REFRESH_SECRET" /tmp/verify-secret.env
  fi

  rm -f /tmp/prod-secret-clean.env /tmp/verify-secret.env
else
  echo ""
  echo "No fix needed - secret format is correct."
fi

echo ""
echo "Step 7: Starting staging VM..."
echo "-------------------------------------------"
gcloud compute instances start financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod 2>&1 | grep -v "already running" || echo "VM started or already running"

echo ""
sleep 3

gcloud compute instances describe financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --format="value(status)"

echo ""
echo "========================================="
echo "DIAGNOSTICS COMPLETE"
echo "========================================="
echo ""

rm -f /tmp/current-prod-secret.env

if [ "$FIX_NEEDED" = "true" ]; then
  echo "✅ Secret fixed and updated"
  echo ""
  echo "Next: Deploy to test the fix"
  echo "  cd /mnt/c/Users/Admin/src"
  echo "  git commit --allow-empty -m 'Deploy with clean secrets (no escaped quotes)'"
  echo "  git push origin main"
else
  echo "⚠️  Secret format looks correct but deployment still failing."
  echo ""
  echo "Possible causes:"
  echo "  1. GitHub Actions may be caching old secrets"
  echo "  2. VM may have cached .env file from previous deployment"
  echo "  3. Issue may be in how docker-compose reads the file"
  echo ""
  echo "Try: SSH to production VM and manually check /opt/financial-rise/.env"
fi
