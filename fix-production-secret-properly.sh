#!/bin/bash
# Fix production Secret Manager properly - rebuild from scratch

set -e

echo "========================================="
echo "FIXING PRODUCTION SECRET MANAGER"
echo "========================================="
echo ""

# Create a clean secret file from scratch
cat > /tmp/production-secret-clean.env << 'EOF'
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

echo "Created clean secret file"
echo ""
echo "Preview (first 10 lines):"
head -10 /tmp/production-secret-clean.env
echo ""

# Verify no escaped quotes
if grep -q '\\"' /tmp/production-secret-clean.env; then
  echo "❌ ERROR: File contains escaped quotes!"
  exit 1
fi

echo "✅ Verified: No escaped quotes"
echo ""

# Update Secret Manager
echo "Updating Secret Manager..."
gcloud secrets versions add financial-rise-production-env \
  --data-file=/tmp/production-secret-clean.env \
  --project=financial-rise-prod

echo ""
echo "✅ Secret Manager updated!"
echo ""

# Verify the update
echo "Verifying new secret version..."
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod > /tmp/verify-secret.env

echo ""
echo "New secret (first 10 lines):"
head -10 /tmp/verify-secret.env
echo ""

# Check for issues
if grep -q '\\"' /tmp/verify-secret.env; then
  echo "⚠️  WARNING: Secret Manager still contains escaped quotes!"
  echo "This may be a Secret Manager encoding issue."
else
  echo "✅ Secret verification passed - no escaped quotes"
fi

# Cleanup
rm -f /tmp/production-secret-clean.env /tmp/verify-secret.env

echo ""
echo "========================================="
echo "SECRET MANAGER FIXED ✅"
echo "========================================="
echo ""
echo "Next: Trigger deployment"
echo "  cd /mnt/c/Users/Admin/src"
echo "  git commit --allow-empty -m 'Deploy with fixed Secret Manager'"
echo "  git push origin main"
