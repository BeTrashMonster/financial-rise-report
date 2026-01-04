#!/bin/bash
# Properly fix production secrets - manual approach

set -e

echo "Fixing production secrets properly..."

# Get current secret
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod > /tmp/secret-current.env

echo "Current secret retrieved. Creating properly formatted version..."

# Manually create properly formatted .env
# Only quote values, skip comment lines, handle base64 properly
cat > /tmp/secret-fixed.env << 'EOF'
# Database Configuration
DATABASE_HOST="34.134.76.171"
DATABASE_PORT="5432"
DATABASE_USER="financial_rise"
DATABASE_PASSWORD="ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE="
DATABASE_NAME="financial_rise_production"

# JWT Configuration
JWT_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
JWT_REFRESH_SECRET="nKqbXDP7aWiWRMKjHFIqijE/ZCEH1rPhRGf3BJExRbpgGyvHwm+H3p0F988oY3bzNRpc8sfc1zWS2lJCbyq+kA=="

# Backwards compatibility
TOKEN_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
REFRESH_TOKEN_SECRET="nKqbXDP7aWiWRMKjHFIqijE/ZCEH1rPhRGf3BJExRbpgGyvHwm+H3p0F988oY3bzNRpc8sfc1zWS2lJCbyq+kA=="

# GCP Configuration
GCS_BUCKET="financial-rise-reports-production"
GCP_PROJECT_ID="financial-rise-prod"

# Application Configuration
NODE_ENV="production"
PORT="4000"
FRONTEND_URL="https://getoffthemoneyshametrain.com"

# Email Configuration
SENDGRID_API_KEY="SG.your-key-here"

# Database Encryption Key
DB_ENCRYPTION_KEY="e0940e7c8aacdf19a470d085472fc75bcfe006c438ab1f0300f812365d19e5af"

# Redis Configuration
REDIS_PASSWORD="your-redis-password"
REDIS_HOST="redis"
REDIS_PORT="6379"
EOF

echo "✅ Properly formatted secret created"
echo ""
echo "Showing formatted secret (first 15 lines):"
head -15 /tmp/secret-fixed.env
echo ""

# Update Secret Manager
echo "Updating Secret Manager with version 3..."
gcloud secrets versions add financial-rise-production-env \
  --data-file=/tmp/secret-fixed.env \
  --project=financial-rise-prod

echo "✅ Secret Manager updated to version 3"
echo ""
echo "Cleanup..."
rm -f /tmp/secret-current.env /tmp/secret-fixed.env

echo "=========================================
"
echo "READY TO DEPLOY"
echo "========================================="
echo ""
echo "Next: Trigger deployment"
echo "  git commit --allow-empty -m 'Deploy with properly formatted secrets (v3)'"
echo "  git push origin main"
