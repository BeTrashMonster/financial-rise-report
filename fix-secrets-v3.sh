#!/bin/bash
# Fix production secrets - Version 3 (proper formatting)

set -e

echo "========================================="
echo "PRODUCTION SECRET FIX - VERSION 3"
echo "========================================="
echo ""

# Get current secret
echo "Step 1: Retrieving current secret from Secret Manager..."
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod > /tmp/secret-raw.env

echo "✅ Retrieved"
echo ""

# Clean up: remove malformed quotes and re-add them properly
echo "Step 2: Cleaning and reformatting..."

# Strip all existing quotes (both " and \"), then add clean quotes
sed 's/^[[:space:]]*#.*$//; /^$/d' /tmp/secret-raw.env | \  # Remove comments and blank lines
  sed 's/["\]//g' | \  # Remove all quotes
  sed 's/^\([^=]*\)=\(.*\)$/\1="\2"/' > /tmp/secret-clean.env

# Add comments back manually for readability
cat > /tmp/secret-final.env << 'HEADER'
# Database Configuration (Private IP)
HEADER

grep "^DATABASE" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION1'

# JWT Configuration
SECTION1

grep "^JWT" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION2'

# Backwards compatibility
SECTION2

grep "^TOKEN_SECRET\|^REFRESH_TOKEN_SECRET" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION3'

# GCP Configuration
SECTION3

grep "^GCS_BUCKET\|^GCP_PROJECT" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION4'

# Application Configuration
SECTION4

grep "^NODE_ENV\|^PORT\|^FRONTEND_URL" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION5'

# Email Configuration
SECTION5

grep "^SENDGRID" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION6'

# Database Encryption Key
SECTION6

grep "^DB_ENCRYPTION_KEY" /tmp/secret-clean.env >> /tmp/secret-final.env

cat >> /tmp/secret-final.env << 'SECTION7'

# Redis Configuration
SECTION7

grep "^REDIS" /tmp/secret-clean.env >> /tmp/secret-final.env

echo "✅ Reformatted with proper quotes"
echo ""

# Show result
echo "Step 3: Preview (first 20 lines)..."
head -20 /tmp/secret-final.env
echo ""

# Update Secret Manager
echo "Step 4: Updating Secret Manager to version 3..."
gcloud secrets versions add financial-rise-production-env \
  --data-file=/tmp/secret-final.env \
  --project=financial-rise-prod

echo "✅ Secret Manager updated to version 3"
echo ""

# Cleanup
rm -f /tmp/secret-raw.env /tmp/secret-clean.env /tmp/secret-final.env

echo "========================================="
echo "SECRET FIX COMPLETE ✅"
echo "========================================="
echo ""
echo "Next: Deploy to production"
echo "  git commit --allow-empty -m 'Deploy with fixed secrets v3'"
echo "  git push origin main"
echo ""
