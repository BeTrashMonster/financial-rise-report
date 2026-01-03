#!/bin/bash
# Alternative approach: Fix how workflow handles environment variables
# This modifies the .env file after pulling from Secret Manager to ensure clean formatting

set -e

echo "This script shows the workflow modification needed..."
echo ""
echo "The issue: Docker Compose .env parser fails on escaped quotes"
echo "Current workflow does: gcloud secrets ... > .env"
echo ""
echo "We need to add a cleaning step after pulling the secret:"
echo ""
cat << 'SOLUTION'

# In .github/workflows/deploy-gcp.yml, AFTER line 419:
# --secret=financial-rise-production-env > .env
# ADD these lines:

# Clean up any escaped quotes or formatting issues in .env
sed -i 's/\\"//g' .env  # Remove escaped quotes
sed -i 's/^[[:space:]]*$//' .env  # Remove blank lines
sed -i '/^$/d' .env  # Remove empty lines

# Verify the .env file is readable
if ! grep -q "DATABASE_HOST" .env; then
  echo "ERROR: .env file appears corrupted"
  cat .env
  exit 1
fi

echo ".env file cleaned and verified"
head -5 .env

SOLUTION

echo ""
echo "However, the BETTER solution is to fix the secret in Secret Manager first."
echo "Run: bash diagnose-and-fix-secrets.sh"
echo ""
echo "This will:"
echo "  1. Check current secret for formatting issues"
echo "  2. Create clean version without escaped quotes"
echo "  3. Update Secret Manager"
echo "  4. Start staging VM"
echo "  5. Trigger new deployment"
