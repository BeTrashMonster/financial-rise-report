#!/bin/bash
# Setup production database and create account

set -e

echo "========================================"
echo "STEP 1: RUN DATABASE MIGRATIONS"
echo "========================================"
echo ""

echo "Connecting to production VM and running migrations..."

gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --tunnel-through-iap \
  --command="cd /opt/financial-rise && docker compose -f docker-compose.prod.yml exec -T backend sh -c 'cd /app && npm run build && npx typeorm migration:run -d dist/config/typeorm.config.js'" \
  2>&1

echo ""
echo "✅ Migrations complete!"
echo ""

sleep 3

echo "========================================"
echo "STEP 2: CREATE YOUR ACCOUNT"
echo "========================================"
echo ""

EMAIL="info@thegracefulpenny.com"
PASSWORD="DemoPass123!"
FIRST_NAME="Audrey"
LAST_NAME="Heesch"

echo "Creating account for:"
echo "  Name: $FIRST_NAME $LAST_NAME"
echo "  Email: $EMAIL"
echo ""

# Register the user
RESPONSE=$(curl -s -X POST "http://34.72.61.170/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$EMAIL\",
    \"password\": \"$PASSWORD\",
    \"first_name\": \"$FIRST_NAME\",
    \"last_name\": \"$LAST_NAME\",
    \"role\": \"consultant\"
  }")

echo "Response:"
echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
echo ""

# Check if registration was successful
if echo "$RESPONSE" | grep -q "access_token"; then
  echo "✅ Account created successfully!"
  echo ""
  echo "========================================"
  echo "YOU'RE ALL SET!"
  echo "========================================"
  echo ""
  echo "1. Open your browser and go to:"
  echo "   http://34.72.61.170/login"
  echo ""
  echo "2. Sign in with:"
  echo "   Email: $EMAIL"
  echo "   Password: $PASSWORD"
  echo ""
  echo "3. You'll be redirected to your dashboard!"
  echo ""
else
  echo "❌ Account creation failed"
  echo ""
  echo "Checking backend logs for errors..."
  gcloud compute ssh financial-rise-production-vm \
    --zone=us-central1-a \
    --project=financial-rise-prod \
    --tunnel-through-iap \
    --command="docker logs financial-rise-backend-prod --tail=30 2>&1" \
    2>&1 | tail -20
fi
