#!/bin/bash
# Create a demo account for testing Financial RISE application

set -e

PRODUCTION_URL="http://34.72.61.170"

echo "========================================"
echo "CREATE DEMO ACCOUNT"
echo "========================================"
echo ""

# Demo account credentials
EMAIL="${1:-demo@financialrise.com}"
PASSWORD="${2:-DemoPass123!}"
FIRST_NAME="${3:-Demo}"
LAST_NAME="${4:-User}"

echo "Creating account with:"
echo "  Email: $EMAIL"
echo "  Password: $PASSWORD"
echo "  Name: $FIRST_NAME $LAST_NAME"
echo ""

# Register the user
echo "Registering user..."
RESPONSE=$(curl -s -X POST "$PRODUCTION_URL/api/v1/auth/register" \
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
  echo "LOGIN INSTRUCTIONS"
  echo "========================================"
  echo ""
  echo "1. Open your browser and go to:"
  echo "   $PRODUCTION_URL/login"
  echo ""
  echo "2. Enter your credentials:"
  echo "   Email: $EMAIL"
  echo "   Password: $PASSWORD"
  echo ""
  echo "3. Click 'Sign In' to access the dashboard"
  echo ""
else
  echo "❌ Account creation failed"
  echo ""
  if echo "$RESPONSE" | grep -q "already exists"; then
    echo "This email is already registered. Try logging in at:"
    echo "   $PRODUCTION_URL/login"
  fi
fi
