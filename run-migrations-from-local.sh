#!/bin/bash
# Run migrations from local machine against production database

set -e

echo "========================================"
echo "RUN MIGRATIONS FROM LOCAL MACHINE"
echo "========================================"
echo ""

# Production database connection details
export DATABASE_HOST="34.134.76.171"
export DATABASE_PORT="5432"
export DATABASE_USER="financial_rise"
export DATABASE_PASSWORD="ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE="
export DATABASE_NAME="financial_rise_production"
export NODE_ENV="production"

echo "Connecting to production database:"
echo "  Host: $DATABASE_HOST"
echo "  Database: $DATABASE_NAME"
echo ""

cd financial-rise-app/backend

echo "Installing dependencies if needed..."
npm install --silent 2>/dev/null || echo "Dependencies already installed"

echo ""
echo "Running migrations..."
npm run typeorm migration:run -- -d src/config/typeorm.config.ts

echo ""
echo "✅ Migrations complete!"
echo ""

# Test registration
echo "Testing registration endpoint..."
curl -s -X POST "http://34.72.61.170/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "info@thegracefulpenny.com",
    "password": "DemoPass123!",
    "first_name": "Audrey",
    "last_name": "Heesch",
    "role": "consultant"
  }' | head -20

echo ""
echo ""
echo "========================================"
echo "NEXT STEPS"
echo "========================================"
echo ""
echo "If you see an access_token above, your account was created!"
echo ""
echo "1. Go to: http://34.72.61.170/login"
echo "2. Sign in with:"
echo "   Email: info@thegracefulpenny.com"
echo "   Password: DemoPass123!"
echo ""
