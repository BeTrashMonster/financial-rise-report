#!/bin/bash
# Script to run database migrations on production
# Usage: Run this from the VM after SSHing in

set -e

echo "=== Running Database Migration on Production ==="
echo "This will add missing columns to disc_profiles and reports tables"
echo ""

# Navigate to production directory
cd /opt/financial-rise

# Build the backend with the new migration
echo "Building backend with new migration..."
docker-compose -f docker-compose.prod.yml build backend

# Run the migration
echo "Running database migration..."
docker-compose -f docker-compose.prod.yml run --rm backend npm run typeorm migration:run -- -d src/config/typeorm.config.ts

echo ""
echo "=== Migration Complete! ==="
echo "Restarting services..."

# Restart services to pick up changes
docker-compose -f docker-compose.prod.yml up -d

echo "Done! Check logs with:"
echo "  docker-compose -f docker-compose.prod.yml logs -f backend"
