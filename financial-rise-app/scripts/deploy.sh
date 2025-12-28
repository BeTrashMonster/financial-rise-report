#!/bin/bash
#
# Financial RISE - GCP Deployment Script
# Usage: ./deploy.sh [staging|production]
#
# SECURITY: This script loads ALL secrets from GCP Secret Manager
# Work Stream 51 (CRIT-001) - Secrets Management & Rotation
#
# Required GCP Secrets:
# - financial-rise-${ENVIRONMENT}-env (contains all environment variables)
# - JWT_SECRET (loaded via SecretsService in application)
# - REFRESH_TOKEN_SECRET (loaded via SecretsService in application)
# - DATABASE_PASSWORD (loaded via SecretsService in application)
# - DB_ENCRYPTION_KEY (loaded via SecretsService in application)
#
# Prerequisites:
# 1. GCP CLI (gcloud) installed and authenticated
# 2. Service account with roles/secretmanager.secretAccessor permission
# 3. Secrets created in GCP Secret Manager for target environment
#

set -e

ENVIRONMENT=${1:-staging}
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"

echo "======================================"
echo "Financial RISE Deployment Script"
echo "Environment: $ENVIRONMENT"
echo "Security: GCP Secret Manager"
echo "======================================"

# Validate environment
if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
    echo "❌ Error: Invalid environment. Use 'staging' or 'production'"
    exit 1
fi

# Check if running on VM
if [ ! -d "/opt/financial-rise" ]; then
    echo "⚠️  Warning: /opt/financial-rise not found. Are you on the VM?"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

cd /opt/financial-rise || exit 1

# CRITICAL SECURITY: Load ALL secrets from GCP Secret Manager
# This ensures NO secrets are hardcoded in version control (CRIT-001)
echo "📥 Loading secrets from GCP Secret Manager..."
echo "   Secret: financial-rise-${ENVIRONMENT}-env"

gcloud secrets versions access latest \
    --secret="financial-rise-${ENVIRONMENT}-env" > .env

if [ $? -ne 0 ]; then
    echo "❌ Failed to pull secrets from GCP Secret Manager"
    echo "   Ensure the secret 'financial-rise-${ENVIRONMENT}-env' exists"
    echo "   and you have roles/secretmanager.secretAccessor permission"
    exit 1
fi

echo "✅ Secrets loaded from GCP Secret Manager"
echo "   Application will validate secret strength on startup"

# Configure Docker for Artifact Registry
echo "🔐 Configuring Docker for Artifact Registry..."
gcloud auth configure-docker us-central1-docker.pkg.dev

# Create backup before deployment
echo "💾 Creating database backup..."
BACKUP_FILE="backup-$(date +%Y%m%d-%H%M%S).sql"

# Try to backup (will fail gracefully if using Cloud SQL)
docker compose $COMPOSE_FILES exec -T postgres \
    pg_dump -U financial_rise financial_rise_${ENVIRONMENT} > $BACKUP_FILE 2>/dev/null || \
    echo "⏭️  Using Cloud SQL, skipping local backup"

if [ -f "$BACKUP_FILE" ] && [ -s "$BACKUP_FILE" ]; then
    echo "✅ Backup created: $BACKUP_FILE"
    # Upload to GCS
    gcloud storage cp $BACKUP_FILE gs://financial-rise-backups/$BACKUP_FILE
    echo "☁️  Backup uploaded to GCS"
else
    echo "⏭️  No local backup created (using Cloud SQL)"
fi

# Pull latest Docker images
echo "🐳 Pulling latest Docker images..."
docker compose $COMPOSE_FILES pull

if [ $? -ne 0 ]; then
    echo "❌ Failed to pull Docker images"
    exit 1
fi

# Run database migrations
echo "📊 Running database migrations..."
docker compose $COMPOSE_FILES run --rm backend npm run migration:run || \
    echo "⏭️  Migrations completed or skipped"

# Deploy based on environment
if [ "$ENVIRONMENT" = "production" ]; then
    echo "🚀 Deploying to PRODUCTION with zero-downtime strategy..."

    # Rolling restart
    echo "   🔄 Restarting backend..."
    docker compose $COMPOSE_FILES up -d --no-deps --force-recreate backend
    sleep 20

    echo "   🔄 Restarting frontend..."
    docker compose $COMPOSE_FILES up -d --no-deps --force-recreate frontend
    sleep 10

else
    echo "🚀 Deploying to STAGING..."
    docker compose $COMPOSE_FILES up -d --force-recreate
    sleep 15
fi

# Health check
echo "🏥 Running health check..."
./scripts/health-check.sh

if [ $? -eq 0 ]; then
    echo ""
    echo "======================================"
    echo "✅ Deployment successful!"
    echo "Environment: $ENVIRONMENT"
    echo "Time: $(date)"
    echo "======================================"
    echo ""
    echo "📊 Running containers:"
    docker ps --filter "name=financial-rise"
else
    echo ""
    echo "======================================"
    echo "❌ Deployment failed - health check did not pass"
    echo "======================================"
    echo ""
    echo "🔍 Recent logs:"
    docker compose $COMPOSE_FILES logs --tail=50
    exit 1
fi
