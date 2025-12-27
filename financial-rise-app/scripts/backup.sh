#!/bin/bash
#
# Financial RISE - Database Backup Script
# Creates a backup of the database and uploads to GCS
# Usage: ./backup.sh [staging|production]
#

set -e

ENVIRONMENT=${1:-production}
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="backup-${ENVIRONMENT}-${TIMESTAMP}.sql"
COMPOSE_FILES="-f docker-compose.yml -f docker-compose.prod.yml"

echo "======================================"
echo "Financial RISE Database Backup"
echo "Environment: $ENVIRONMENT"
echo "======================================"

# Validate environment
if [ "$ENVIRONMENT" != "staging" ] && [ "$ENVIRONMENT" != "production" ]; then
    echo "❌ Error: Invalid environment. Use 'staging' or 'production'"
    exit 1
fi

cd /opt/financial-rise || exit 1

# Create backup
echo "💾 Creating database backup..."

# Try to backup from local postgres container (for development)
# If using Cloud SQL, this will fail gracefully
if docker compose $COMPOSE_FILES ps postgres | grep -q "Up"; then
    echo "📦 Backing up from local PostgreSQL container..."
    docker compose $COMPOSE_FILES exec -T postgres \
        pg_dump -U financial_rise financial_rise_${ENVIRONMENT} > $BACKUP_FILE

    if [ -s "$BACKUP_FILE" ]; then
        echo "✅ Local backup created: $BACKUP_FILE"
        SIZE=$(du -h $BACKUP_FILE | cut -f1)
        echo "   Size: $SIZE"
    else
        echo "❌ Backup file is empty"
        rm -f $BACKUP_FILE
        exit 1
    fi
else
    echo "📦 No local PostgreSQL container found"
    echo "   If using Cloud SQL, use Cloud SQL automated backups"
    echo "   Or manually export: gcloud sql export sql INSTANCE_NAME gs://BUCKET/backup.sql --database=DB_NAME"
    exit 0
fi

# Upload to Google Cloud Storage
echo "☁️  Uploading backup to GCS..."
GCS_BUCKET="gs://financial-rise-backups"

gcloud storage cp $BACKUP_FILE $GCS_BUCKET/$BACKUP_FILE

if [ $? -eq 0 ]; then
    echo "✅ Backup uploaded successfully"
    echo "   Location: $GCS_BUCKET/$BACKUP_FILE"

    # Clean up local backup file
    rm -f $BACKUP_FILE
    echo "🧹 Local backup file removed"
else
    echo "❌ Failed to upload backup to GCS"
    echo "   Local backup preserved at: $BACKUP_FILE"
    exit 1
fi

# Rotate old backups (keep last 30 days)
echo "🔄 Rotating old backups (keeping last 30 days)..."

gcloud storage ls $GCS_BUCKET/ | \
    grep "backup-${ENVIRONMENT}-" | \
    sort -r | \
    tail -n +31 | \
    while read -r old_backup; do
        echo "   Deleting old backup: $old_backup"
        gcloud storage rm "$old_backup" || true
    done

echo ""
echo "======================================"
echo "✅ Backup completed successfully"
echo "======================================"
