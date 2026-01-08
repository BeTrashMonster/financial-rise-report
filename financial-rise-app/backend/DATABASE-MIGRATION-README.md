# Database Migration Guide

## Overview

This guide explains how to run the database schema fix migration on production.

## What This Migration Does

**Migration:** `1767906953082-FixDatabaseSchema.ts`

This migration fixes two critical database schema issues preventing PDF generation:

### 1. disc_profiles Table
Adds missing `assessment_id` column (UUID, NOT NULL) which is required for the foreign key relationship to assessments.

### 2. reports Table
Adds six missing columns needed for PDF report generation:
- `status` - enum ('generating', 'completed', 'failed') with default 'generating'
- `file_url` - text, nullable (stores PDF download URL)
- `file_size_bytes` - integer, nullable (stores PDF file size)
- `generated_at` - timestamp, nullable (when PDF was generated)
- `expires_at` - timestamp, nullable (when signed URL expires)
- `error` - text, nullable (error message if generation failed)

## Prerequisites

1. SSH access to production VM: `gcloud compute ssh financial-rise-vm`
2. Docker and docker-compose running on production
3. Backend code with the new migration deployed

## Method 1: Using the Script (Recommended)

The easiest way is to use the provided script:

```bash
# SSH into VM
gcloud compute ssh financial-rise-vm

# Navigate to project directory
cd /opt/financial-rise

# Copy the migration script to VM (if not already there)
# Then run it:
bash backend/run-migration-prod.sh
```

The script will:
1. Build the backend container with the new migration
2. Run the migration using TypeORM
3. Restart all services

## Method 2: Manual Steps

If the script doesn't work, run these commands manually:

```bash
# SSH into VM
gcloud compute ssh financial-rise-vm

# Navigate to project directory
cd /opt/financial-rise

# Pull latest code
git pull origin main

# Build backend with new migration
docker-compose -f docker-compose.prod.yml build backend

# Run the migration
docker-compose -f docker-compose.prod.yml run --rm backend npm run migration:run

# Restart services
docker-compose -f docker-compose.prod.yml up -d

# Check logs for errors
docker-compose -f docker-compose.prod.yml logs -f backend
```

## Method 3: Direct SQL (Emergency Fallback)

If TypeORM migration fails, you can run the SQL directly:

```bash
# Get database credentials from backend container
docker exec financial-rise-backend-prod env | grep DATABASE

# Install postgresql-client in container
docker exec -u root financial-rise-backend-prod apt-get update && apt-get install -y postgresql-client

# Create SQL file
cat > /tmp/fix-schema.sql << 'EOF'
-- Fix disc_profiles table
ALTER TABLE disc_profiles
ADD COLUMN IF NOT EXISTS assessment_id UUID;

-- Fix reports table
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'report_status') THEN
        CREATE TYPE report_status AS ENUM ('generating', 'completed', 'failed');
    END IF;
END $$;

ALTER TABLE reports ADD COLUMN IF NOT EXISTS status report_status DEFAULT 'generating';
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_url TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_size_bytes INTEGER;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS generated_at TIMESTAMP;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS error TEXT;
EOF

# Run SQL using psql from container
docker exec -i financial-rise-backend-prod sh -c 'PGPASSWORD=$DATABASE_PASSWORD psql -h $DATABASE_HOST -U $DATABASE_USER -d $DATABASE_NAME' < /tmp/fix-schema.sql
```

## Verification

After running the migration, verify it worked:

```bash
# Check migration was recorded
docker-compose -f docker-compose.prod.yml exec backend npm run typeorm migration:show

# Check backend logs for errors
docker-compose -f docker-compose.prod.yml logs backend | tail -50

# Test PDF generation
# 1. Go to https://getoffthemoneyshametrain.com
# 2. Complete an assessment
# 3. Click "Generate Report"
# 4. Should see report generating, then download link
```

## Rollback

If something goes wrong, you can rollback the migration:

```bash
cd /opt/financial-rise
docker-compose -f docker-compose.prod.yml run --rm backend npm run migration:revert
docker-compose -f docker-compose.prod.yml up -d
```

## Troubleshooting

### Migration Already Run
If you see "QueryFailedError: column already exists", the migration was already applied. This is safe to ignore.

### psql Not Found
Install postgresql-client in the container:
```bash
docker exec -u root financial-rise-backend-prod apt-get update && apt-get install -y postgresql-client
```

### Database Connection Errors
Check environment variables are set correctly:
```bash
docker exec financial-rise-backend-prod env | grep DATABASE
```

### Build Timeout
If the build takes too long, try building locally and pushing the image:
```bash
# On local machine
cd backend
docker build -t gcr.io/financial-rise-1234/backend:latest .
docker push gcr.io/financial-rise-1234/backend:latest

# On VM
docker-compose -f docker-compose.prod.yml pull backend
docker-compose -f docker-compose.prod.yml up -d
```

## Related Issues

- **ERROR-LOGS.md Issue 9**: disc_profiles.assessment_id constraint
- **ERROR-LOGS.md Issue 10**: reports table missing columns

## Next Steps After Migration

1. Test PDF generation end-to-end
2. Verify report download URLs work
3. Check that expired reports are handled correctly
4. Monitor logs for any new errors

## Questions?

Check the main ERROR-LOGS.md for full context on these issues.
