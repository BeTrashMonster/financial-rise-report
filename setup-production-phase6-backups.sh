#!/bin/bash
# Production Infrastructure Setup - Phase 6: Database Backup Strategy
# Estimated Time: 20 minutes
# Prerequisites: Phase 1 complete (Cloud SQL running)

set -e

PROJECT_ID="financial-rise-prod"
ZONE="us-central1-a"
VM_NAME="financial-rise-production-vm"
SQL_INSTANCE="financial-rise-production"
DATABASE_NAME="financial_rise_production"

echo "========================================="
echo "PHASE 6: Database Backup Strategy Setup"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Instance: $SQL_INSTANCE"
echo ""

# Step 6.1: Verify Backup Configuration
echo "Step 1/7: Verifying current backup configuration..."

gcloud sql instances describe $SQL_INSTANCE \
  --format="table(settings.backupConfiguration.enabled,settings.backupConfiguration.startTime,settings.backupConfiguration.pointInTimeRecoveryEnabled,settings.backupConfiguration.transactionLogRetentionDays)" \
  --project=$PROJECT_ID

echo ""

# Step 6.2: Update Backup Configuration
echo "Step 2/7: Updating backup configuration for production..."

gcloud sql instances patch $SQL_INSTANCE \
  --backup-start-time=03:00 \
  --retained-backups-count=30 \
  --retained-transaction-log-days=7 \
  --project=$PROJECT_ID

echo "✅ Backup configuration updated:"
echo "   - Daily backups at 3:00 AM UTC"
echo "   - Retain 30 daily backups"
echo "   - Point-in-time recovery: 7 days"
echo ""

# Step 6.3: Create Manual Pre-Production Backup
echo "Step 3/7: Creating manual backup before deployment..."

BACKUP_DESCRIPTION="Pre-production deployment backup - $(date +%Y-%m-%d)"

gcloud sql backups create \
  --instance=$SQL_INSTANCE \
  --description="$BACKUP_DESCRIPTION" \
  --project=$PROJECT_ID

echo "✅ Manual backup created: $BACKUP_DESCRIPTION"
echo ""

# Step 6.4: Create GCS Bucket for Export Backups
echo "Step 4/7: Creating GCS bucket for off-site database exports..."

gsutil mb -p $PROJECT_ID \
  -c STANDARD \
  -l us-central1 \
  gs://financial-rise-db-exports/ || echo "Bucket may already exist"

echo "✅ GCS bucket created: gs://financial-rise-db-exports/"
echo ""

# Step 6.5: Set Lifecycle Policy on GCS Bucket
echo "Step 5/7: Setting lifecycle policy (delete exports after 90 days)..."

cat > /tmp/lifecycle.json << 'EOF'
{
  "lifecycle": {
    "rule": [
      {
        "action": {"type": "Delete"},
        "condition": {"age": 90}
      }
    ]
  }
}
EOF

gsutil lifecycle set /tmp/lifecycle.json gs://financial-rise-db-exports/

rm /tmp/lifecycle.json

echo "✅ Lifecycle policy set: Delete exports after 90 days"
echo ""

# Step 6.6: Create Backup Export Script on VM
echo "Step 6/7: Creating backup export script on production VM..."

gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="
    cat > ~/backup-to-gcs.sh << 'SCRIPT'
#!/bin/bash
# Export Cloud SQL database to GCS for off-site backup

set -e

PROJECT_ID=\"$PROJECT_ID\"
SQL_INSTANCE=\"$SQL_INSTANCE\"
DATABASE_NAME=\"$DATABASE_NAME\"

TIMESTAMP=\\\$(date +%Y%m%d-%H%M%S)
EXPORT_URI=\"gs://financial-rise-db-exports/production-\\\$TIMESTAMP.sql.gz\"

echo \"Starting database export...\"
echo \"Instance: \\\$SQL_INSTANCE\"
echo \"Database: \\\$DATABASE_NAME\"
echo \"Destination: \\\$EXPORT_URI\"

gcloud sql export sql \\\$SQL_INSTANCE \\\$EXPORT_URI \\
  --database=\\\$DATABASE_NAME \\
  --project=\\\$PROJECT_ID

echo \"✅ Backup exported successfully to: \\\$EXPORT_URI\"
SCRIPT

    chmod +x ~/backup-to-gcs.sh
    echo '✅ Backup script created at ~/backup-to-gcs.sh'
  "

echo "✅ Export script installed on VM"
echo ""

# Step 6.7: Schedule Weekly Export via Cron
echo "Step 7/7: Scheduling weekly database exports..."

gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="
    # Remove existing cron job if present
    crontab -l 2>/dev/null | grep -v 'backup-to-gcs.sh' | crontab - || true

    # Add new cron job: Sunday at 4 AM
    (crontab -l 2>/dev/null; echo '0 4 * * 0 ~/backup-to-gcs.sh >> ~/backup.log 2>&1') | crontab -

    echo '✅ Cron job scheduled: Every Sunday at 4:00 AM'
    echo 'Current crontab:'
    crontab -l
  "

echo "✅ Weekly exports scheduled"
echo ""

# Step 6.8: Create Disaster Recovery Documentation
echo "Creating disaster recovery documentation..."

cat > DISASTER-RECOVERY.md << 'EOF'
# Disaster Recovery Procedure - Financial RISE Production

**Last Updated:** $(date +%Y-%m-%d)

## Recovery Objectives

- **RTO (Recovery Time Objective):** 1 hour
- **RPO (Recovery Point Objective):** 24 hours (daily backups)
- **Point-in-Time Recovery Window:** 7 days

---

## Backup Strategy

### Automated Backups (Cloud SQL)
- **Frequency:** Daily at 3:00 AM UTC
- **Retention:** 30 daily backups
- **Type:** Full database backup
- **Location:** us-central1 (same region as production)

### Off-Site Exports (GCS)
- **Frequency:** Weekly on Sunday at 4:00 AM
- **Retention:** 90 days (auto-deleted via lifecycle policy)
- **Location:** gs://financial-rise-db-exports/
- **Format:** Compressed SQL dump (.sql.gz)

### Point-in-Time Recovery
- **Window:** Last 7 days
- **Type:** Transaction log replay
- **Granularity:** Any point in time down to the second

---

## Recovery Procedures

### Scenario 1: Full Database Restore from Automated Backup

**When to use:** Database corruption, accidental data deletion (older than 7 days)

```bash
# 1. List available backups
gcloud sql backups list \
  --instance=financial-rise-production \
  --project=financial-rise-prod

# 2. Stop application to prevent new writes
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker compose -f financial-rise-app/docker-compose.prod.yml down"

# 3. Restore from backup (DESTRUCTIVE - replaces all data)
gcloud sql backups restore BACKUP_ID \
  --instance=financial-rise-production \
  --project=financial-rise-prod

# 4. Restart application
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker compose -f financial-rise-app/docker-compose.prod.yml up -d"
```

**Estimated Time:** 20-30 minutes

---

### Scenario 2: Point-in-Time Recovery

**When to use:** Recent data corruption, need to recover to specific moment

```bash
# 1. Clone database to specific point in time (creates new instance)
gcloud sql instances clone financial-rise-production \
  financial-rise-production-recovery \
  --point-in-time='2026-01-01T14:30:00.000Z' \
  --project=financial-rise-prod

# 2. Verify recovered data
gcloud sql connect financial-rise-production-recovery --user=financial_rise

# 3. If data looks correct, replace production instance:

# Option A: Export from recovery instance and import to production
gcloud sql export sql financial-rise-production-recovery \
  gs://financial-rise-db-exports/recovery-export.sql.gz \
  --database=financial_rise_production \
  --project=financial-rise-prod

# Stop production app
docker compose down

# Import to production
gcloud sql import sql financial-rise-production \
  gs://financial-rise-db-exports/recovery-export.sql.gz \
  --database=financial_rise_production \
  --project=financial-rise-prod

# Restart app
docker compose up -d

# 4. Delete recovery instance
gcloud sql instances delete financial-rise-production-recovery \
  --project=financial-rise-prod
```

**Estimated Time:** 45-60 minutes

---

### Scenario 3: Restore from GCS Export (Off-Site Backup)

**When to use:** Regional failure, Cloud SQL backups unavailable

```bash
# 1. List available GCS exports
gsutil ls gs://financial-rise-db-exports/

# 2. Stop application
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker compose -f financial-rise-app/docker-compose.prod.yml down"

# 3. Import backup from GCS
gcloud sql import sql financial-rise-production \
  gs://financial-rise-db-exports/production-20260101-040000.sql.gz \
  --database=financial_rise_production \
  --project=financial-rise-prod

# 4. Restart application
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker compose -f financial-rise-app/docker-compose.prod.yml up -d"
```

**Estimated Time:** 30-45 minutes

---

## Manual Backup (Before Major Changes)

**Run before:** Schema migrations, major deployments, bulk data operations

```bash
# Create manual backup with description
gcloud sql backups create \
  --instance=financial-rise-production \
  --description="Pre-deployment backup: $(date +%Y-%m-%d)" \
  --project=financial-rise-prod

# Export to GCS for extra safety
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="~/backup-to-gcs.sh"
```

---

## Testing & Validation

### Monthly Restore Test

**Purpose:** Verify backups are restorable and data is intact

```bash
# 1. Create test instance from latest backup
LATEST_BACKUP=$(gcloud sql backups list \
  --instance=financial-rise-production \
  --limit=1 \
  --format="value(id)" \
  --project=financial-rise-prod)

gcloud sql backups restore $LATEST_BACKUP \
  --backup-instance=financial-rise-production \
  --instance=financial-rise-test-restore \
  --project=financial-rise-prod

# 2. Connect and verify data
gcloud sql connect financial-rise-test-restore --user=financial_rise

# 3. Run test queries
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM assessments;

# 4. Delete test instance
gcloud sql instances delete financial-rise-test-restore \
  --project=financial-rise-prod
```

### Quarterly DR Drill

**Purpose:** Full disaster recovery practice

1. Schedule maintenance window
2. Create manual backup
3. Simulate failure (rename production instance)
4. Perform full recovery
5. Verify application functionality
6. Document time taken and issues
7. Restore original instance

---

## Contacts & Escalation

- **Primary:** [Your Email]
- **GCP Support:** https://console.cloud.google.com/support
- **Backup Location:** gs://financial-rise-db-exports/
- **Monitoring:** https://console.cloud.google.com/monitoring

---

**Important:** Test recovery procedures regularly. Untested backups are not backups.
EOF

echo "✅ Disaster recovery documentation created"
echo ""

# Verification
echo "========================================="
echo "VERIFICATION"
echo "========================================="
echo ""

echo "Backup Configuration:"
gcloud sql instances describe $SQL_INSTANCE \
  --format="table(settings.backupConfiguration.enabled,settings.backupConfiguration.startTime,settings.backupConfiguration.pointInTimeRecoveryEnabled)" \
  --project=$PROJECT_ID

echo ""
echo "Available Backups:"
gcloud sql backups list \
  --instance=$SQL_INSTANCE \
  --limit=5 \
  --project=$PROJECT_ID

echo ""
echo "GCS Export Bucket:"
gsutil ls -L gs://financial-rise-db-exports/ | head -10

echo ""
echo "Backup Script on VM:"
gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="ls -lh ~/backup-to-gcs.sh && echo '' && echo 'Cron Jobs:' && crontab -l | grep backup"

echo ""

# Summary
echo "========================================="
echo "PHASE 6 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✅ Automated Backups:"
echo "      - Daily at 3:00 AM UTC"
echo "      - Retention: 30 days"
echo "      - Point-in-time recovery: 7 days"
echo "  ✅ Off-Site Exports:"
echo "      - Weekly on Sunday at 4:00 AM"
echo "      - Location: gs://financial-rise-db-exports/"
echo "      - Retention: 90 days (auto-delete)"
echo "  ✅ Backup Script:"
echo "      - Installed on VM: ~/backup-to-gcs.sh"
echo "      - Scheduled via cron"
echo "  ✅ Disaster Recovery:"
echo "      - Documentation: DISASTER-RECOVERY.md"
echo "      - RTO: 1 hour"
echo "      - RPO: 24 hours"
echo ""
echo "⚠️  CRITICAL: Test restore procedures monthly!"
echo ""
echo "Test backup restore now:"
echo "  gcloud sql backups list --instance=$SQL_INSTANCE --project=$PROJECT_ID"
echo ""
echo "Manual backup script:"
echo "  gcloud compute ssh $VM_NAME --zone=$ZONE --command='~/backup-to-gcs.sh'"
echo ""
echo "Next: Run Phase 7 (GitHub Secrets Configuration)"
echo "  ./setup-production-phase7-github.sh"
echo ""
echo "Or if all phases complete, proceed to deployment!"
echo ""
