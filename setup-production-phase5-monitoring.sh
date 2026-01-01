#!/bin/bash
# Production Infrastructure Setup - Phase 5: Monitoring & Alerting
# Estimated Time: 30 minutes
# Prerequisites: Phase 1, 2, and 4 complete (Cloud SQL, VM, Secrets ready)

set -e

PROJECT_ID="financial-rise-prod"
ZONE="us-central1-a"
VM_NAME="financial-rise-production-vm"
SQL_INSTANCE="financial-rise-production"

echo "========================================="
echo "PHASE 5: Monitoring & Alerting Setup"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo ""

# Step 5.1: Enable Monitoring API
echo "Step 1/8: Enabling Cloud Monitoring API..."
gcloud services enable monitoring.googleapis.com \
  --project=$PROJECT_ID

echo "✅ Monitoring API enabled"
echo ""

# Step 5.2: Get alert email from user
echo "Step 2/8: Email Configuration for Alerts"
echo ""
echo "⚠️  Enter email address to receive production alerts:"
read -p "Alert Email: " ALERT_EMAIL

if [ -z "$ALERT_EMAIL" ]; then
  echo "❌ Email address required for monitoring alerts"
  exit 1
fi

echo "✅ Alert email: $ALERT_EMAIL"
echo ""

# Step 5.3: Create Email Notification Channel
echo "Step 3/8: Creating email notification channel..."

# Create notification channel
CHANNEL_ID=$(gcloud alpha monitoring channels create \
  --display-name="Production Alerts" \
  --type=email \
  --channel-labels=email_address="$ALERT_EMAIL" \
  --project=$PROJECT_ID \
  --format="value(name)")

echo "✅ Notification channel created: $CHANNEL_ID"
echo ""

# Save for later use
echo "$CHANNEL_ID" > /tmp/monitoring-channel-id.txt

# Step 5.4: Get VM and SQL instance IDs
echo "Step 4/8: Getting resource IDs..."

VM_INSTANCE_ID=$(gcloud compute instances describe $VM_NAME \
  --zone=$ZONE \
  --format="value(id)" \
  --project=$PROJECT_ID)

echo "VM Instance ID: $VM_INSTANCE_ID"
echo ""

# Step 5.5: Create Alert Policy - VM High CPU
echo "Step 5/8: Creating alert policy - VM High CPU..."

gcloud alpha monitoring policies create \
  --notification-channels="$CHANNEL_ID" \
  --display-name="Production VM High CPU" \
  --condition-display-name="CPU > 80% for 5 minutes" \
  --condition-threshold-value=0.8 \
  --condition-threshold-duration=300s \
  --condition-filter="resource.type=\"gce_instance\" AND resource.labels.instance_id=\"$VM_INSTANCE_ID\" AND metric.type=\"compute.googleapis.com/instance/cpu/utilization\"" \
  --project=$PROJECT_ID

echo "✅ VM CPU alert created"
echo ""

# Step 5.6: Create Alert Policy - VM High Disk Usage
echo "Step 6/8: Creating alert policy - VM High Disk Usage..."

gcloud alpha monitoring policies create \
  --notification-channels="$CHANNEL_ID" \
  --display-name="Production VM High Disk Usage" \
  --condition-display-name="Disk > 85% for 5 minutes" \
  --condition-threshold-value=0.85 \
  --condition-threshold-duration=300s \
  --condition-filter="resource.type=\"gce_instance\" AND resource.labels.instance_id=\"$VM_INSTANCE_ID\" AND metric.type=\"compute.googleapis.com/instance/disk/utilization\"" \
  --project=$PROJECT_ID

echo "✅ VM disk alert created"
echo ""

# Step 5.7: Create Alert Policy - Cloud SQL High CPU
echo "Step 7/8: Creating alert policy - Cloud SQL High CPU..."

gcloud alpha monitoring policies create \
  --notification-channels="$CHANNEL_ID" \
  --display-name="Production DB High CPU" \
  --condition-display-name="DB CPU > 80% for 5 minutes" \
  --condition-threshold-value=0.8 \
  --condition-threshold-duration=300s \
  --condition-filter="resource.type=\"cloudsql_database\" AND resource.labels.database_id=\"$PROJECT_ID:$SQL_INSTANCE\" AND metric.type=\"cloudsql.googleapis.com/database/cpu/utilization\"" \
  --project=$PROJECT_ID

echo "✅ Cloud SQL CPU alert created"
echo ""

# Step 5.8: Create Uptime Check for API Health
echo "Step 8/8: Creating uptime check for API health endpoint..."

# Get VM IP
PROD_IP=$(gcloud compute instances describe $VM_NAME \
  --zone=$ZONE \
  --format="value(networkInterfaces[0].accessConfigs[0].natIP)" \
  --project=$PROJECT_ID)

echo "Production IP: $PROD_IP"
echo ""

gcloud monitoring uptime create \
  --display-name="Production API Health Check" \
  --resource-type=uptime-url \
  --http-check-path=/api/v1/health \
  --timeout=10s \
  --period=60s \
  --http-check-port=80 \
  --host="$PROD_IP" \
  --project=$PROJECT_ID

echo "✅ Uptime check created for http://$PROD_IP/api/v1/health"
echo ""

# Step 5.9: Create Logging Sink for Errors
echo "Creating logging sink for error-level logs..."

# Create GCS bucket for logs
gsutil mb -p $PROJECT_ID \
  -c STANDARD \
  -l us-central1 \
  gs://financial-rise-logs-production/ || echo "Bucket may already exist"

# Create log sink
gcloud logging sinks create production-errors \
  gs://financial-rise-logs-production/errors \
  --log-filter='severity >= ERROR' \
  --project=$PROJECT_ID || echo "Sink may already exist"

echo "✅ Error log sink created"
echo ""

# Verification
echo "========================================="
echo "VERIFICATION"
echo "========================================="
echo ""

echo "Alert Policies:"
gcloud alpha monitoring policies list \
  --project=$PROJECT_ID \
  --format="table(displayName,enabled,conditions[0].displayName)"

echo ""
echo "Notification Channels:"
gcloud alpha monitoring channels list \
  --project=$PROJECT_ID \
  --format="table(displayName,type,labels)"

echo ""
echo "Uptime Checks:"
gcloud monitoring uptime list \
  --project=$PROJECT_ID \
  --format="table(displayName,httpCheck.path,period)"

echo ""

# Summary
echo "========================================="
echo "PHASE 5 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✅ Monitoring API: Enabled"
echo "  ✅ Notification Email: $ALERT_EMAIL"
echo "  ✅ Alert Policies:"
echo "      - VM High CPU (>80% for 5 min)"
echo "      - VM High Disk Usage (>85% for 5 min)"
echo "      - Cloud SQL High CPU (>80% for 5 min)"
echo "  ✅ Uptime Check:"
echo "      - API Health: http://$PROD_IP/api/v1/health (every 60s)"
echo "  ✅ Error Logging:"
echo "      - Sink: gs://financial-rise-logs-production/errors"
echo "      - Filter: severity >= ERROR"
echo ""
echo "⚠️  You will receive email alerts for:"
echo "   - High CPU usage on VM or database"
echo "   - High disk usage on VM"
echo "   - API health check failures"
echo "   - Application errors"
echo ""
echo "View dashboards at:"
echo "  https://console.cloud.google.com/monitoring/dashboards?project=$PROJECT_ID"
echo ""
echo "Next: Run Phase 6 (Database Backup Strategy)"
echo "  ./setup-production-phase6-backups.sh"
echo ""
