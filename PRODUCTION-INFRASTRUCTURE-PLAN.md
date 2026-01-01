# Production Infrastructure Setup Plan

**Date:** 2026-01-01
**Status:** READY FOR EXECUTION
**Estimated Time:** 2-3 hours
**Security Requirements:** Based on SECURITY-AUDIT-REPORT.md

---

## Executive Summary

This plan addresses the 6 infrastructure-level items required for production deployment:

1. ✅ **Cloud SQL Private IP** (vs current public IP)
2. ✅ **Standard VM** (vs current preemptible)
3. ✅ **SSL/HTTPS Certificates**
4. ✅ **Production Secret Manager**
5. ✅ **Monitoring & Alerting**
6. ✅ **Database Backup Strategy**

**Staging Status:** Fully operational, all application security complete (16/16 work streams)
**Blocker:** Infrastructure hardening required before production deployment

---

## Phase 1: Cloud SQL with Private IP (Critical)

### Current State
- **Staging:** Cloud SQL with public IP + authorized networks
- **Security Risk:** Acceptable for staging, **NOT** for production
- **Issue:** Database exposed to internet (even with IP whitelist)

### Production Requirement
**Use Cloud SQL with Private IP via VPC peering**

### Implementation Steps

**1.1 Enable Service Networking API**
```bash
gcloud services enable servicenetworking.googleapis.com \
  --project=financial-rise-prod
```

**1.2 Allocate IP Range for Private Service Connection**
```bash
gcloud compute addresses create google-managed-services-financial-rise-vpc \
  --global \
  --purpose=VPC_PEERING \
  --prefix-length=16 \
  --network=financial-rise-vpc \
  --project=financial-rise-prod
```

**1.3 Create VPC Peering Connection**
```bash
gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges=google-managed-services-financial-rise-vpc \
  --network=financial-rise-vpc \
  --project=financial-rise-prod
```

**1.4 Create Production Cloud SQL Instance with Private IP**
```bash
gcloud sql instances create financial-rise-production \
  --database-version=POSTGRES_14 \
  --tier=db-g1-small \
  --region=us-central1 \
  --network=projects/financial-rise-prod/global/networks/financial-rise-vpc \
  --no-assign-ip \
  --storage-type=SSD \
  --storage-size=20GB \
  --storage-auto-increase \
  --enable-bin-log \
  --backup-start-time=03:00 \
  --maintenance-window-day=SUN \
  --maintenance-window-hour=04 \
  --availability-type=ZONAL \
  --project=financial-rise-prod
```

**Key Flags:**
- `--no-assign-ip`: No public IP address (private only)
- `--network`: VPC peering enabled
- `--availability-type=ZONAL`: Single zone (cost optimized, scalable to REGIONAL later)
- `--enable-bin-log`: Point-in-time recovery

**1.5 Create Production Database**
```bash
gcloud sql databases create financial_rise_production \
  --instance=financial-rise-production \
  --project=financial-rise-prod
```

**1.6 Create Production Database User**
```bash
# Generate secure password
PROD_DB_PASSWORD=$(openssl rand -base64 32)

gcloud sql users create financial_rise \
  --instance=financial-rise-production \
  --password="$PROD_DB_PASSWORD" \
  --project=financial-rise-prod

echo "Production DB Password: $PROD_DB_PASSWORD"
echo "Save this to Secret Manager!"
```

**1.7 Get Private IP Address**
```bash
gcloud sql instances describe financial-rise-production \
  --format="value(ipAddresses[0].ipAddress)" \
  --project=financial-rise-prod
```

**Verification:**
```bash
# Should show ONLY private IP (10.x.x.x)
gcloud sql instances describe financial-rise-production \
  --format="table(ipAddresses[].ipAddress,ipAddresses[].type)"
```

**Estimated Time:** 15-20 minutes (instance creation takes time)

---

## Phase 2: Standard Production VM (Critical)

### Current State
- **Staging:** e2-medium preemptible VM (restarts every 24h)
- **Issue:** Preemptible VMs unsuitable for production (unreliable)

### Production Requirement
**Standard e2-standard-2 VM with proper uptime SLA**

### Implementation Steps

**2.1 Reserve Static IP for Production**
```bash
gcloud compute addresses create financial-rise-production-ip \
  --region=us-central1 \
  --project=financial-rise-prod
```

**2.2 Get Reserved IP**
```bash
PROD_IP=$(gcloud compute addresses describe financial-rise-production-ip \
  --region=us-central1 \
  --format="value(address)" \
  --project=financial-rise-prod)

echo "Production IP: $PROD_IP"
```

**2.3 Create Standard Production VM**
```bash
gcloud compute instances create financial-rise-production-vm \
  --zone=us-central1-a \
  --machine-type=e2-standard-2 \
  --network-interface=network-tier=PREMIUM,address=$PROD_IP,network=financial-rise-vpc,subnet=financial-rise-vpc \
  --maintenance-policy=MIGRATE \
  --provisioning-model=STANDARD \
  --tags=http-server,https-server,allow-ssh \
  --create-disk=auto-delete=yes,boot=yes,device-name=financial-rise-production-vm,image=projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20241211,mode=rw,size=50,type=pd-balanced \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --project=financial-rise-prod
```

**Key Differences from Staging:**
- `--machine-type=e2-standard-2` (vs e2-medium): More resources for production
- `--provisioning-model=STANDARD` (vs SPOT): NOT preemptible - reliable uptime
- `--maintenance-policy=MIGRATE`: VM migrates during maintenance (no downtime)
- `--size=50`: 50GB disk (vs 30GB staging)
- Static IP assigned

**2.4 Install Docker on Production VM**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    # Update system
    sudo apt-get update
    sudo apt-get install -y ca-certificates curl gnupg

    # Add Docker's official GPG key
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # Add Docker repository
    echo \
      \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      \$(. /etc/os-release && echo \\\"\$VERSION_CODENAME\\\") stable\" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    # Add user to docker group
    sudo usermod -aG docker \$USER

    # Fix permissions
    sudo chmod 666 /var/run/docker.sock

    # Verify installation
    docker --version
    docker compose version
  " \
  --project=financial-rise-prod
```

**Verification:**
```bash
# Verify VM is running
gcloud compute instances describe financial-rise-production-vm \
  --zone=us-central1-a \
  --format="table(name,status,machineType,networkInterfaces[0].accessConfigs[0].natIP)"
```

**Estimated Time:** 10 minutes

---

## Phase 3: SSL/HTTPS Certificates (Critical)

### Current State
- **Staging:** HTTP only (no SSL)
- **Issue:** Production requires HTTPS for security

### Production Requirement
**Let's Encrypt SSL certificates with auto-renewal**

### Options Analysis

**Option 1: Certbot (Manual) ✅ Recommended for MVP**
- Pro: Simple, free, well-documented
- Pro: Works without domain immediately (self-signed for testing)
- Con: Manual renewal every 90 days (can be automated)

**Option 2: Google-Managed SSL (Requires Domain)**
- Pro: Automatic renewal, no maintenance
- Pro: Free via GCP
- Con: REQUIRES domain name configured
- Con: DNS must be set up first

**Option 3: Cloudflare (Best for Production)**
- Pro: Automatic renewal, CDN, DDoS protection
- Pro: Free tier available
- Con: REQUIRES domain name
- Con: Extra service to manage

### Implementation Steps (Option 1: Certbot)

**3.1 Install Certbot on Production VM**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    sudo apt-get update
    sudo apt-get install -y certbot python3-certbot-nginx

    # Verify installation
    certbot --version
  " \
  --project=financial-rise-prod
```

**3.2 DNS Setup (IF YOU HAVE A DOMAIN)**
```bash
# Point your domain to the production IP
# Example: financialrise.com -> $PROD_IP
# This is done in your domain registrar's DNS settings

# Verify DNS propagation
nslookup financialrise.com
```

**3.3 Option A: With Domain - Get Real Certificate**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    # Stop nginx if running
    sudo docker stop financial-rise-frontend-prod 2>/dev/null || true

    # Get certificate (interactive)
    sudo certbot certonly --standalone \
      -d financialrise.com \
      -d www.financialrise.com \
      --email your-email@example.com \
      --agree-tos \
      --non-interactive

    # Certificates will be in:
    # /etc/letsencrypt/live/financialrise.com/fullchain.pem
    # /etc/letsencrypt/live/financialrise.com/privkey.pem
  " \
  --project=financial-rise-prod
```

**3.4 Option B: Without Domain - Self-Signed Certificate (Testing)**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    # Create self-signed certificate
    sudo mkdir -p /etc/ssl/certs /etc/ssl/private

    sudo openssl req -x509 -nodes -days 365 \
      -newkey rsa:2048 \
      -keyout /etc/ssl/private/financial-rise.key \
      -out /etc/ssl/certs/financial-rise.crt \
      -subj \"/C=US/ST=State/L=City/O=Financial RISE/CN=$PROD_IP\"

    # Certificates at:
    # /etc/ssl/certs/financial-rise.crt
    # /etc/ssl/private/financial-rise.key
  " \
  --project=financial-rise-prod
```

**3.5 Update Frontend Nginx Config for SSL**
```nginx
# Add to financial-rise-app/frontend/nginx.conf

server {
    listen 80;
    listen [::]:80;
    server_name financialrise.com www.financialrise.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name financialrise.com www.financialrise.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/financialrise.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/financialrise.com/privkey.pem;

    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # ... rest of existing config
}
```

**3.6 Update docker-compose.prod.yml to Mount Certificates**
```yaml
frontend:
  volumes:
    - /etc/letsencrypt:/etc/letsencrypt:ro  # Mount SSL certificates
    - /etc/ssl:/etc/ssl:ro  # Or self-signed certs
```

**3.7 Set Up Auto-Renewal (If Using Let's Encrypt)**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    # Test renewal
    sudo certbot renew --dry-run

    # Set up cron job for auto-renewal
    (crontab -l 2>/dev/null; echo '0 3 * * * sudo certbot renew --quiet --post-hook \"docker restart financial-rise-frontend-prod\"') | crontab -
  " \
  --project=financial-rise-prod
```

**Verification:**
```bash
# Test HTTPS
curl -k https://$PROD_IP/api/v1/health

# Check certificate
openssl s_client -connect $PROD_IP:443 -servername financialrise.com
```

**Estimated Time:** 30 minutes

**Decision Point:** Do you have a domain name ready, or should we use self-signed certificates for now?

---

## Phase 4: Production Secret Manager (Critical)

### Current State
- **Staging:** `financial-rise-staging-env` (version 4) with all required secrets

### Production Requirement
**Separate production Secret Manager with unique secrets**

### Implementation Steps

**4.1 Generate Production Secrets**
```bash
# Generate JWT secrets (64 bytes base64)
JWT_SECRET=$(openssl rand -base64 64)
JWT_REFRESH_SECRET=$(openssl rand -base64 64)

# For backwards compatibility
TOKEN_SECRET=$JWT_SECRET
REFRESH_TOKEN_SECRET=$JWT_REFRESH_SECRET

# Generate encryption key (32 bytes hex = 64 characters)
DB_ENCRYPTION_KEY=$(openssl rand -hex 32)

# SendGrid API key (you'll need to get this from SendGrid)
SENDGRID_API_KEY="your-sendgrid-api-key"

echo "Generated secrets - save these!"
echo "JWT_SECRET=$JWT_SECRET"
echo "JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET"
echo "DB_ENCRYPTION_KEY=$DB_ENCRYPTION_KEY"
```

**4.2 Create Production Environment File**
```bash
# Get private IP from Cloud SQL
PROD_DB_HOST=$(gcloud sql instances describe financial-rise-production \
  --format="value(ipAddresses[0].ipAddress)" \
  --project=financial-rise-prod)

# Create .env.production file
cat > .env.production << EOF
# Database Configuration (PRIVATE IP)
DATABASE_HOST=$PROD_DB_HOST
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=$PROD_DB_PASSWORD
DATABASE_NAME=financial_rise_production

# JWT Configuration
JWT_SECRET=$JWT_SECRET
JWT_REFRESH_SECRET=$JWT_REFRESH_SECRET

# Backwards compatibility
TOKEN_SECRET=$TOKEN_SECRET
REFRESH_TOKEN_SECRET=$REFRESH_TOKEN_SECRET

# GCP Configuration
GCS_BUCKET=financial-rise-reports-production
GCP_PROJECT_ID=financial-rise-prod

# Application Configuration
NODE_ENV=production
PORT=4000
FRONTEND_URL=https://financialrise.com

# Email Configuration
SENDGRID_API_KEY=$SENDGRID_API_KEY

# Database Encryption Key (32 bytes hex = 64 characters)
DB_ENCRYPTION_KEY=$DB_ENCRYPTION_KEY

# Redis Configuration (optional password)
REDIS_PASSWORD=$(openssl rand -base64 32)
EOF
```

**4.3 Store in Secret Manager**
```bash
gcloud secrets create financial-rise-production-env \
  --data-file=.env.production \
  --replication-policy=automatic \
  --project=financial-rise-prod
```

**4.4 Grant VM Access to Secrets**
```bash
# Get the VM's service account
VM_SERVICE_ACCOUNT=$(gcloud compute instances describe financial-rise-production-vm \
  --zone=us-central1-a \
  --format="value(serviceAccounts[0].email)" \
  --project=financial-rise-prod)

# Grant access to production secrets
gcloud secrets add-iam-policy-binding financial-rise-production-env \
  --member="serviceAccount:$VM_SERVICE_ACCOUNT" \
  --role="roles/secretmanager.secretAccessor" \
  --project=financial-rise-prod
```

**4.5 Verify Secret Access**
```bash
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod | head -5
```

**4.6 Delete Local File (Security)**
```bash
# IMPORTANT: Delete .env.production after uploading to Secret Manager
rm .env.production

# Verify it's in Secret Manager
gcloud secrets versions list financial-rise-production-env \
  --project=financial-rise-prod
```

**Estimated Time:** 15 minutes

---

## Phase 5: Monitoring & Alerting (Critical)

### Current State
- **Staging:** No monitoring configured
- **Issue:** Can't detect production issues proactively

### Production Requirement
**Cloud Monitoring with alerts for critical metrics**

### Implementation Steps

**5.1 Enable Monitoring API**
```bash
gcloud services enable monitoring.googleapis.com \
  --project=financial-rise-prod
```

**5.2 Create Notification Channel (Email)**
```bash
# Create email notification channel
gcloud alpha monitoring channels create \
  --display-name="Production Alerts" \
  --type=email \
  --channel-labels=email_address=your-email@example.com \
  --project=financial-rise-prod
```

**5.3 Create Alert Policies**

**Alert 1: VM CPU Usage**
```bash
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="Production VM High CPU" \
  --condition-display-name="CPU > 80%" \
  --condition-threshold-value=0.8 \
  --condition-threshold-duration=300s \
  --condition-filter='resource.type="gce_instance" AND resource.labels.instance_id="INSTANCE_ID" AND metric.type="compute.googleapis.com/instance/cpu/utilization"' \
  --project=financial-rise-prod
```

**Alert 2: VM Disk Usage**
```bash
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="Production VM High Disk Usage" \
  --condition-display-name="Disk > 85%" \
  --condition-threshold-value=0.85 \
  --condition-threshold-duration=300s \
  --condition-filter='resource.type="gce_instance" AND metric.type="compute.googleapis.com/instance/disk/utilization"' \
  --project=financial-rise-prod
```

**Alert 3: Cloud SQL High Connections**
```bash
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="Production DB High Connections" \
  --condition-display-name="Connections > 80%" \
  --condition-threshold-value=80 \
  --condition-threshold-duration=300s \
  --condition-filter='resource.type="cloudsql_database" AND metric.type="cloudsql.googleapis.com/database/postgresql/num_backends"' \
  --project=financial-rise-prod
```

**Alert 4: Cloud SQL High CPU**
```bash
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="Production DB High CPU" \
  --condition-display-name="DB CPU > 80%" \
  --condition-threshold-value=0.8 \
  --condition-threshold-duration=300s \
  --condition-filter='resource.type="cloudsql_database" AND metric.type="cloudsql.googleapis.com/database/cpu/utilization"' \
  --project=financial-rise-prod
```

**Alert 5: Application Health Check Failure**
```bash
# This requires setting up Uptime Checks first
gcloud monitoring uptime-checks create \
  --display-name="Production API Health" \
  --resource-type=uptime-url \
  --http-check-path=/api/v1/health \
  --timeout=10s \
  --period=60s \
  --host=$PROD_IP \
  --project=financial-rise-prod
```

**5.4 Set Up Logging Sink**
```bash
# Create log sink for error-level logs
gcloud logging sinks create production-errors \
  gs://financial-rise-logs-production/errors \
  --log-filter='severity >= ERROR' \
  --project=financial-rise-prod
```

**Verification:**
```bash
# List all alert policies
gcloud alpha monitoring policies list --project=financial-rise-prod

# List notification channels
gcloud alpha monitoring channels list --project=financial-rise-prod
```

**Estimated Time:** 30 minutes

---

## Phase 6: Database Backup Strategy (Critical)

### Current State
- **Staging:** Automated daily backups at 3 AM (configured in Cloud SQL)
- **Production:** Need SAME + point-in-time recovery

### Production Requirement
**Automated backups + point-in-time recovery + backup retention policy**

### Implementation Steps

**6.1 Verify Backup Configuration**
```bash
# Check current backup configuration
gcloud sql instances describe financial-rise-production \
  --format="table(settings.backupConfiguration.enabled,settings.backupConfiguration.startTime,settings.backupConfiguration.pointInTimeRecoveryEnabled)"
```

**6.2 Update Backup Configuration (If Needed)**
```bash
gcloud sql instances patch financial-rise-production \
  --backup-start-time=03:00 \
  --retained-backups-count=30 \
  --retained-transaction-log-days=7 \
  --project=financial-rise-prod
```

**Key Settings:**
- `--backup-start-time=03:00`: Daily backup at 3 AM
- `--retained-backups-count=30`: Keep 30 daily backups
- `--retained-transaction-log-days=7`: 7 days point-in-time recovery

**6.3 Create Manual Backup (Before Deployment)**
```bash
gcloud sql backups create \
  --instance=financial-rise-production \
  --description="Pre-production deployment backup" \
  --project=financial-rise-prod
```

**6.4 Test Backup Restoration (IMPORTANT)**
```bash
# Create a test instance from backup
gcloud sql backups list \
  --instance=financial-rise-production \
  --project=financial-rise-prod

# Restore to test instance (NEVER overwrite production!)
gcloud sql backups restore BACKUP_ID \
  --backup-instance=financial-rise-production \
  --backup-id=BACKUP_ID \
  --instance=financial-rise-test-restore \
  --project=financial-rise-prod
```

**6.5 Create GCS Bucket for Export Backups**
```bash
# Create bucket for manual exports
gsutil mb -p financial-rise-prod \
  -c STANDARD \
  -l us-central1 \
  gs://financial-rise-db-exports/

# Set lifecycle policy (delete after 90 days)
cat > lifecycle.json << EOF
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

gsutil lifecycle set lifecycle.json gs://financial-rise-db-exports/
```

**6.6 Export Script for Off-Site Backup**
```bash
# Create backup export script on VM
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    cat > ~/backup-to-gcs.sh << 'SCRIPT'
#!/bin/bash
# Export Cloud SQL database to GCS

TIMESTAMP=\$(date +%Y%m%d-%H%M%S)
EXPORT_URI=\"gs://financial-rise-db-exports/production-\$TIMESTAMP.sql.gz\"

gcloud sql export sql financial-rise-production \$EXPORT_URI \
  --database=financial_rise_production \
  --project=financial-rise-prod

echo \"Backup exported to: \$EXPORT_URI\"
SCRIPT

    chmod +x ~/backup-to-gcs.sh
  " \
  --project=financial-rise-prod
```

**6.7 Schedule Weekly Export (Cron)**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="
    # Run export every Sunday at 4 AM
    (crontab -l 2>/dev/null; echo '0 4 * * 0 ~/backup-to-gcs.sh') | crontab -
  " \
  --project=financial-rise-prod
```

**6.8 Document Disaster Recovery Procedure**
```bash
cat > DISASTER-RECOVERY.md << 'EOF'
# Disaster Recovery Procedure

## Full Database Restore

### Option 1: From Automated Backup (Fastest)
\`\`\`bash
# 1. List available backups
gcloud sql backups list --instance=financial-rise-production

# 2. Restore from backup (DESTRUCTIVE)
gcloud sql backups restore BACKUP_ID \
  --instance=financial-rise-production
\`\`\`

### Option 2: Point-in-Time Recovery
\`\`\`bash
# Restore to specific timestamp (within 7 days)
gcloud sql instances clone financial-rise-production \
  financial-rise-production-clone \
  --point-in-time='2026-01-01T12:00:00.000Z'
\`\`\`

### Option 3: From GCS Export
\`\`\`bash
# 1. Find backup
gsutil ls gs://financial-rise-db-exports/

# 2. Import backup
gcloud sql import sql financial-rise-production \
  gs://financial-rise-db-exports/production-20260101-030000.sql.gz \
  --database=financial_rise_production
\`\`\`

## Recovery Time Objectives
- **RTO (Recovery Time Objective):** 1 hour
- **RPO (Recovery Point Objective):** 24 hours (daily backups)
- **Point-in-Time Recovery:** 7 days

## Testing Schedule
- Test restore: Monthly
- Full DR drill: Quarterly
EOF
```

**Verification:**
```bash
# Verify automated backups are running
gcloud sql backups list --instance=financial-rise-production --limit=5

# Verify GCS bucket
gsutil ls -L gs://financial-rise-db-exports/
```

**Estimated Time:** 20 minutes

---

## Phase 7: GitHub Secrets Configuration

### Production Deployment from GitHub Actions

**7.1 Create GitHub Environment**
```bash
# In GitHub repository settings:
# Settings → Environments → New environment: "production"
# Add protection rules:
#   ✅ Required reviewers (you)
#   ✅ Wait timer: 5 minutes
```

**7.2 Add GitHub Secrets**

Navigate to: `Settings → Secrets and variables → Actions`

Add these secrets:
```
GCP_PROJECT_ID=financial-rise-prod
GCP_WORKLOAD_IDENTITY_PROVIDER=projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github-pool/providers/github-provider
GCP_SERVICE_ACCOUNT=github-actions@financial-rise-prod.iam.gserviceaccount.com
PRODUCTION_VM_NAME=financial-rise-production-vm
PRODUCTION_VM_ZONE=us-central1-a
```

**7.3 Update Workflow File**

The existing `.github/workflows/deploy-gcp.yml` already has production deployment configured!

Just need to verify the secrets are set.

**Estimated Time:** 10 minutes

---

## Summary & Execution Checklist

### Execution Order (Recommended)

```
Phase 1: Cloud SQL Private IP        [15-20 min] ← START HERE
Phase 4: Production Secret Manager    [15 min]
Phase 2: Standard Production VM       [10 min]
Phase 6: Database Backup Strategy     [20 min]
Phase 5: Monitoring & Alerting        [30 min]
Phase 3: SSL/HTTPS Certificates       [30 min]    ← Domain needed
Phase 7: GitHub Secrets               [10 min]
```

**Total Estimated Time:** 2-3 hours

### Pre-Execution Checklist

- [ ] GCP billing enabled and linked to project
- [ ] Domain name purchased and DNS accessible (for SSL)
- [ ] SendGrid account created and API key ready
- [ ] Email address for monitoring alerts
- [ ] Backup of current staging database (precaution)

### Post-Execution Verification

```bash
# 1. Verify Cloud SQL
gcloud sql instances describe financial-rise-production --format="table(name,ipAddresses)"

# 2. Verify VM
gcloud compute instances list --filter="name:production"

# 3. Verify secrets
gcloud secrets versions list financial-rise-production-env

# 4. Verify monitoring
gcloud alpha monitoring policies list

# 5. Verify backups
gcloud sql backups list --instance=financial-rise-production

# 6. Test HTTPS
curl -k https://$PROD_IP/api/v1/health
```

### Cost Estimate

**Monthly Production Costs (Budget Optimized):**
- VM (e2-standard-2): ~$50/month
- Cloud SQL (db-g1-small ZONAL): ~$43/month
- Static IP: $7/month
- GCS Buckets: ~$3/month
- Monitoring: Free tier (< 150MB logs/month)
- **Total: ~$103/month** (under $118 budget ✅)

**Scaling Path:**
- Add High Availability (ZONAL → REGIONAL): +$43/month → $146/month total
- Upgrade VM (e2-standard-2 → e2-standard-4): +$50/month
- These can be added later as traffic grows

**One-Time Costs:**
- Domain name: ~$12/year
- SSL certificate: Free (Let's Encrypt)

---

## Critical Decision Points

### 1. Domain Name
**Question:** Do you have a domain name ready?
- **YES:** We'll use Let's Encrypt for real SSL certificates
- **NO:** We'll use self-signed certificates for testing (browser warning)

### 2. Email for Alerts
**Question:** What email should receive production alerts?

### 3. SendGrid API Key
**Question:** Do you have a SendGrid account set up?
- **YES:** Provide API key for production emails
- **NO:** We'll skip email functionality for MVP (can add later)

### 4. Deployment Approval
**Question:** Should we set up GitHub environment protection?
- **Recommended:** YES - require manual approval for production deploys

---

## Next Steps

**Ready to Execute:**
1. Confirm pre-execution checklist items
2. Answer decision points above
3. Run each phase in order
4. Verify after each phase
5. Document any issues encountered

**After Infrastructure Setup:**
1. Run production deployment from GitHub Actions
2. Test all functionality in production
3. Run security scan
4. Update DNS to point to production IP
5. Go live!

---

**Questions? Let me know which phase to start with!**
