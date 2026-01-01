# Production Infrastructure Setup Scripts

**Last Updated:** 2026-01-01
**Status:** Ready for execution
**Estimated Total Time:** 2-3 hours
**Monthly Cost:** ~$103 (budget optimized)

---

## Overview

This directory contains automated scripts to set up the complete production infrastructure for Financial RISE on Google Cloud Platform (GCP).

### What Gets Created

- **Cloud SQL:** PostgreSQL 14 with Private IP, High Availability, automated backups
- **Compute VM:** Standard e2-standard-2 (non-preemptible), 50GB SSD, Docker installed
- **Secret Manager:** Production secrets securely stored and accessible to VM
- **Monitoring:** Cloud Monitoring with alerts for CPU, disk, and database metrics
- **Backups:** Automated daily backups + weekly off-site exports to GCS
- **SSL/HTTPS:** Optional Let's Encrypt or self-signed certificates
- **GitHub CI/CD:** Secrets configured for automated deployments

---

## Quick Start

### Prerequisites

1. **GCP Project:** `financial-rise-prod` created and billing enabled
2. **gcloud CLI:** Installed and authenticated (`gcloud auth login`)
3. **Permissions:** Owner or Editor role on the project
4. **Time:** 2-3 hours for full setup
5. **Domain (optional):** For SSL/HTTPS with Let's Encrypt

### Option 1: Run All Phases Automatically (Recommended)

```bash
# Make scripts executable
chmod +x setup-production-*.sh

# Run master script
./setup-production-all-phases.sh
```

This will execute all 7 phases in order with interactive prompts.

### Option 2: Run Phases Individually

```bash
# Phase 1: Cloud SQL with Private IP (15-20 min)
./setup-production-phase1-cloudsql.sh

# Phase 2: Standard Production VM (10 min)
./setup-production-phase2-vm.sh

# Phase 4: Production Secret Manager (15 min)
./setup-production-phase4-secrets.sh

# Phase 5: Monitoring & Alerting (30 min)
./setup-production-phase5-monitoring.sh

# Phase 6: Database Backup Strategy (20 min)
./setup-production-phase6-backups.sh

# Phase 7: GitHub Secrets Configuration (10 min)
./setup-production-phase7-github.sh

# Phase 3: SSL/HTTPS (Optional - 30 min)
./setup-production-phase3-ssl.sh
```

---

## Script Details

### Phase 1: Cloud SQL with Private IP

**File:** `setup-production-phase1-cloudsql.sh`
**Time:** 15-20 minutes
**Prerequisites:** GCP project exists

**What it does:**
- Enables Service Networking API
- Creates VPC peering for private database access
- Creates Cloud SQL PostgreSQL 14 instance with:
  - Private IP only (no public IP)
  - High availability (REGIONAL)
  - Automated daily backups at 3 AM
  - Point-in-time recovery (7 days)
  - 20GB SSD storage (auto-increase enabled)
- Creates production database: `financial_rise_production`
- Creates database user: `financial_rise` with secure password
- Saves credentials to `/tmp/prod-db-password.txt`

**Cost:** ~$86/month

---

### Phase 2: Standard Production VM

**File:** `setup-production-phase2-vm.sh`
**Time:** 10 minutes
**Prerequisites:** Phase 1 complete

**What it does:**
- Reserves static IP address
- Creates standard e2-standard-2 VM:
  - 2 vCPU, 8GB RAM
  - 50GB SSD disk
  - Non-preemptible (reliable uptime)
  - Connected to VPC (can access Cloud SQL via private IP)
- Installs Docker and Docker Compose
- Configures Docker permissions
- Saves VM IP to `/tmp/prod-vm-ip.txt`

**Cost:** ~$50/month

---

### Phase 3: SSL/HTTPS Certificates (Optional)

**File:** `setup-production-phase3-ssl.sh`
**Time:** 30 minutes
**Prerequisites:** Phase 2 complete, domain name configured

**What it does:**
- Installs Certbot on VM
- Options:
  1. **Let's Encrypt** (requires domain): Real SSL certificate
  2. **Self-signed:** For testing (browser warning)
  3. **Skip:** Set up later
- Updates nginx configuration for HTTPS
- Configures HTTP → HTTPS redirect
- Sets up SSL security headers
- Auto-renewal (Let's Encrypt only)

**Interactive prompts:**
- Domain name (if using Let's Encrypt)
- Email for certificate notifications
- DNS confirmation

**Note:** Requires nginx config changes to be committed and redeployed

---

### Phase 4: Production Secret Manager

**File:** `setup-production-phase4-secrets.sh`
**Time:** 15 minutes
**Prerequisites:** Phase 1 and 2 complete

**What it does:**
- Loads credentials from Phase 1 and 2
- Generates production secrets:
  - JWT_SECRET (64 bytes base64)
  - JWT_REFRESH_SECRET (64 bytes base64)
  - DB_ENCRYPTION_KEY (64 hex characters)
  - REDIS_PASSWORD (32 bytes base64)
- Creates production `.env` file with all configuration
- Stores in Secret Manager: `financial-rise-production-env`
- Grants VM access to secrets
- Creates GCS bucket: `financial-rise-reports-production`
- Securely deletes temporary files

**Interactive prompts:**
- SendGrid API key (optional - press ENTER to skip)
- Domain name (optional - uses VM IP if skipped)

**Cost:** Free (Secret Manager within free tier)

---

### Phase 5: Monitoring & Alerting

**File:** `setup-production-phase5-monitoring.sh`
**Time:** 30 minutes
**Prerequisites:** Phase 1, 2, and 4 complete

**What it does:**
- Enables Cloud Monitoring API
- Creates email notification channel
- Creates alert policies for:
  - VM High CPU (>80% for 5 minutes)
  - VM High Disk Usage (>85% for 5 minutes)
  - Cloud SQL High CPU (>80% for 5 minutes)
- Creates uptime check for API health endpoint
- Creates log sink for ERROR-level logs
- Creates GCS bucket: `financial-rise-logs-production`

**Interactive prompts:**
- Email address for alerts

**Cost:** Free (within free tier for <150MB logs/month)

---

### Phase 6: Database Backup Strategy

**File:** `setup-production-phase6-backups.sh`
**Time:** 20 minutes
**Prerequisites:** Phase 1 complete

**What it does:**
- Configures automated daily backups:
  - Daily at 3:00 AM UTC
  - Retain 30 backups
  - Point-in-time recovery: 7 days
- Creates pre-production manual backup
- Creates GCS bucket for exports: `financial-rise-db-exports`
- Sets lifecycle policy (delete after 90 days)
- Installs backup export script on VM
- Schedules weekly exports (Sunday 4 AM)
- Creates disaster recovery documentation

**Deliverables:**
- `~/backup-to-gcs.sh` script on VM
- `DISASTER-RECOVERY.md` documentation
- Automated backup schedule

**Cost:** ~$3/month (GCS storage)

---

### Phase 7: GitHub Secrets Configuration

**File:** `setup-production-phase7-github.sh`
**Time:** 10 minutes
**Prerequisites:** All previous phases complete

**What it does:**
- Retrieves GCP project information
- Generates list of GitHub secrets to add
- Saves secrets to `/tmp/github-secrets.txt`
- Verifies Workload Identity Pool exists
- Verifies GitHub Actions service account
- Provides manual instructions for:
  - Adding secrets to GitHub
  - Creating production environment
  - Configuring deployment approvals

**Manual steps required:**
- Add 5 secrets to GitHub repository
- Create production environment with required reviewers

**Cost:** Free

---

### Master Script: All Phases

**File:** `setup-production-all-phases.sh`
**Time:** 2-3 hours total
**Prerequisites:** GCP project, gcloud CLI

**What it does:**
- Executes all phases in recommended order
- Creates log directory: `/tmp/production-setup-logs/`
- Logs each phase to separate file
- Optionally includes SSL setup
- Displays comprehensive summary
- Saves all logs for troubleshooting

**Execution order:**
1. Phase 1: Cloud SQL
2. Phase 2: VM
3. Phase 4: Secrets
4. Phase 5: Monitoring
5. Phase 6: Backups
6. Phase 7: GitHub
7. Phase 3: SSL (optional)

---

## After Setup: Manual Steps

### 1. Configure GitHub Secrets

```bash
# View the secrets to add
cat /tmp/github-secrets.txt
```

Go to GitHub repository:
1. Settings → Secrets and variables → Actions
2. Add 5 secrets listed in the file

### 2. Create GitHub Production Environment

1. Settings → Environments
2. New environment: `production`
3. Add protection rules:
   - ☑️ Required reviewers (your username)
   - ☑️ Wait timer: 5 minutes (optional)

### 3. Deploy to Production

```bash
# Commit any changes
git add .
git commit -m "Configure production infrastructure"

# Push to trigger deployment
git push origin main
```

### 4. Approve Deployment

1. Go to GitHub Actions
2. Wait for production deployment to request approval
3. Review changes and approve
4. Monitor deployment progress

### 5. Verify Production

```bash
# Get production IP
PROD_IP=$(cat /tmp/prod-vm-ip.txt)

# Test health endpoint
curl http://$PROD_IP/api/v1/health

# Expected: {"status":"ok","timestamp":"...","service":"financial-rise-api"}

# Test frontend
curl -I http://$PROD_IP/
# Expected: HTTP/1.1 200 OK
```

### 6. Monitor Production

- **Logs:** https://console.cloud.google.com/logs
- **Monitoring:** https://console.cloud.google.com/monitoring
- **Alerts:** Check email for monitoring notifications
- **Backups:** https://console.cloud.google.com/sql/instances

---

## Cost Breakdown

### Monthly Costs (Budget Optimized)

| Service | Tier | Monthly Cost |
|---------|------|--------------|
| Cloud SQL (PostgreSQL 14 ZONAL) | db-g1-small | ~$43 |
| Compute Engine VM | e2-standard-2 | ~$50 |
| Static IP | Standard | $7 |
| GCS Buckets | STANDARD | ~$3 |
| Monitoring & Logging | Free tier | $0 |
| Secret Manager | Free tier | $0 |
| **Total** | | **~$103/month** |

**Under $118 budget ✅**

### One-Time Costs

- Domain name: ~$12/year (optional)
- SSL certificate: Free (Let's Encrypt)

### Scaling Up When Needed

**Current Setup:** ZONAL database (single zone, no automatic failover)

**When to upgrade to High Availability:**
- Traffic grows beyond 100 concurrent users
- Downtime becomes costly
- Need 99.95% uptime SLA

**How to upgrade:**
```bash
# Upgrade to REGIONAL (High Availability)
gcloud sql instances patch financial-rise-production \
  --availability-type=REGIONAL \
  --project=financial-rise-prod

# Cost increase: +$43/month → $146/month total
```

**Other scaling options:**
- Upgrade VM: `e2-standard-4` (+$50/month) for more traffic
- Read replicas: Add for read-heavy workloads (+$43/month per replica)
- Connection pooling: Use PgBouncer before upgrading database

### Cost Optimization Tips

1. **Current setup:** Already optimized for budget ($103/month)
2. **Staging environment:** Use smaller instances (e2-micro, db-f1-micro)
3. **Development:** Use preemptible VMs, Cloud SQL with public IP
4. **Backups:** Keep 30 days (included in cost)
5. **Monitoring:** Stay within free tier (<150MB logs/month)

---

## Troubleshooting

### Common Issues

**Issue:** `gcloud: command not found`
```bash
# Install gcloud CLI
# macOS: brew install google-cloud-sdk
# Linux: https://cloud.google.com/sdk/docs/install
```

**Issue:** Permission denied errors
```bash
# Verify you're authenticated
gcloud auth login

# Verify project is set
gcloud config set project financial-rise-prod

# Verify you have necessary roles
gcloud projects get-iam-policy financial-rise-prod \
  --flatten="bindings[].members" \
  --filter="bindings.members:user:YOUR_EMAIL"
```

**Issue:** Cloud SQL creation fails
```bash
# Check quotas
gcloud compute project-info describe --project=financial-rise-prod

# Verify VPC exists
gcloud compute networks list --project=financial-rise-prod
```

**Issue:** VM can't connect to Cloud SQL
```bash
# Verify private IP is configured
gcloud sql instances describe financial-rise-production \
  --format="value(ipAddresses[0].ipAddress,ipAddresses[0].type)"

# Should show: 10.x.x.x PRIVATE
```

**Issue:** Secrets not accessible from VM
```bash
# Check IAM binding
gcloud secrets get-iam-policy financial-rise-production-env

# Should show VM service account with secretAccessor role
```

### Logs

All setup logs are saved to `/tmp/production-setup-logs/`:
- `master-TIMESTAMP.log` - Full execution log
- `phase1-TIMESTAMP.log` - Cloud SQL setup
- `phase2-TIMESTAMP.log` - VM setup
- etc.

```bash
# View latest master log
ls -t /tmp/production-setup-logs/master-* | head -1 | xargs cat

# View specific phase
cat /tmp/production-setup-logs/phase1-*.log
```

---

## Security Best Practices

### Implemented

✅ Cloud SQL with Private IP only
✅ Secrets in Secret Manager (not in code)
✅ Strong passwords (32+ bytes, base64)
✅ Encryption key (64 hex characters)
✅ VM with minimal attack surface
✅ Monitoring and alerting enabled
✅ Automated backups with retention
✅ SSL/HTTPS available

### Recommended (Post-Setup)

- [ ] Enable Cloud Armor for DDoS protection
- [ ] Set up VPN for database access (instead of authorized networks)
- [ ] Enable Cloud IAP for VM SSH access
- [ ] Set up binary authorization for container images
- [ ] Enable vulnerability scanning for Docker images
- [ ] Implement log-based metrics for security events
- [ ] Set up Cloud KMS for encryption keys

---

## Rollback Procedures

### If Setup Fails Mid-Way

Each phase is idempotent where possible. Safe to re-run.

**Phase 1 (Cloud SQL):**
```bash
# Delete instance and start over
gcloud sql instances delete financial-rise-production --project=financial-rise-prod
./setup-production-phase1-cloudsql.sh
```

**Phase 2 (VM):**
```bash
# Delete VM and IP
gcloud compute instances delete financial-rise-production-vm --zone=us-central1-a
gcloud compute addresses delete financial-rise-production-ip --region=us-central1
./setup-production-phase2-vm.sh
```

**Phases 4-7:**
These update configurations and can be re-run safely.

### Complete Teardown

```bash
# WARNING: This deletes ALL production infrastructure

# Delete VM
gcloud compute instances delete financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod

# Delete static IP
gcloud compute addresses delete financial-rise-production-ip \
  --region=us-central1 \
  --project=financial-rise-prod

# Delete Cloud SQL instance
gcloud sql instances delete financial-rise-production \
  --project=financial-rise-prod

# Delete secrets
gcloud secrets delete financial-rise-production-env \
  --project=financial-rise-prod

# Delete GCS buckets
gsutil -m rm -r gs://financial-rise-reports-production
gsutil -m rm -r gs://financial-rise-db-exports
gsutil -m rm -r gs://financial-rise-logs-production
```

---

## Next Steps After Production Setup

1. **Test Deployment**
   - Verify health endpoint
   - Test authentication flow
   - Run E2E tests against production

2. **Configure Domain (if not done)**
   - Update DNS A record
   - Run Phase 3 (SSL)
   - Update FRONTEND_URL in secrets

3. **Set Up Monitoring Dashboard**
   - Create custom dashboard
   - Add key metrics
   - Configure SLOs

4. **Document Runbooks**
   - Deployment procedures
   - Incident response
   - Scaling procedures

5. **Load Testing**
   - Test with expected traffic
   - Identify bottlenecks
   - Adjust resources if needed

6. **Go Live!**
   - Announce to users
   - Monitor closely
   - Be ready for issues

---

## Support

- **GCP Documentation:** https://cloud.google.com/docs
- **GCP Support:** https://console.cloud.google.com/support
- **Project Issues:** https://github.com/YOUR_REPO/issues
- **Internal Docs:** See `docs/` directory

---

**Good luck with your production deployment! 🚀**
