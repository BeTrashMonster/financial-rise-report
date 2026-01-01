# Production Infrastructure - Quick Start Guide

**Status:** ✅ Ready for Execution
**Date:** 2026-01-01
**Total Time:** 2-3 hours
**Cost:** ~$103/month (budget optimized, scalable to $146 with HA)

---

## TL;DR - Get Production Running in 3 Steps

### Step 1: Run Setup Scripts (2-3 hours)

```bash
# Option A: Run everything automatically
./setup-production-all-phases.sh

# Option B: Run phase by phase
./setup-production-phase1-cloudsql.sh    # 15-20 min
./setup-production-phase2-vm.sh          # 10 min
./setup-production-phase4-secrets.sh     # 15 min
./setup-production-phase5-monitoring.sh  # 30 min
./setup-production-phase6-backups.sh     # 20 min
./setup-production-phase7-github.sh      # 10 min
# Optional: ./setup-production-phase3-ssl.sh  # 30 min (requires domain)
```

### Step 2: Configure GitHub (5 minutes)

```bash
# View the secrets to add
cat /tmp/github-secrets.txt
```

1. Go to: `GitHub → Settings → Secrets and variables → Actions`
2. Add the 5 secrets shown in the file
3. Go to: `Settings → Environments`
4. Create environment: `production`
5. Add required reviewers

### Step 3: Deploy (5 minutes + approval)

```bash
# Push code to trigger deployment
git push origin main
```

1. Go to GitHub Actions
2. Approve production deployment
3. Wait for completion
4. Verify: `curl http://YOUR_IP/api/v1/health`

---

## What Gets Created

| Resource | Type | Details |
|----------|------|---------|
| **Cloud SQL** | PostgreSQL 14 | Private IP, ZONAL, daily backups |
| **Compute VM** | e2-standard-2 | Standard (non-preemptible), 50GB |
| **Static IP** | External | Reserved for production |
| **Secrets** | Secret Manager | All credentials securely stored |
| **Monitoring** | Cloud Monitoring | CPU, disk, DB alerts |
| **Backups** | Automated | Daily + weekly off-site |
| **SSL** | Optional | Let's Encrypt or self-signed |

**Budget:** ~$103/month (scalable to HA for +$43/month)

---

## After Deployment

### Verify Production is Working

```bash
# Get production IP
PROD_IP=$(cat /tmp/prod-vm-ip.txt)

# Health check
curl http://$PROD_IP/api/v1/health
# Expected: {"status":"ok","timestamp":"...","service":"financial-rise-api"}

# Frontend
curl -I http://$PROD_IP/
# Expected: HTTP/1.1 200 OK
```

### Access Monitoring

- **Logs:** https://console.cloud.google.com/logs
- **Metrics:** https://console.cloud.google.com/monitoring
- **SQL:** https://console.cloud.google.com/sql

### SSH to Production VM

```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod
```

---

## Emergency Contacts

- **Primary:** [Your Email]
- **GCP Support:** https://console.cloud.google.com/support
- **Monitoring Email:** Configured during Phase 5
- **Logs:** `/tmp/production-setup-logs/`

---

## Disaster Recovery

See `DISASTER-RECOVERY.md` for full procedures.

**Quick recovery from backup:**
```bash
# List backups
gcloud sql backups list --instance=financial-rise-production

# Restore (DESTRUCTIVE)
gcloud sql backups restore BACKUP_ID \
  --instance=financial-rise-production
```

**RTO:** 1 hour | **RPO:** 24 hours

---

## Cost Monitoring

**Monthly budget:** ~$103/month (under approved $118 budget)

Set up billing alerts:
```bash
gcloud billing budgets create \
  --billing-account=BILLING_ACCOUNT_ID \
  --display-name="Production Budget Alert" \
  --budget-amount=118 \
  --threshold-rule=percent=80 \
  --threshold-rule=percent=100
```

**Scaling costs:**
- Add High Availability: +$43/month → $146/month total
- Upgrade VM to e2-standard-4: +$50/month

---

## Troubleshooting

**Problem:** Scripts fail with permission errors
```bash
# Re-authenticate
gcloud auth login
gcloud config set project financial-rise-prod
```

**Problem:** VM can't connect to database
```bash
# Check Cloud SQL has private IP
gcloud sql instances describe financial-rise-production \
  --format="value(ipAddresses[0].type)"
# Should show: PRIVATE
```

**Problem:** Deployment fails
```bash
# Check GitHub secrets are configured
# Check VM has Docker running
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --command="docker ps"
```

---

## Next Steps

1. ✅ Run setup scripts
2. ✅ Configure GitHub
3. ✅ Deploy to production
4. ✅ Verify health checks
5. ⏭️ Set up domain and SSL (if not done)
6. ⏭️ Load testing
7. ⏭️ Go live!

---

**For detailed documentation, see:** `PRODUCTION-SETUP-README.md`
