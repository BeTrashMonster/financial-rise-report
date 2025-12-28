# Financial RISE - GCP Deployment Documentation

## 📚 Documentation Index

This directory contains complete documentation for deploying the Financial RISE application to Google Cloud Platform using GitHub Actions with Workload Identity Federation.

### Quick Start

**If you just want to get the CI/CD pipeline running:**
1. Read **[CICD-SETUP-SUMMARY.md](CICD-SETUP-SUMMARY.md)** - 5-minute overview
2. Follow the GitHub secrets setup (9 secrets)
3. Configure production environment protection
4. Push to main branch to trigger deployment

### Complete Documentation

| Document | Purpose | When to Use |
|----------|---------|-------------|
| **[CICD-SETUP-SUMMARY.md](CICD-SETUP-SUMMARY.md)** | Quick overview and setup steps | Start here - fastest path to deployment |
| **[GITHUB-SECRETS-REFERENCE.md](GITHUB-SECRETS-REFERENCE.md)** | Quick reference table of all secrets | Copy-paste secret values |
| **[GITHUB-ACTIONS-SETUP.md](GITHUB-ACTIONS-SETUP.md)** | Detailed setup guide with troubleshooting | Deep dive into Workload Identity Federation |
| **[DEPLOYMENT-CHECKLIST.md](DEPLOYMENT-CHECKLIST.md)** | Complete pre-deployment checklist | Ensure nothing is missed before going live |
| **[ARCHITECTURE-DIAGRAM.md](ARCHITECTURE-DIAGRAM.md)** | Visual architecture and data flows | Understand the system design |
| **[GCP-SETUP-QUICKSTART.md](GCP-SETUP-QUICKSTART.md)** | GCP infrastructure setup | Set up GCP resources |

### Original Planning Documents

| Document | Purpose |
|----------|---------|
| **[plans/requirements.md](plans/requirements.md)** | Complete requirements specification (2200+ lines) |
| **[plans/roadmap.md](plans/roadmap.md)** | Implementation roadmap with work streams |
| **[plans/priorities.md](plans/priorities.md)** | Business analysis and prioritization |
| **[CLAUDE.md](CLAUDE.md)** | Project overview and guidance |

---

## 🎯 Your Current Status

### ✅ Already Complete

- [x] GCP infrastructure created (VMs, databases, networking, storage)
- [x] Workload Identity Federation configured
- [x] Service accounts created with proper permissions
- [x] GitHub Actions workflow file created (`.github/workflows/deploy-gcp.yml`)
- [x] Workflow uses Workload Identity Federation (no service account keys)
- [x] Complete documentation written

### ⏳ Next Steps (Your Action Items)

- [ ] **Configure 9 GitHub Secrets** (5 minutes)
  - See: [GITHUB-SECRETS-REFERENCE.md](GITHUB-SECRETS-REFERENCE.md)
  - Use GitHub CLI or web UI

- [ ] **Set up Production Environment Protection** (2 minutes)
  - GitHub Settings → Environments → production → Required reviewers
  - Add team members who can approve deployments

- [ ] **Test the Pipeline** (10 minutes)
  - Push a commit to main branch
  - Monitor in GitHub Actions tab
  - Verify staging deployment
  - Approve production deployment
  - Verify production deployment

---

## 🚀 Quick Start Commands

### Configure All GitHub Secrets at Once

```bash
# Navigate to your repository
cd /path/to/financial-rise

# Install GitHub CLI if needed
# https://cli.github.com/

# Login
gh auth login

# Set all 9 secrets
gh secret set GCP_PROJECT_ID -b "financial-rise-prod"
gh secret set GCP_WORKLOAD_IDENTITY_PROVIDER -b "projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider"
gh secret set GCP_SERVICE_ACCOUNT -b "github-actions@financial-rise-prod.iam.gserviceaccount.com"
gh secret set GCP_REGION -b "us-central1"
gh secret set ARTIFACT_REGISTRY_REPO -b "financial-rise-docker"
gh secret set STAGING_VM_NAME -b "financial-rise-staging-vm"
gh secret set STAGING_VM_ZONE -b "us-central1-a"
gh secret set PRODUCTION_VM_NAME -b "financial-rise-production-vm"
gh secret set PRODUCTION_VM_ZONE -b "us-central1-a"

# Verify all secrets are set
gh secret list
```

### Trigger First Deployment

```bash
# Create an empty commit to trigger the workflow
git commit --allow-empty -m "Initial deployment test"
git push origin main

# Watch the workflow
# Go to: https://github.com/YOUR_ORG/YOUR_REPO/actions
```

---

## 📊 System Architecture Overview

```
GitHub Repository (Code)
        ↓
GitHub Actions (CI/CD)
        ↓
Workload Identity Federation (Auth - No Keys!)
        ↓
GCP Service Account
        ↓
┌───────────────┬───────────────┬────────────────┐
│               │               │                │
↓               ↓               ↓                ↓
Artifact     Compute       Cloud SQL      Cloud Storage
Registry     Engine VMs    PostgreSQL     (Reports + Backups)
(Docker)     (App Server)  (Database)
```

**Key Components:**
- **GitHub Actions**: Automated testing, building, and deployment
- **Workload Identity Federation**: Keyless authentication (no service account keys stored)
- **Artifact Registry**: Stores Docker images (backend + frontend)
- **Compute Engine**: Runs application (staging + production VMs)
- **Cloud SQL**: PostgreSQL databases (staging + production)
- **Cloud Storage**: PDF reports and database backups
- **Secret Manager**: Environment variables

---

## 🔒 Security Highlights

### Workload Identity Federation

**Traditional approach (less secure):**
```
Service Account Key → JSON file → GitHub Secret → Risk of exposure
```

**Our approach (secure):**
```
OIDC Token → Workload Identity → Temporary credentials → Auto-expire
```

**Benefits:**
- No long-lived credentials stored anywhere
- Credentials automatically expire after 1 hour
- GitHub repository validation before granting access
- Full audit trail in GCP Cloud Logging
- Complies with enterprise security policies

### Secrets Management

- Application secrets stored in GCP Secret Manager (not GitHub)
- Environment variables pulled at deployment time only
- Never stored on disk or in git
- Production and staging use different secrets
- Regular rotation recommended

---

## 🔄 CI/CD Pipeline Flow

### On Every Push to Main

```
1. Test Backend (lint + tests + coverage)
2. Test Frontend (lint + type-check + tests + build)
   ↓ (if tests pass)
3. Build Docker Images
4. Push to Artifact Registry
   ↓
5. Deploy to Staging
   - Copy deployment files
   - Pull environment variables
   - Run database migrations
   - Restart containers
   - Health check
   - Auto-rollback on failure
   ↓ (if staging succeeds)
6. ⏸️  WAIT FOR MANUAL APPROVAL
   ↓ (after approval)
7. Deploy to Production
   - Create database backup
   - Upload backup to Cloud Storage
   - Copy deployment files
   - Pull environment variables
   - Run database migrations
   - Rolling restart (zero-downtime)
   - Health check
   - Auto-rollback on failure
   ↓
8. ✅ Deployment Complete
```

### Manual Approval Required

Production deployments require manual approval from authorized team members. This prevents accidental production deployments and provides a review checkpoint.

**To configure:**
1. Go to repository Settings → Environments
2. Create `production` environment
3. Enable "Required reviewers"
4. Add team members

---

## 🧪 Testing the Setup

### Verification Checklist

After configuring secrets, verify:

```bash
# 1. Check all secrets are configured
gh secret list
# Should show 9 secrets

# 2. Trigger a test deployment
git commit --allow-empty -m "Test deployment"
git push origin main

# 3. Monitor the workflow
# Go to GitHub Actions tab

# 4. Verify images in Artifact Registry
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker

# 5. Check staging deployment
STAGING_IP=$(gcloud compute addresses describe financial-rise-staging-ip \
  --region=us-central1 --format='get(address)')
curl http://$STAGING_IP/api/v1/health

# 6. Approve production deployment in GitHub UI

# 7. Check production deployment
PROD_IP=$(gcloud compute addresses describe financial-rise-production-ip \
  --region=us-central1 --format='get(address)')
curl http://$PROD_IP/api/v1/health
```

---

## 🆘 Troubleshooting

### Common Issues

#### "Could not authenticate with Workload Identity Federation"

**Solution:** Verify the `GCP_WORKLOAD_IDENTITY_PROVIDER` secret exactly matches:
```
projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
```

Check Workload Identity setup:
```bash
gcloud iam workload-identity-pools providers describe github-provider \
  --location=global \
  --workload-identity-pool=github-actions-pool \
  --project=financial-rise-prod
```

#### "Permission denied" errors

**Solution:** Verify service account has required roles:
```bash
gcloud projects get-iam-policy financial-rise-prod \
  --flatten="bindings[].members" \
  --filter="bindings.members:github-actions@financial-rise-prod.iam.gserviceaccount.com"
```

#### Health check fails

**Debug:**
```bash
# SSH to VM
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a

# Check container logs
cd /opt/financial-rise
docker compose logs backend
docker compose logs frontend

# Test locally on VM
curl http://localhost:4000/api/v1/health
```

### Getting Help

1. Check the detailed troubleshooting section in [GITHUB-ACTIONS-SETUP.md](GITHUB-ACTIONS-SETUP.md)
2. Review workflow logs in GitHub Actions tab
3. Check GCP Cloud Logging for authentication issues
4. Verify all secrets are spelled correctly (case-sensitive)

---

## 📈 Monitoring & Maintenance

### Monitoring

After deployment, monitor:
- **GitHub Actions**: Check workflow runs for failures
- **GCP Cloud Monitoring**: CPU, memory, disk usage
- **Application logs**: Errors and warnings
- **Health endpoints**: Uptime and response times

### Maintenance Tasks

**Weekly:**
- Review deployment logs
- Check error rates in monitoring
- Verify backups are running

**Monthly:**
- Review and rotate secrets
- Check for OS/dependency updates
- Review access controls and permissions

**Quarterly:**
- Test disaster recovery procedures
- Review and update documentation
- Audit security configurations

---

## 📞 Support Resources

### Documentation

- **GitHub Actions**: https://docs.github.com/en/actions
- **Workload Identity Federation**: https://cloud.google.com/iam/docs/workload-identity-federation
- **GCP Compute Engine**: https://cloud.google.com/compute/docs
- **Cloud SQL**: https://cloud.google.com/sql/docs

### Internal Docs

- Architecture diagrams: [ARCHITECTURE-DIAGRAM.md](ARCHITECTURE-DIAGRAM.md)
- Full checklist: [DEPLOYMENT-CHECKLIST.md](DEPLOYMENT-CHECKLIST.md)
- Detailed setup: [GITHUB-ACTIONS-SETUP.md](GITHUB-ACTIONS-SETUP.md)

---

## 🎉 Success Criteria

You'll know the setup is complete when:

- ✅ All 9 GitHub secrets configured
- ✅ Production environment requires manual approval
- ✅ Workflow runs successfully on push to main
- ✅ Backend and frontend tests pass
- ✅ Docker images build and push to Artifact Registry
- ✅ Staging deploys automatically and health check passes
- ✅ Production deploys after approval and health check passes
- ✅ Application is accessible at staging and production IPs

---

## 🚀 What's Next

After successful deployment:

1. **Configure DNS**
   - Point your domain to the static IPs
   - Set up SSL/TLS certificates (Let's Encrypt recommended)

2. **Set up monitoring alerts**
   - Configure Cloud Monitoring alert policies
   - Set up notification channels (email, Slack, PagerDuty)

3. **Test rollback procedures**
   - Verify automatic rollback works
   - Practice manual rollback
   - Document rollback runbook

4. **Plan for high availability**
   - Consider multi-zone deployment
   - Set up load balancing
   - Configure autoscaling

5. **Security hardening**
   - Review and minimize firewall rules
   - Restrict SSH access to specific IPs
   - Set up VPN for administrative access
   - Enable audit logging

---

**Ready to deploy?** Start with **[CICD-SETUP-SUMMARY.md](CICD-SETUP-SUMMARY.md)** for a 5-minute overview and setup guide.

**Questions?** Check **[GITHUB-ACTIONS-SETUP.md](GITHUB-ACTIONS-SETUP.md)** for detailed troubleshooting and FAQs.

**Need the big picture?** See **[ARCHITECTURE-DIAGRAM.md](ARCHITECTURE-DIAGRAM.md)** for visual system architecture.

---

**Document Version:** 1.0
**Last Updated:** 2025-12-27
**Status:** Ready for deployment
