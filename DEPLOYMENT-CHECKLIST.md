# Financial RISE - Deployment Checklist

## Pre-Deployment Setup

Use this checklist to ensure all infrastructure and CI/CD components are properly configured before deploying the Financial RISE application.

---

## ✅ Infrastructure Setup (GCP)

- [ ] **GCP Project Created**
  - Project ID: `financial-rise-prod`
  - Billing enabled
  - Location: Run `gcloud config get-value project`

- [ ] **APIs Enabled**
  - [ ] Compute Engine API
  - [ ] Cloud SQL Admin API
  - [ ] Artifact Registry API
  - [ ] Cloud Storage API
  - [ ] Secret Manager API
  - [ ] IAM Credentials API
  - [ ] Service Usage API
  - Verify: `gcloud services list --enabled --project=financial-rise-prod`

- [ ] **VPC Network Created**
  - [ ] Network: `financial-rise-vpc`
  - [ ] Subnet: `financial-rise-subnet` (10.0.0.0/24)
  - [ ] Firewall rules configured (SSH, HTTP, HTTPS, app ports)
  - Verify: `gcloud compute networks list --project=financial-rise-prod`

- [ ] **Cloud SQL Databases**
  - [ ] PostgreSQL 14 instances created
  - [ ] Staging database: `financial-rise-staging`
  - [ ] Production database: `financial-rise-production`
  - [ ] Private IP enabled
  - [ ] Automatic backups configured
  - Verify: `gcloud sql instances list --project=financial-rise-prod`

- [ ] **Artifact Registry**
  - [ ] Repository created: `financial-rise-docker`
  - [ ] Format: Docker
  - [ ] Location: `us-central1`
  - Verify: `gcloud artifacts repositories list --project=financial-rise-prod`

- [ ] **Cloud Storage Buckets**
  - [ ] Reports bucket: `financial-rise-reports`
  - [ ] Backups bucket: `financial-rise-backups`
  - [ ] Appropriate lifecycle policies configured
  - Verify: `gcloud storage buckets list --project=financial-rise-prod`

- [ ] **Compute Engine VMs**
  - [ ] Staging VM: `financial-rise-staging-vm` (e2-medium, us-central1-a)
  - [ ] Production VM: `financial-rise-production-vm` (e2-standard-2, us-central1-a)
  - [ ] Docker installed on both VMs
  - [ ] Static external IPs assigned
  - Verify: `gcloud compute instances list --project=financial-rise-prod`

- [ ] **Service Accounts**
  - [ ] `github-actions@financial-rise-prod.iam.gserviceaccount.com` created
  - [ ] Required roles assigned:
    - [ ] `roles/artifactregistry.writer`
    - [ ] `roles/compute.admin`
    - [ ] `roles/storage.admin`
    - [ ] `roles/secretmanager.secretAccessor`
    - [ ] `roles/cloudsql.client`
  - Verify: `gcloud iam service-accounts list --project=financial-rise-prod`

- [ ] **Workload Identity Federation**
  - [ ] Workload Identity Pool: `github-actions-pool`
  - [ ] Provider: `github-provider`
  - [ ] Service account binding configured
  - Verify: `gcloud iam workload-identity-pools list --location=global --project=financial-rise-prod`

- [ ] **Secret Manager**
  - [ ] `financial-rise-staging-env` secret created
  - [ ] `financial-rise-production-env` secret created
  - [ ] Secrets contain all required environment variables
  - Verify: `gcloud secrets list --project=financial-rise-prod`

---

## ✅ GitHub Repository Setup

- [ ] **Repository Access**
  - [ ] Repository created and accessible
  - [ ] Admin permissions configured
  - [ ] Branch protection rules set for `main`

- [ ] **GitHub Secrets Configured** (See: `GITHUB-SECRETS-REFERENCE.md`)
  - [ ] `GCP_PROJECT_ID` = `financial-rise-prod`
  - [ ] `GCP_WORKLOAD_IDENTITY_PROVIDER` = `projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider`
  - [ ] `GCP_SERVICE_ACCOUNT` = `github-actions@financial-rise-prod.iam.gserviceaccount.com`
  - [ ] `GCP_REGION` = `us-central1`
  - [ ] `ARTIFACT_REGISTRY_REPO` = `financial-rise-docker`
  - [ ] `STAGING_VM_NAME` = `financial-rise-staging-vm`
  - [ ] `STAGING_VM_ZONE` = `us-central1-a`
  - [ ] `PRODUCTION_VM_NAME` = `financial-rise-production-vm`
  - [ ] `PRODUCTION_VM_ZONE` = `us-central1-a`
  - Verify: `gh secret list` (should show 9 secrets)

- [ ] **GitHub Environments**
  - [ ] `staging` environment created
  - [ ] `production` environment created
  - [ ] Production environment requires manual approval
  - [ ] Reviewers assigned for production deployments
  - Verify: Navigate to Settings → Environments in GitHub

- [ ] **Workflow Files Present**
  - [ ] `.github/workflows/deploy-gcp.yml` exists
  - [ ] Workflow uses Workload Identity Federation (not service account keys)
  - [ ] Backend and frontend paths correct

---

## ✅ Application Code

- [ ] **Repository Structure**
  - [ ] `financial-rise-app/backend/` exists with Dockerfile
  - [ ] `financial-rise-app/frontend/` exists with Dockerfile
  - [ ] `financial-rise-app/docker-compose.yml` exists
  - [ ] `financial-rise-app/docker-compose.prod.yml` exists

- [ ] **Backend Configuration**
  - [ ] `package.json` with required scripts (start, test, lint, migration:run)
  - [ ] Database migrations ready
  - [ ] Environment variable validation implemented
  - [ ] Health check endpoint implemented (`/api/v1/health`)

- [ ] **Frontend Configuration**
  - [ ] `package.json` with required scripts (start, build, test, lint)
  - [ ] Environment variables configured for API URL
  - [ ] Production build optimized

- [ ] **Docker Images**
  - [ ] Backend Dockerfile has `development` and `production` targets
  - [ ] Frontend Dockerfile has `development` and `production` targets
  - [ ] Multi-stage builds configured for optimization

---

## ✅ VM Preparation

### Staging VM

- [ ] **SSH Access Configured**
  ```bash
  gcloud compute ssh financial-rise-staging-vm \
    --zone=us-central1-a \
    --project=financial-rise-prod
  ```

- [ ] **Docker Installed**
  ```bash
  docker --version
  docker compose version
  ```

- [ ] **Application Directory Created**
  ```bash
  sudo mkdir -p /opt/financial-rise
  sudo chown $(whoami):$(whoami) /opt/financial-rise
  ```

- [ ] **Artifact Registry Authentication**
  ```bash
  gcloud auth configure-docker us-central1-docker.pkg.dev
  ```

- [ ] **Cloud SQL Proxy Configured** (if using Cloud SQL)
  - Or database connection verified

### Production VM

- [ ] **SSH Access Configured**
  ```bash
  gcloud compute ssh financial-rise-production-vm \
    --zone=us-central1-a \
    --project=financial-rise-prod
  ```

- [ ] **Docker Installed**
  ```bash
  docker --version
  docker compose version
  ```

- [ ] **Application Directory Created**
  ```bash
  sudo mkdir -p /opt/financial-rise
  sudo chown $(whoami):$(whoami) /opt/financial-rise
  ```

- [ ] **Artifact Registry Authentication**
  ```bash
  gcloud auth configure-docker us-central1-docker.pkg.dev
  ```

- [ ] **Cloud SQL Proxy Configured** (if using Cloud SQL)
  - Or database connection verified

- [ ] **Monitoring Configured** (optional but recommended)
  - Cloud Monitoring agent installed
  - Logging agent installed

---

## ✅ Environment Variables

### Staging Environment

- [ ] **Secret Manager Secret Created**: `financial-rise-staging-env`
- [ ] **Required Variables Set**:
  - [ ] `NODE_ENV=staging`
  - [ ] `DATABASE_HOST` (Cloud SQL private IP or connection name)
  - [ ] `DATABASE_PORT=5432`
  - [ ] `DATABASE_USER`
  - [ ] `DATABASE_PASSWORD`
  - [ ] `DATABASE_NAME=financial_rise_staging`
  - [ ] `JWT_SECRET` (strong random value)
  - [ ] `JWT_REFRESH_SECRET` (strong random value)
  - [ ] `GCS_BUCKET=financial-rise-reports`
  - [ ] `GCP_PROJECT_ID=financial-rise-prod`
  - [ ] Any other app-specific variables

### Production Environment

- [ ] **Secret Manager Secret Created**: `financial-rise-production-env`
- [ ] **Required Variables Set**:
  - [ ] `NODE_ENV=production`
  - [ ] `DATABASE_HOST` (Cloud SQL private IP or connection name)
  - [ ] `DATABASE_PORT=5432`
  - [ ] `DATABASE_USER`
  - [ ] `DATABASE_PASSWORD`
  - [ ] `DATABASE_NAME=financial_rise_production`
  - [ ] `JWT_SECRET` (DIFFERENT from staging)
  - [ ] `JWT_REFRESH_SECRET` (DIFFERENT from staging)
  - [ ] `GCS_BUCKET=financial-rise-reports`
  - [ ] `GCP_PROJECT_ID=financial-rise-prod`
  - [ ] Any other app-specific variables

**Update secrets:**
```bash
# Create .env file locally
nano staging.env

# Upload to Secret Manager
gcloud secrets versions add financial-rise-staging-env \
  --data-file=staging.env \
  --project=financial-rise-prod

# Verify
gcloud secrets versions access latest \
  --secret=financial-rise-staging-env \
  --project=financial-rise-prod
```

---

## ✅ Database Setup

### Staging Database

- [ ] **Database Created**
  - Database name: `financial_rise_staging`
  - User created with appropriate permissions

- [ ] **Connection Verified**
  ```bash
  # From staging VM
  psql -h CLOUD_SQL_IP -U DB_USER -d financial_rise_staging
  ```

- [ ] **Initial Migration Ready**
  - Migration scripts exist in backend code
  - Migration can be run via `npm run migration:run`

### Production Database

- [ ] **Database Created**
  - Database name: `financial_rise_production`
  - User created with appropriate permissions

- [ ] **Connection Verified**
  ```bash
  # From production VM
  psql -h CLOUD_SQL_IP -U DB_USER -d financial_rise_production
  ```

- [ ] **Backup Schedule Configured**
  - Automated backups enabled in Cloud SQL
  - Retention period set (7-30 days recommended)

---

## ✅ First Deployment Test

- [ ] **Trigger Workflow Manually**
  - Navigate to Actions tab
  - Run workflow on `main` branch
  - Monitor execution

- [ ] **Verify Stages**
  - [ ] Backend tests pass
  - [ ] Frontend tests pass
  - [ ] Docker images build successfully
  - [ ] Images push to Artifact Registry
  - [ ] Staging deployment succeeds
  - [ ] Health check passes on staging

- [ ] **Manual Staging Verification**
  ```bash
  # Get staging IP
  gcloud compute addresses describe financial-rise-staging-ip \
    --region=us-central1 \
    --project=financial-rise-prod \
    --format='get(address)'

  # Test health endpoint
  curl http://STAGING_IP/api/v1/health

  # Test frontend
  curl http://STAGING_IP/
  ```

- [ ] **Approve Production Deployment**
  - Review staging
  - Approve in GitHub Actions
  - Monitor production deployment
  - Verify health checks pass

- [ ] **Manual Production Verification**
  ```bash
  # Get production IP
  gcloud compute addresses describe financial-rise-production-ip \
    --region=us-central1 \
    --project=financial-rise-prod \
    --format='get(address)'

  # Test health endpoint
  curl http://PRODUCTION_IP/api/v1/health

  # Test frontend
  curl http://PRODUCTION_IP/
  ```

---

## ✅ Post-Deployment

- [ ] **DNS Configuration**
  - [ ] Domain registered
  - [ ] A records point to static IPs
  - [ ] SSL/TLS certificate obtained (Let's Encrypt recommended)
  - [ ] HTTPS redirect configured

- [ ] **Monitoring Setup**
  - [ ] GCP Cloud Monitoring dashboards created
  - [ ] Uptime checks configured
  - [ ] Alert policies defined
  - [ ] Notification channels configured (email, Slack, etc.)

- [ ] **Logging**
  - [ ] Application logs flowing to Cloud Logging
  - [ ] Log-based metrics created
  - [ ] Log retention policy set

- [ ] **Backup Verification**
  - [ ] Database backups running automatically
  - [ ] Backup restoration tested
  - [ ] Backup retention policy confirmed

- [ ] **Security Hardening**
  - [ ] VM firewall rules reviewed and minimal
  - [ ] SSH access restricted to authorized IPs
  - [ ] Service account permissions reviewed
  - [ ] Secrets rotation schedule planned
  - [ ] HTTPS enforced

- [ ] **Documentation**
  - [ ] Deployment runbook created
  - [ ] Rollback procedure documented
  - [ ] On-call contacts listed
  - [ ] Known issues documented

---

## 🚨 Rollback Procedure

In case of deployment failure:

### Automatic Rollback

The GitHub Actions workflow includes automatic rollback on health check failure:
- Staging: Automatically reverts to previous `:latest` images
- Production: Automatically reverts to previous `:latest` images

### Manual Rollback

If needed, rollback manually:

```bash
# SSH to the VM
gcloud compute ssh ENVIRONMENT-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod

# Navigate to app directory
cd /opt/financial-rise

# Pull previous version (tagged as :latest before new deployment)
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull

# Restart with previous images
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate

# Verify services
docker ps
curl http://localhost/api/v1/health
```

### Database Rollback

```bash
# Restore from backup
gcloud sql backups list \
  --instance=financial-rise-ENVIRONMENT \
  --project=financial-rise-prod

# Restore specific backup
gcloud sql backups restore BACKUP_ID \
  --backup-instance=financial-rise-ENVIRONMENT \
  --project=financial-rise-prod
```

---

## 📚 Reference Documents

- **GCP-SETUP-QUICKSTART.md** - Quick start guide for GCP infrastructure
- **GITHUB-ACTIONS-SETUP.md** - Detailed GitHub Actions and Workload Identity setup
- **GITHUB-SECRETS-REFERENCE.md** - Quick reference for required secrets
- **.github/workflows/deploy-gcp.yml** - CI/CD pipeline configuration

---

## ✅ Final Checklist

Before considering deployment complete:

- [ ] All items above checked off
- [ ] Staging environment tested and verified
- [ ] Production environment tested and verified
- [ ] Team trained on deployment process
- [ ] Monitoring and alerting active
- [ ] Rollback procedure tested
- [ ] Documentation complete and accessible
- [ ] Stakeholders notified of deployment

---

**Document Version:** 1.0
**Last Updated:** 2025-12-27
**Status:** Ready for deployment
