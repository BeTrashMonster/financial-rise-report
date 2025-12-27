# Google Cloud VM Deployment Plan - Financial RISE Report

## Overview

Replace existing AWS ECS infrastructure with Google Cloud Compute Engine VMs running Docker Compose. This plan provides simpler, more cost-effective deployment while maintaining full production capabilities.

**Target Application:** `financial-rise-app/` (NestJS backend + React frontend)
**Architecture:** Single VM per environment running Docker Compose
**CI/CD:** GitHub Actions with auto-deploy to staging, manual approval for production

---

## Infrastructure Components

### Compute Resources

**Staging Environment (~$20/month)**
- VM: `e2-medium` (2 vCPU, 4GB RAM) - **Preemptible**
- Disk: 30GB SSD
- Cloud SQL: `db-f1-micro` (PostgreSQL 14)
- Static IP: Reserved regional address
- Zone: `us-central1-a`

**Production Environment (~$86/month)**
- VM: `e2-standard-2` (2 vCPU, 8GB RAM)
- Disk: 50GB SSD
- Cloud SQL: `db-g1-small` with HA enabled
- Static IP: Reserved regional address
- Zone: `us-central1-a`

### Supporting Services

- **Artifact Registry:** Docker image repository (replaces AWS ECR)
- **Cloud Storage:** PDF report storage (replaces AWS S3)
- **Secret Manager:** Environment variables and secrets
- **Cloud Logging:** Centralized logging (replaces CloudWatch)
- **VPC Network:** Private networking with Cloud NAT
- **Cloud SQL:** Managed PostgreSQL (replaces AWS RDS)

---

## Implementation Steps

### Phase 1: GCP Infrastructure Setup

**1. Project & APIs**
```bash
# Create project
gcloud projects create financial-rise-prod

# Enable required APIs
gcloud services enable compute.googleapis.com sqladmin.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com \
  storage.googleapis.com
```

**2. Networking**
```bash
# Create VPC
gcloud compute networks create financial-rise-vpc --subnet-mode=auto

# Firewall rules
gcloud compute firewall-rules create allow-http-https \
  --network=financial-rise-vpc --allow=tcp:80,tcp:443 \
  --source-ranges=0.0.0.0/0 --target-tags=http-server

gcloud compute firewall-rules create allow-ssh-iap \
  --network=financial-rise-vpc --allow=tcp:22 \
  --source-ranges=35.235.240.0/20 --target-tags=allow-ssh
```

**3. Cloud SQL Databases**
```bash
# Staging DB
gcloud sql instances create financial-rise-staging-db \
  --database-version=POSTGRES_14 --tier=db-f1-micro \
  --region=us-central1 --network=financial-rise-vpc \
  --no-assign-ip

# Production DB (with HA)
gcloud sql instances create financial-rise-production-db \
  --database-version=POSTGRES_14 --tier=db-g1-small \
  --region=us-central1 --availability-type=REGIONAL \
  --network=financial-rise-vpc --no-assign-ip
```

**4. Storage & Registry**
```bash
# Artifact Registry
gcloud artifacts repositories create financial-rise-docker \
  --repository-format=docker --location=us-central1

# GCS Buckets
gcloud storage buckets create gs://financial-rise-reports-staging --location=us-central1
gcloud storage buckets create gs://financial-rise-reports-production --location=us-central1
```

**5. Static IPs**
```bash
gcloud compute addresses create financial-rise-staging-ip --region=us-central1
gcloud compute addresses create financial-rise-production-ip --region=us-central1
```

### Phase 2: VM Creation

**1. Create VMs**
```bash
# Staging (preemptible for cost savings)
gcloud compute instances create financial-rise-staging-vm \
  --zone=us-central1-a --machine-type=e2-medium \
  --network=financial-rise-vpc --address=financial-rise-staging-ip \
  --boot-disk-size=30GB --boot-disk-type=pd-ssd \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --tags=http-server,https-server,allow-ssh \
  --metadata-from-file=startup-script=scripts/vm-startup.sh \
  --scopes=cloud-platform --preemptible

# Production
gcloud compute instances create financial-rise-production-vm \
  --zone=us-central1-a --machine-type=e2-standard-2 \
  --network=financial-rise-vpc --address=financial-rise-production-ip \
  --boot-disk-size=50GB --boot-disk-type=pd-ssd \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --tags=http-server,https-server,allow-ssh \
  --metadata-from-file=startup-script=scripts/vm-startup.sh \
  --scopes=cloud-platform
```

**2. VM Directory Structure**
```
/opt/financial-rise/
├── .env                    # From Secret Manager
├── docker-compose.yml      # Main compose file
├── docker-compose.prod.yml # Production overrides
├── backend/                # App code (cloned/copied)
├── frontend/               # App code (cloned/copied)
└── scripts/
    ├── deploy.sh
    ├── health-check.sh
    ├── backup.sh
    └── rollback.sh
```

### Phase 3: Application Configuration

**Critical Files to Create/Modify:**

**1. CREATE `.github/workflows/deploy-gcp.yml`** (Main repo root)
- Complete CI/CD pipeline with 5 jobs:
  - `backend-test`: Run backend tests with PostgreSQL service
  - `frontend-test`: Run frontend tests and build
  - `build-and-push`: Build Docker images → push to Artifact Registry
  - `deploy-staging`: Auto-deploy to staging VM
  - `deploy-production`: Manual approval deployment to production

**2. CREATE `financial-rise-app/docker-compose.prod.yml`**
```yaml
version: '3.8'
services:
  postgres:
    profiles: [local-only]  # Disable - using Cloud SQL

  backend:
    build:
      target: production
    restart: always
    environment:
      DATABASE_HOST: ${DATABASE_HOST}  # Cloud SQL private IP
    logging:
      driver: gcplogs
      options:
        gcp-project: ${GCP_PROJECT_ID}

  frontend:
    build:
      target: production
    restart: always
    ports:
      - "80:80"
      - "443:443"
    logging:
      driver: gcplogs

  redis:
    restart: always
    command: redis-server --appendonly yes
    logging:
      driver: gcplogs
```

**3. CREATE `financial-rise-app/scripts/vm-startup.sh`**
```bash
#!/bin/bash
set -e

# Install Docker & Docker Compose
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Docker Compose V2
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Install Google Cloud Ops Agent (logging)
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install

# Create app directory
mkdir -p /opt/financial-rise
systemctl enable docker
```

**4. MODIFY `financial-rise-app/backend/package.json`**
- Add: `"@google-cloud/storage": "^7.7.0"`
- Replace AWS S3 dependency with GCS

**5. MODIFY `financial-rise-app/backend/src/[storage-service]`**
- Replace AWS S3 SDK with Google Cloud Storage SDK
- Update upload/download methods for GCS bucket

**6. MODIFY `financial-rise-app/docker-compose.yml`**
- Change backend port from 3000 to 4000 (to match nginx proxy)
- Update environment variable references

### Phase 4: Secrets & Environment

**1. Create Production Environment File**
```env
DATABASE_HOST=10.x.x.x  # Cloud SQL private IP
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=<generated>
DATABASE_NAME=financial_rise_production
JWT_SECRET=<generated>
JWT_REFRESH_SECRET=<generated>
GCS_BUCKET=financial-rise-reports-production
GCP_PROJECT_ID=financial-rise-prod
SENDGRID_API_KEY=<your-key>
NODE_ENV=production
PORT=4000
FRONTEND_URL=https://financialrise.com
```

**2. Upload to Secret Manager**
```bash
gcloud secrets create financial-rise-production-env --data-file=.env.production
gcloud secrets create financial-rise-staging-env --data-file=.env.staging
```

**3. Configure GitHub Secrets**
Navigate to GitHub repo → Settings → Secrets → Add:
- `GCP_PROJECT_ID`
- `GCP_SA_KEY` (service account JSON key, base64 encoded)
- `GCP_REGION` = `us-central1`
- `ARTIFACT_REGISTRY_REPO` = `financial-rise-docker`
- `STAGING_VM_NAME` = `financial-rise-staging-vm`
- `PRODUCTION_VM_NAME` = `financial-rise-production-vm`
- `STAGING_VM_ZONE` = `us-central1-a`
- `PRODUCTION_VM_ZONE` = `us-central1-a`

### Phase 5: CI/CD Pipeline Setup

**GitHub Actions Workflow Structure:**

```yaml
# .github/workflows/deploy-gcp.yml

jobs:
  backend-test:
    - Checkout code
    - Setup Node 18
    - npm ci & lint & test:cov
    - Upload coverage to Codecov

  frontend-test:
    - Checkout code
    - Setup Node 18
    - npm ci & lint & type-check & test & build
    - Upload coverage to Codecov

  build-and-push:
    needs: [backend-test, frontend-test]
    if: github.ref == 'refs/heads/main'
    - Authenticate to GCP
    - Configure Docker for Artifact Registry
    - Build backend image → tag with git SHA + latest
    - Build frontend image → tag with git SHA + latest
    - Push to us-central1-docker.pkg.dev/PROJECT/financial-rise-docker/

  deploy-staging:
    needs: build-and-push
    environment: staging
    - Copy docker-compose files to VM via gcloud compute scp
    - SSH to VM and execute:
      - Pull secrets from Secret Manager → .env
      - docker compose pull
      - Create database backup
      - Run migrations
      - docker compose up -d --force-recreate
    - Health check with retries (30 attempts, 10s interval)
    - Rollback on failure

  deploy-production:
    needs: deploy-staging
    environment: production  # ← Manual approval required
    - Same as staging but for production VM
    - Backup to GCS before deployment
    - Rolling restart (backend first, then frontend)
    - Health check verification
```

### Phase 6: Testing & Validation

**Pre-Deployment Validation:**
1. Local Docker Compose test
2. Backend health endpoint test
3. Frontend access test
4. Database connection test

**Post-Deployment Validation:**
1. Health endpoint: `curl https://staging.financialrise.com/api/v1/health`
2. API functionality test (login endpoint)
3. PDF generation test
4. Cloud Logging verification
5. Performance testing with Apache Bench

### Phase 7: Data Migration from AWS

**1. Export from AWS RDS**
```bash
pg_dump -h aws-rds-endpoint.amazonaws.com -U username -d financial_rise > backup.sql
```

**2. Import to Cloud SQL**
```bash
# Upload backup to GCS
gcloud storage cp backup.sql gs://financial-rise-backups/

# Import
gcloud sql import sql financial-rise-production-db \
  gs://financial-rise-backups/backup.sql \
  --database=financial_rise_production
```

**3. Migrate S3 to GCS**
```bash
gsutil -m rsync -r s3://financial-rise-reports gs://financial-rise-reports-production
```

### Phase 8: DNS Cutover

**Update DNS Records:**
- Get static IP: `gcloud compute addresses describe financial-rise-production-ip --region=us-central1 --format='get(address)'`
- Update DNS A record to point to GCP static IP
- Monitor for 24-48 hours
- Keep AWS running as backup during transition

### Phase 9: AWS Cleanup

**After 48 hours of stable GCP operation:**

**Files to DELETE:**
- `financial-rise-app/infrastructure/terraform/` (AWS modules)
- `financial-rise-app/.github/workflows/ci-cd.yml` (AWS workflow)
- Any AWS-specific configs

**AWS Resources to Terminate:**
```bash
cd financial-rise-app/infrastructure/terraform
terraform destroy  # Destroys ECS, RDS, S3, etc.
```

**GitHub Secrets to Remove:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_REGION`

---

## Deployment Flow

**When you push to `main` branch:**

```
git push origin main
  ↓
GitHub Actions triggers
  ↓
Run backend tests (with PostgreSQL service)
  ↓
Run frontend tests + build
  ↓
Build Docker images
  ↓
Push to Artifact Registry (us-central1)
  ↓
Auto-deploy to STAGING VM
  ├─ Pull secrets from Secret Manager
  ├─ docker compose pull
  ├─ Database backup
  ├─ Run migrations
  ├─ docker compose up -d --force-recreate
  └─ Health check (30 retries)
  ↓
Wait for MANUAL APPROVAL in GitHub
  ↓
Deploy to PRODUCTION VM
  ├─ Database backup → upload to GCS
  ├─ Pull secrets
  ├─ docker compose pull
  ├─ Run migrations
  ├─ Rolling restart (backend → frontend)
  └─ Health check verification
  ↓
✅ Deployment Complete
```

---

## Rollback Procedures

### Automatic Rollback
- GitHub Actions automatically rolls back on deployment failure
- Pulls previous `latest` tagged images
- Restarts containers

### Manual Rollback
```bash
# SSH to VM
gcloud compute ssh financial-rise-production-vm --zone=us-central1-a

# Pull specific previous version
cd /opt/financial-rise
docker compose pull backend:PREVIOUS_SHA frontend:PREVIOUS_SHA

# Restart with specific versions
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate
```

### Database Rollback
```bash
# Download backup from GCS
gcloud storage cp gs://financial-rise-backups/backup-TIMESTAMP.sql /tmp/

# Restore
docker compose exec -T postgres psql -U financial_rise financial_rise_production < /tmp/backup-TIMESTAMP.sql
```

---

## Security Features

**Network Security:**
- VPC with private Cloud SQL connection (no public IP)
- Firewall: Only ports 80, 443, and SSH (via IAP) allowed
- Cloud NAT for outbound traffic only

**Access Control:**
- Service account with minimal IAM roles
- Secret Manager for all sensitive data
- OS Login for SSH access
- Workload Identity for GitHub Actions

**Container Security:**
- Non-root containers
- Multi-stage builds
- Image vulnerability scanning via Artifact Registry
- Resource limits in docker-compose.prod.yml

**Database Security:**
- Private IP only
- SSL/TLS enforced
- Automated encrypted backups (30-day retention)
- Automatic patch management

**Monitoring:**
- Cloud Logging integration via gcplogs driver
- Uptime checks on health endpoints
- Alert policies for CPU, memory, disk usage
- Audit logging for all infrastructure changes

---

## Cost Breakdown

**Monthly Estimates:**

**Staging (~$20/month):**
- e2-medium preemptible: $7
- 30GB SSD: $5
- Cloud SQL db-f1-micro: $7
- Static IP: $3

**Production (~$86/month):**
- e2-standard-2: $50
- 50GB SSD: $8
- Cloud SQL db-g1-small HA: $25
- Static IP: $3

**Shared Costs:**
- Artifact Registry: ~$2/month
- Cloud Storage: ~$1/month
- Logging: ~$5/month

**Total: ~$112/month** (vs AWS ECS likely $200-300/month)

**Cost Optimization:**
- Use committed use discounts (25-52% savings)
- Schedule staging VM stop/start (save 50% on staging compute)
- GCS lifecycle policies (delete old PDFs after 90 days)
- Log retention: 7 days staging, 30 days production

---

## Critical Implementation Files

**Files to CREATE:**
1. `.github/workflows/deploy-gcp.yml` - Complete CI/CD pipeline
2. `financial-rise-app/docker-compose.prod.yml` - Production overrides
3. `financial-rise-app/scripts/vm-startup.sh` - VM initialization
4. `financial-rise-app/scripts/deploy.sh` - Deployment automation
5. `financial-rise-app/scripts/health-check.sh` - Health verification
6. `financial-rise-app/scripts/backup.sh` - Database backup automation

**Files to MODIFY:**
1. `financial-rise-app/backend/package.json` - Add @google-cloud/storage
2. `financial-rise-app/backend/src/[storage-service].ts` - Replace S3 with GCS
3. `financial-rise-app/docker-compose.yml` - Update backend port to 4000
4. `financial-rise-app/frontend/nginx.conf` - Add SSL config (optional)

**Files to DELETE:**
1. `financial-rise-app/infrastructure/terraform/*` - All AWS Terraform configs
2. `financial-rise-app/.github/workflows/ci-cd.yml` - AWS workflow

---

## Success Criteria

**Deployment Successful When:**
- ✅ GitHub Actions workflow completes without errors
- ✅ Health endpoint returns 200 OK
- ✅ Frontend loads and displays correctly
- ✅ Backend API responds to test requests
- ✅ Database migrations applied successfully
- ✅ PDF generation works and uploads to GCS
- ✅ Cloud Logging shows application logs
- ✅ No errors in past 30 minutes of logs
- ✅ Database backups created and stored in GCS

**Production Ready When:**
- ✅ Staging environment stable for 48+ hours
- ✅ All tests passing in CI/CD pipeline
- ✅ Manual approval process configured in GitHub
- ✅ SSL/TLS configured (Let's Encrypt or Cloud Load Balancer)
- ✅ Domain DNS points to static IP
- ✅ Monitoring and alerting active
- ✅ Backup strategy tested with restore verification

---

## VM Sizing Comparison & Trade-offs

### e2-small ($9/month) vs e2-medium ($17/month) vs e2-standard-2 ($50/month)

| Spec | e2-small | e2-medium (Recommended Staging) | e2-standard-2 (Recommended Production) |
|------|----------|--------------------------------|----------------------------------------|
| **vCPUs** | 2 shared | 2 shared | 2 dedicated |
| **Memory** | 2 GB | 4 GB | 8 GB |
| **Cost/month** | ~$9 | ~$17 | ~$50 |
| **Preemptible** | ~$2/month | ~$7/month | N/A for production |

### Can you use e2-small ($9/month)?

**YES for Staging**, with these considerations:

**What Works:**
- ✅ Docker Compose with all services (backend, frontend, redis)
- ✅ NestJS backend with TypeORM
- ✅ React frontend with Nginx
- ✅ Redis caching
- ✅ PDF generation (Puppeteer will be slower)
- ✅ Development and testing workloads

**Limitations with 2GB RAM:**
- ⚠️ **Memory pressure** when running all containers simultaneously
- ⚠️ **Slower PDF generation** (Puppeteer + Chromium is memory-intensive ~500MB+)
- ⚠️ **Slower builds** if building on the VM (use pre-built images instead)
- ⚠️ **Limited concurrent users** (~5-10 simultaneous users max)
- ⚠️ **Database migrations may be slow** with large datasets
- ⚠️ **Swap usage** likely during peak usage (performance degradation)

**Recommendation for e2-small:**
```bash
# Add swap space to handle memory pressure
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# Limit Docker container memory
# Add to docker-compose.prod.yml:
services:
  backend:
    deploy:
      resources:
        limits:
          memory: 800M
  frontend:
    deploy:
      resources:
        limits:
          memory: 200M
  redis:
    deploy:
      resources:
        limits:
          memory: 128M
```

**Cost Comparison for Full Stack:**

| Component | e2-small Setup | e2-medium Setup | e2-standard-2 Setup |
|-----------|----------------|-----------------|---------------------|
| VM (preemptible) | $2/month | $7/month | $17/month (spot) |
| VM (standard) | $9/month | $17/month | $50/month |
| Disk 30GB | $5/month | $5/month | $8/month (50GB) |
| Cloud SQL micro | $7/month | $7/month | $25/month (small HA) |
| Static IP | $3/month | $3/month | $3/month |
| **Total (staging)** | **$17/month** | **$22/month** | **$53/month** |
| **Total (production)** | **$24/month** | **$32/month** | **$86/month** |

### Recommended Configuration

**Budget-Conscious Approach:**
- **Staging:** `e2-small` preemptible ($17/month total) + swap space
- **Production:** `e2-medium` standard ($32/month total)
- **Total:** ~$49/month for both environments

**Recommended Approach (from original plan):**
- **Staging:** `e2-medium` preemptible ($22/month total)
- **Production:** `e2-standard-2` standard ($86/month total)
- **Total:** ~$108/month for both environments

**Performance Difference:**
- e2-small: Good for 5-10 concurrent users, slower PDF generation
- e2-medium: Good for 20-30 concurrent users, acceptable PDF generation
- e2-standard-2: Good for 50+ concurrent users, fast PDF generation, room to scale

**Decision Guide:**
- Use **e2-small** if: Budget is critical, <10 users, staging only, willing to accept slower performance
- Use **e2-medium** if: Balanced cost/performance, 20-30 users, good for production MVP
- Use **e2-standard-2** if: Production-grade performance, 50+ users, critical workload, fast PDF generation required

### To Use e2-small Instead:

Update the VM creation commands to:
```bash
# Staging with e2-small
gcloud compute instances create financial-rise-staging-vm \
  --machine-type=e2-small \
  [... rest of flags ...]

# Production with e2-medium (instead of e2-standard-2)
gcloud compute instances create financial-rise-production-vm \
  --machine-type=e2-medium \
  [... rest of flags ...]
```

And add memory limits to `docker-compose.prod.yml` as shown above.

---

## Next Steps After Plan Approval

1. Create GCP project and enable billing
2. Run infrastructure setup commands (Phase 1)
3. Create VM startup script
4. Provision VMs and Cloud SQL instances
5. Update backend code for GCS
6. Create docker-compose.prod.yml
7. Create GitHub Actions workflow
8. Configure GitHub secrets
9. Test staging deployment
10. Migrate data from AWS
11. Update DNS for production cutover
12. Clean up AWS resources
