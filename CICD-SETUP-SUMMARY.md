# CI/CD Setup Summary - Financial RISE Project

## ✅ Current Status

Your GitHub Actions CI/CD pipeline is **already configured** to use Workload Identity Federation for GCP authentication. The workflow file `.github/workflows/deploy-gcp.yml` is properly set up and ready to use.

## 📋 What You Need to Do

### 1. Configure GitHub Secrets

You need to add **9 secrets** to your GitHub repository. Use either method below:

#### Option A: GitHub CLI (Recommended - Fastest)

```bash
# Navigate to your repository
cd /path/to/financial-rise

# Set all secrets at once
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

#### Option B: GitHub Web UI

1. Go to your repository on GitHub
2. Navigate to **Settings → Secrets and variables → Actions**
3. Click **New repository secret**
4. Add each secret from the table in `GITHUB-SECRETS-REFERENCE.md`

### 2. Set Up GitHub Environments (For Production Approval)

1. Go to **Settings → Environments**
2. Create environment named `production`
3. Enable **Required reviewers**
4. Add team members who can approve production deployments
5. (Optional) Create `staging` environment if you want approval for staging too

### 3. Test the Pipeline

```bash
# Trigger a test deployment
git commit --allow-empty -m "Test CI/CD pipeline"
git push origin main

# Watch the workflow
# Go to GitHub Actions tab in your repository
```

## 🔄 How the Pipeline Works

### Workflow Stages

```
┌─────────────────────────────────────────────────────────────┐
│  1. Backend Tests         2. Frontend Tests                 │
│     ├─ Linting               ├─ Linting                     │
│     ├─ Unit Tests            ├─ Type Checking               │
│     └─ Coverage              ├─ Tests                       │
│                              └─ Build                       │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  3. Build & Push (main branch only)                         │
│     ├─ Authenticate via Workload Identity Federation       │
│     ├─ Build backend Docker image                          │
│     ├─ Build frontend Docker image                         │
│     ├─ Tag with commit SHA and :latest                     │
│     └─ Push to Artifact Registry                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  4. Deploy to Staging                                       │
│     ├─ Copy docker-compose files to VM                     │
│     ├─ Pull environment variables from Secret Manager      │
│     ├─ Pull Docker images                                  │
│     ├─ Run database migrations                             │
│     ├─ Restart containers                                  │
│     ├─ Health check                                        │
│     └─ Auto-rollback on failure                            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│  5. Deploy to Production (MANUAL APPROVAL REQUIRED)         │
│     ├─ Wait for reviewer approval                          │
│     ├─ Create database backup                              │
│     ├─ Copy docker-compose files to VM                     │
│     ├─ Pull environment variables from Secret Manager      │
│     ├─ Pull Docker images                                  │
│     ├─ Run database migrations                             │
│     ├─ Rolling restart (zero-downtime)                     │
│     ├─ Health check                                        │
│     └─ Auto-rollback on failure                            │
└─────────────────────────────────────────────────────────────┘
```

### Authentication Flow (Workload Identity Federation)

```
GitHub Actions Workflow
        ↓
    (Request OIDC Token from GitHub)
        ↓
GCP Workload Identity Provider
        ↓
    (Validate Token)
        ↓
GCP Service Account (github-actions@...)
        ↓
    (Short-lived credentials)
        ↓
GCP Resources (Artifact Registry, Compute, etc.)
```

**Key Security Benefits:**
- No service account keys stored in GitHub
- Credentials automatically rotate
- Fine-grained permissions via IAM roles
- Full audit trail in GCP Cloud Logging

## 📚 Documentation Reference

| Document | Purpose |
|----------|---------|
| **GITHUB-SECRETS-REFERENCE.md** | Quick reference table of all required secrets |
| **GITHUB-ACTIONS-SETUP.md** | Detailed setup guide with troubleshooting |
| **DEPLOYMENT-CHECKLIST.md** | Complete pre-deployment checklist |
| **GCP-SETUP-QUICKSTART.md** | GCP infrastructure setup guide |
| **.github/workflows/deploy-gcp.yml** | The actual workflow file |

## 🎯 Quick Start Steps

1. **Configure Secrets** (5 minutes)
   ```bash
   # Use the GitHub CLI commands from section 1 above
   ```

2. **Set Up Production Environment Protection** (2 minutes)
   - GitHub Settings → Environments → production → Required reviewers

3. **Trigger Test Deployment** (30 seconds)
   ```bash
   git commit --allow-empty -m "Test pipeline"
   git push origin main
   ```

4. **Monitor First Deployment** (5-10 minutes)
   - Watch in GitHub Actions tab
   - Verify staging deployment succeeds
   - Approve production deployment
   - Verify production deployment succeeds

## ✅ Verification Checklist

After setup, verify:

- [ ] All 9 GitHub secrets are configured (`gh secret list`)
- [ ] Production environment requires approval (Settings → Environments)
- [ ] Workflow runs successfully on push to `main`
- [ ] Backend tests pass
- [ ] Frontend tests pass
- [ ] Docker images build and push to Artifact Registry
- [ ] Staging deployment succeeds
- [ ] Staging health check passes
- [ ] Production deployment requires manual approval
- [ ] Production deployment succeeds after approval
- [ ] Production health check passes

## 🔧 Common Commands

### Check Secrets
```bash
gh secret list
```

### Trigger Manual Workflow Run
```bash
# Empty commit to trigger pipeline
git commit --allow-empty -m "Trigger deployment"
git push origin main
```

### View Workflow Logs
```bash
gh run list
gh run view WORKFLOW_RUN_ID
gh run view WORKFLOW_RUN_ID --log
```

### Check Deployed Images
```bash
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker \
  --project=financial-rise-prod
```

### SSH to VMs
```bash
# Staging
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod

# Production
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod
```

### Check Running Containers on VM
```bash
# After SSH to VM
cd /opt/financial-rise
docker ps
docker compose logs -f
```

### Manual Rollback (if needed)
```bash
# SSH to affected VM
cd /opt/financial-rise
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --force-recreate
```

## 🚨 Troubleshooting

### Issue: "Could not authenticate with Workload Identity Federation"

**Check:**
1. Verify `GCP_WORKLOAD_IDENTITY_PROVIDER` secret is exactly:
   ```
   projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
   ```
2. Verify service account has `roles/iam.workloadIdentityUser` binding
3. Ensure workflow is running from the main repository (not a fork)

**Fix:**
```bash
# Verify Workload Identity Pool exists
gcloud iam workload-identity-pools describe github-actions-pool \
  --location=global \
  --project=financial-rise-prod

# Check service account bindings
gcloud iam service-accounts get-iam-policy \
  github-actions@financial-rise-prod.iam.gserviceaccount.com \
  --project=financial-rise-prod
```

### Issue: "Permission denied" errors

**Check:**
- Service account has required roles
- Secrets are spelled correctly (case-sensitive)

**Fix:**
```bash
# List service account roles
gcloud projects get-iam-policy financial-rise-prod \
  --flatten="bindings[].members" \
  --filter="bindings.members:github-actions@financial-rise-prod.iam.gserviceaccount.com"
```

### Issue: Health check fails

**Check:**
1. Application logs on VM
2. Database connection
3. Environment variables loaded correctly

**Debug:**
```bash
# SSH to VM
gcloud compute ssh ENVIRONMENT-vm --zone=us-central1-a

# Check logs
cd /opt/financial-rise
docker compose logs backend
docker compose logs frontend

# Test health endpoint locally
curl http://localhost:4000/api/v1/health
```

## 📞 Support

For detailed troubleshooting, see **GITHUB-ACTIONS-SETUP.md** section "Common Issues"

---

**Summary:** Your workflow is already configured correctly! Just add the GitHub secrets and you're ready to deploy.

**Next Steps:**
1. Add the 9 GitHub secrets
2. Configure production environment protection
3. Push a commit to trigger the pipeline
4. Monitor the deployment
5. Celebrate! 🎉
