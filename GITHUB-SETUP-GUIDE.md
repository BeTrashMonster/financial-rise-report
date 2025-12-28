# GitHub Actions Setup Guide - Workload Identity Federation

## What I've Done

✅ Updated `.github/workflows/deploy-gcp.yml` to use Workload Identity Federation
✅ Created `setup-workload-identity.sh` to configure GCP for GitHub Actions
✅ Updated Secret Manager with your environment variables

## What You Need to Do

### Step 1: Run the Workload Identity Setup Script

This creates the secure connection between GitHub Actions and GCP:

```bash
bash setup-workload-identity.sh
```

This script will:
- Enable IAM Credentials API
- Create a Workload Identity Pool
- Create a GitHub OIDC Provider
- Grant permissions to your repository
- Generate all the secret values you need
- Save them to `github-secrets.txt` for easy copying

**Time:** ~2 minutes

### Step 2: Add Secrets to GitHub

1. Go to: **https://github.com/BeTrashMonster/financial-rise-report/settings/secrets/actions**

2. Click **"New repository secret"** for each of these:

The script will output all values. You can also find them in `github-secrets.txt`.

#### Required Secrets (10 total):

| Secret Name | Description | Example Value |
|-------------|-------------|---------------|
| `GCP_PROJECT_ID` | Your GCP project ID | `financial-rise-prod` |
| `GCP_PROJECT_NUMBER` | Your GCP project number | `123456789012` |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Workload Identity Provider resource | `projects/123.../providers/github-provider` |
| `GCP_SERVICE_ACCOUNT` | Service account email | `github-actions@financial-rise-prod.iam.gserviceaccount.com` |
| `GCP_REGION` | Deployment region | `us-central1` |
| `ARTIFACT_REGISTRY_REPO` | Docker registry name | `financial-rise-docker` |
| `STAGING_VM_NAME` | Staging VM instance name | `financial-rise-staging-vm` |
| `PRODUCTION_VM_NAME` | Production VM instance name | `financial-rise-production-vm` |
| `STAGING_VM_ZONE` | Staging VM zone | `us-central1-a` |
| `PRODUCTION_VM_ZONE` | Production VM zone | `us-central1-a` |

### Step 3: Commit the Updated Workflow

The workflow file has been updated to use Workload Identity. Commit it:

```bash
git add .github/workflows/deploy-gcp.yml
git commit -m "Update GitHub Actions to use Workload Identity Federation"
git push origin main
```

### Step 4: Monitor the First Deployment

1. Go to: **https://github.com/BeTrashMonster/financial-rise-report/actions**

2. Watch the workflow run through:
   - ✅ Backend tests
   - ✅ Frontend tests
   - ✅ Build and push Docker images
   - ✅ Deploy to staging
   - ⏸️ Wait for manual approval
   - ✅ Deploy to production (after you approve)

## Understanding Workload Identity Federation

### Why This is Better Than Service Account Keys:

**Traditional Method (Service Account Keys):**
- ❌ Long-lived credentials that never expire
- ❌ Can be stolen if compromised
- ❌ Must be rotated manually
- ❌ Stored as secrets in GitHub

**Workload Identity Federation:**
- ✅ No long-lived credentials
- ✅ Short-lived tokens (1 hour)
- ✅ Automatically rotated
- ✅ Can only be used by your specific GitHub repository
- ✅ Can't be stolen or reused elsewhere

### How It Works:

```
GitHub Actions
    ↓
Requests token from GitHub's OIDC provider
    ↓
Presents token to GCP Workload Identity Provider
    ↓
GCP verifies token is from your repository
    ↓
GCP issues short-lived access token
    ↓
GitHub Actions can now access GCP resources
```

## Troubleshooting

### "Permission denied" when running setup script

```bash
# Make sure you're authenticated
gcloud auth login
gcloud config set project financial-rise-prod
```

### "Workload Identity Pool already exists"

This is fine! The script will skip creation and use the existing pool.

### GitHub Actions fails with "authentication failed"

1. Verify all secrets are set correctly in GitHub
2. Check that the service account has the necessary permissions:
   ```bash
   gcloud projects get-iam-policy financial-rise-prod \
     --flatten="bindings[].members" \
     --filter="bindings.members:github-actions@financial-rise-prod.iam.gserviceaccount.com"
   ```

### "Cannot find project" error

Make sure `GCP_PROJECT_ID` secret matches your actual project ID: `financial-rise-prod`

### Deployment succeeds but app doesn't work

1. Check the VMs are running:
   ```bash
   gcloud compute instances list --project=financial-rise-prod
   ```

2. Check application logs:
   ```bash
   gcloud logging read "resource.type=gce_instance" \
     --project=financial-rise-prod \
     --limit=50
   ```

3. SSH into VM and check Docker containers:
   ```bash
   gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod
   docker ps
   docker logs financial-rise-backend
   docker logs financial-rise-frontend
   ```

## Security Best Practices

✅ **Enabled:**
- Workload Identity Federation (no service account keys)
- Repository-specific access (only your repo can authenticate)
- Short-lived tokens (1 hour expiration)
- Principle of least privilege (service account has only necessary roles)

🔒 **Additional Recommendations:**

1. **Enable branch protection:**
   - Require pull request reviews before merging to main
   - Require status checks to pass

2. **Set up environment protection rules:**
   - Require approval for production deployments
   - Limit who can approve deployments

3. **Monitor deployments:**
   - Set up GCP Cloud Monitoring alerts
   - Review audit logs regularly

4. **Rotate secrets periodically:**
   - Database passwords (quarterly)
   - JWT secrets (quarterly)
   - SendGrid API keys (as needed)

## What Happens on Deployment

### Automatic (Staging):

```bash
git push origin main
  ↓
[1] Run backend tests with PostgreSQL
  ↓
[2] Run frontend tests and build
  ↓
[3] Build Docker images
  ↓
[4] Push to Artifact Registry
  ↓
[5] Deploy to staging VM:
    - SSH to staging VM
    - Pull latest secrets from Secret Manager
    - Pull Docker images
    - Create database backup
    - Restart containers
    - Health check
```

### Manual Approval (Production):

```
[6] GitHub sends notification for approval
  ↓
[7] You review staging and click "Approve"
  ↓
[8] Deploy to production VM:
    - Same steps as staging
    - Additional backup to GCS
    - Rolling restart
    - Health verification
```

## Costs

**Running Costs:**
- Workload Identity: **FREE**
- GitHub Actions: **FREE** (included in GitHub)
- GCP VMs: ~$108/month (as configured)

## Next Steps

1. ✅ Run `bash setup-workload-identity.sh`
2. ✅ Add the 10 secrets to GitHub
3. ✅ Commit and push the updated workflow
4. ✅ Watch your first deployment!
5. 🎉 Your application is live!

After deployment, access your app at:
- **Staging:** `http://<STAGING_IP>:4000/api/v1/health`
- **Production:** `http://<PRODUCTION_IP>:4000/api/v1/health`

(IPs shown in setup script output)
