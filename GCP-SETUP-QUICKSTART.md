# GCP Infrastructure Setup - Quick Start Guide

## Overview

I've created automated scripts to set up your entire Google Cloud infrastructure for the Financial RISE application. This guide walks you through the process step-by-step.

## What Will Be Created

When you run the setup script, it will create:

### Infrastructure
- ✅ GCP Project: `financial-rise-prod`
- ✅ VPC Network with firewall rules
- ✅ 2 Cloud SQL PostgreSQL databases (staging + production)
- ✅ Artifact Registry for Docker images
- ✅ 3 GCS buckets (staging reports, production reports, backups)
- ✅ 2 Static IP addresses
- ✅ 2 Compute Engine VMs (staging e2-medium, production e2-standard-2)
- ✅ Service account for GitHub Actions
- ✅ Secret Manager with environment variables

### Monthly Cost Estimate
- **Staging:** ~$22/month
- **Production:** ~$86/month
- **Shared Services:** ~$8/month
- **Total:** ~$116/month

## Step-by-Step Setup

### 1. Install Google Cloud SDK

#### Option A: Download Installer (Recommended)
1. Go to: https://cloud.google.com/sdk/docs/install
2. Download "Google Cloud CLI installer" for Windows
3. Run the installer
4. Check "Run 'gcloud init'" at the end
5. Restart your terminal

#### Option B: PowerShell
```powershell
# Download installer
(New-Object Net.WebClient).DownloadFile("https://dl.google.com/dl/cloudsdk/channels/rapid/GoogleCloudSDKInstaller.exe", "$env:Temp\GoogleCloudSDKInstaller.exe")

# Run installer
& $env:Temp\GoogleCloudSDKInstaller.exe
```

### 2. Verify Installation

Open a new terminal and run:

```bash
gcloud --version
```

You should see the gcloud version information.

### 3. Authenticate to Google Cloud

```bash
gcloud init
```

This will:
- Open your browser for authentication
- Let you select or create a project (you can skip this for now)
- Set your default region

### 4. Set Up Billing

**IMPORTANT:** You need a billing account to create resources.

1. Go to: https://console.cloud.google.com/billing
2. Create a billing account (requires credit card)
3. No charges will occur until resources are created and running

### 5. Run the Infrastructure Setup Script

From the `C:\Users\Admin\src` directory:

#### Using Git Bash or WSL:
```bash
bash setup-gcp-infrastructure.sh
```

#### Using PowerShell:
```powershell
# Run in Git Bash or WSL
wsl bash setup-gcp-infrastructure.sh
```

The script will:
- ✅ Create the GCP project
- ✅ Enable all required APIs (~2-3 minutes)
- ✅ Set up networking
- ✅ Create Cloud SQL databases (~10-15 minutes)
- ✅ Create storage buckets
- ✅ Reserve static IPs
- ✅ Create VMs (~5 minutes)
- ✅ Generate secrets and environment files
- ✅ Upload secrets to Secret Manager

**Total time: ~20-30 minutes**

### 6. Encode the Service Account Key

After the setup script completes, run:

```powershell
.\encode-service-account-key.ps1
```

This will:
- Encode `github-actions-key.json` to base64
- Save it to `github-actions-key-base64.txt`
- Copy it to your clipboard (if available)

### 7. Configure GitHub Secrets

1. Go to: https://github.com/BeTrashMonster/financial-rise-report/settings/secrets/actions

2. Click "New repository secret" and add each of these:

| Secret Name | Value |
|-------------|-------|
| `GCP_PROJECT_ID` | `financial-rise-prod` |
| `GCP_SA_KEY` | Contents of `github-actions-key-base64.txt` |
| `GCP_REGION` | `us-central1` |
| `ARTIFACT_REGISTRY_REPO` | `financial-rise-docker` |
| `STAGING_VM_NAME` | `financial-rise-staging-vm` |
| `PRODUCTION_VM_NAME` | `financial-rise-production-vm` |
| `STAGING_VM_ZONE` | `us-central1-a` |
| `PRODUCTION_VM_ZONE` | `us-central1-a` |

### 8. Update SendGrid API Key (Optional but Recommended)

If you have a SendGrid account for sending emails:

1. Edit `.env.staging` and `.env.production`
2. Replace `your-sendgrid-api-key-here` with your actual API key
3. Update the secrets:

```bash
gcloud secrets versions add financial-rise-staging-env --data-file=.env.staging --project=financial-rise-prod
gcloud secrets versions add financial-rise-production-env --data-file=.env.production --project=financial-rise-prod
```

### 9. Wait for VM Initialization

The VMs need 5-10 minutes to complete their startup scripts, which install:
- Docker
- Docker Compose V2
- Google Cloud Ops Agent (for logging)

You can check the status:

```bash
# Check staging VM
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod --command="docker --version"

# Check production VM
gcloud compute ssh financial-rise-production-vm --zone=us-central1-a --project=financial-rise-prod --command="docker --version"
```

### 10. Deploy Your Application

Once GitHub secrets are configured and VMs are ready:

```bash
git push origin main
```

This will trigger the GitHub Actions workflow:
1. Run backend tests
2. Run frontend tests
3. Build and push Docker images to Artifact Registry
4. Auto-deploy to staging
5. Wait for manual approval
6. Deploy to production (after approval)

Monitor the deployment:
- https://github.com/BeTrashMonster/financial-rise-report/actions

## Files Created by Setup Script

**⚠️ KEEP THESE SECURE - DO NOT COMMIT TO GIT:**

- `.env.staging` - Staging environment variables with database credentials
- `.env.production` - Production environment variables with database credentials
- `github-actions-key.json` - Service account key (JSON)
- `github-actions-key-base64.txt` - Base64-encoded service account key

These files contain sensitive information. Add them to `.gitignore`:

```bash
echo ".env.staging" >> .gitignore
echo ".env.production" >> .gitignore
echo "github-actions-key.json" >> .gitignore
echo "github-actions-key-base64.txt" >> .gitignore
```

## Access Your Application

After successful deployment:

**Staging:**
- Frontend: `http://<STAGING_IP>`
- Backend API: `http://<STAGING_IP>:4000/api/v1`
- Health Check: `http://<STAGING_IP>:4000/api/v1/health`

**Production:**
- Frontend: `http://<PRODUCTION_IP>`
- Backend API: `http://<PRODUCTION_IP>:4000/api/v1`
- Health Check: `http://<PRODUCTION_IP>:4000/api/v1/health`

(IPs will be displayed at the end of the setup script)

## Troubleshooting

### "gcloud: command not found"
- Restart your terminal after installing Google Cloud SDK
- Or add gcloud to your PATH manually

### "No billing account found"
- Set up billing at: https://console.cloud.google.com/billing
- You need a credit card on file (even for free tier)

### "Permission denied" errors
- Make sure you're authenticated: `gcloud auth login`
- Check your account has necessary permissions

### VMs not ready after 10 minutes
- Check startup script logs:
  ```bash
  gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod --command="sudo journalctl -u google-startup-scripts.service"
  ```

### Deployment fails
- Check GitHub Actions logs
- Verify all GitHub secrets are set correctly
- Ensure VMs completed startup scripts

## Viewing Logs

### Application Logs (Cloud Logging)
```bash
# Staging logs
gcloud logging read "resource.type=gce_instance AND resource.labels.instance_id=financial-rise-staging-vm" --limit 50 --project=financial-rise-prod

# Production logs
gcloud logging read "resource.type=gce_instance AND resource.labels.instance_id=financial-rise-production-vm" --limit 50 --project=financial-rise-prod
```

### Or use the Cloud Console:
- https://console.cloud.google.com/logs

## Cost Management

### View Current Costs
- https://console.cloud.google.com/billing

### Set Budget Alerts
```bash
# Create a budget with email alerts at 50%, 90%, 100%
gcloud billing budgets create \
  --billing-account=<YOUR_BILLING_ACCOUNT_ID> \
  --display-name="Financial RISE Monthly Budget" \
  --budget-amount=150USD \
  --threshold-rule=percent=50 \
  --threshold-rule=percent=90 \
  --threshold-rule=percent=100
```

### Stop VMs to Save Money
```bash
# Stop staging VM (save ~$17/month)
gcloud compute instances stop financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod

# Start it again when needed
gcloud compute instances start financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod
```

## Next Steps After Deployment

1. **Set up custom domain** (optional)
   - Point your domain's A record to the static IP addresses
   - Configure SSL/TLS with Let's Encrypt or Cloud Load Balancer

2. **Set up monitoring and alerting**
   - Create uptime checks
   - Set up alert policies for CPU, memory, disk usage

3. **Configure database backups**
   - Cloud SQL has automated backups enabled by default
   - Test restore procedures

4. **Review security**
   - Enable Cloud Armor for DDoS protection
   - Review IAM permissions
   - Enable audit logging

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review the detailed plan: `plans/gcp-vm-deployment-plan.md`
3. Check GCP documentation: https://cloud.google.com/docs

---

**Ready to begin?** Start with Step 1: Install Google Cloud SDK
