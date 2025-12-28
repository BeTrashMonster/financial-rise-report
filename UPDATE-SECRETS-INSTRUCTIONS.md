# How to Update Secret Manager

Since you've already run the infrastructure setup, you now need to update the Secret Manager secrets with your latest environment variables (like adding SendGrid API key).

## Option 1: Using Git Bash (Recommended)

1. **Open Git Bash** (not PowerShell or CMD)

2. **Navigate to the project directory:**
   ```bash
   cd /c/Users/Admin/src
   ```

3. **Run the update script:**
   ```bash
   bash update-secrets.sh
   ```

This will update both staging and production secrets in one command.

## Option 2: Manual Commands (Git Bash)

```bash
# Update staging
gcloud secrets versions add financial-rise-staging-env --data-file=.env.staging --project=financial-rise-prod

# Update production
gcloud secrets versions add financial-rise-production-env --data-file=.env.production --project=financial-rise-prod
```

## Option 3: Using Google Cloud Console

1. Go to: https://console.cloud.google.com/security/secret-manager?project=financial-rise-prod

2. Click on `financial-rise-staging-env`

3. Click "NEW VERSION"

4. Click "Browse" and select `.env.staging`

5. Click "ADD NEW VERSION"

6. Repeat for `financial-rise-production-env` with `.env.production`

## Important Notes

### About Service Account Key

I noticed the setup script skipped creating the service account key due to organization policy. You have two options:

**Option A: Use Workload Identity Federation (Recommended)**

This is more secure and doesn't require downloading keys. Update `.github/workflows/deploy-gcp.yml` to use Workload Identity:

```yaml
- name: Authenticate to Google Cloud
  uses: google-github-actions/auth@v2
  with:
    workload_identity_provider: 'projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/github/providers/github'
    service_account: 'github-actions@financial-rise-prod.iam.gserviceaccount.com'
```

Setup instructions: https://github.com/google-github-actions/auth#workload-identity-federation

**Option B: Create Key Manually (if allowed)**

If your organization allows it:

```bash
gcloud iam service-accounts keys create github-actions-key.json \
    --iam-account=github-actions@financial-rise-prod.iam.gserviceaccount.com \
    --project=financial-rise-prod
```

Then encode it:
```powershell
.\encode-service-account-key.ps1
```

## Verifying Secrets Were Updated

```bash
# View staging secret (first 20 lines)
gcloud secrets versions access latest --secret=financial-rise-staging-env --project=financial-rise-prod | head -20

# View production secret (first 20 lines)
gcloud secrets versions access latest --secret=financial-rise-production-env --project=financial-rise-prod | head -20
```

## Next Steps After Updating Secrets

1. **If VMs are already deployed:**
   The VMs will pull the latest secrets on next deployment. To apply immediately:

   ```bash
   # SSH to staging VM
   gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --project=financial-rise-prod

   # Pull latest secret
   cd /opt/financial-rise
   gcloud secrets versions access latest --secret=financial-rise-staging-env > .env

   # Restart containers
   docker compose -f docker-compose.yml -f docker-compose.prod.yml restart
   ```

2. **For new deployment:**
   Just push to trigger the GitHub Actions workflow:
   ```bash
   git push origin main
   ```

## Troubleshooting

### "gcloud: command not found" in Git Bash

Add gcloud to your PATH in Git Bash:

```bash
# Add to ~/.bashrc
echo 'export PATH="/c/Program Files (x86)/Google/Cloud SDK/google-cloud-sdk/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Or find your gcloud installation:
```bash
# Windows - find where gcloud is installed
where gcloud
```

Then add that directory to your PATH.

### "Permission denied" when updating secrets

Make sure you're authenticated:
```bash
gcloud auth login
gcloud config set project financial-rise-prod
```

### Still Having Issues?

Use the Google Cloud Console (Option 3 above) - it's the most reliable method and doesn't require CLI tools.
