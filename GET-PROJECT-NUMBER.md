# Get Your GCP Project Number

The Workload Identity setup needs your GCP project **number** (not just the project ID).

## Quick Method - Cloud Console

1. Go to: **https://console.cloud.google.com/home/dashboard?project=financial-rise-prod**

2. Look at the **Project Info** card on the left side of the dashboard

3. You'll see:
   ```
   Project name: Financial RISE
   Project ID: financial-rise-prod
   Project number: 123456789012  ← This is what you need!
   ```

4. Copy the **Project number**

## Alternative - gcloud Command

If you have gcloud working in PowerShell or another terminal:

```bash
gcloud projects describe financial-rise-prod --format="value(projectNumber)"
```

## What to Do With It

Once you have the project number, you need to update TWO secrets in GitHub:

### 1. GCP_PROJECT_NUMBER
Just paste the number (e.g., `123456789012`)

### 2. GCP_WORKLOAD_IDENTITY_PROVIDER
Format:
```
projects/YOUR_PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
```

Example with project number `123456789012`:
```
projects/123456789012/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
```

## All GitHub Secrets You Need

Go to: **https://github.com/BeTrashMonster/financial-rise-report/settings/secrets/actions**

Add these 10 secrets:

| Secret Name | Value |
|-------------|-------|
| `GCP_PROJECT_ID` | `financial-rise-prod` |
| `GCP_PROJECT_NUMBER` | `YOUR_PROJECT_NUMBER` (get from console) |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/YOUR_PROJECT_NUMBER/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider` |
| `GCP_SERVICE_ACCOUNT` | `github-actions@financial-rise-prod.iam.gserviceaccount.com` |
| `GCP_REGION` | `us-central1` |
| `ARTIFACT_REGISTRY_REPO` | `financial-rise-docker` |
| `STAGING_VM_NAME` | `financial-rise-staging-vm` |
| `PRODUCTION_VM_NAME` | `financial-rise-production-vm` |
| `STAGING_VM_ZONE` | `us-central1-a` |
| `PRODUCTION_VM_ZONE` | `us-central1-a` |

## Verification

After adding all secrets, they should look like this in GitHub:

```
✓ GCP_PROJECT_ID
✓ GCP_PROJECT_NUMBER
✓ GCP_WORKLOAD_IDENTITY_PROVIDER
✓ GCP_SERVICE_ACCOUNT
✓ GCP_REGION
✓ ARTIFACT_REGISTRY_REPO
✓ STAGING_VM_NAME
✓ PRODUCTION_VM_NAME
✓ STAGING_VM_ZONE
✓ PRODUCTION_VM_ZONE
```

## Next Step

After adding all 10 secrets, commit and push the updated workflow:

```bash
git add .github/workflows/deploy-gcp.yml
git commit -m "Update GitHub Actions to use Workload Identity Federation"
git push origin main
```

This will trigger your first deployment!
