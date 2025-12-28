# GitHub Secrets Quick Reference

## Required Secrets for GCP CI/CD Pipeline

Configure these in **GitHub Repository Settings → Secrets and variables → Actions**

| Secret Name | Value | Description |
|------------|-------|-------------|
| `GCP_PROJECT_ID` | `financial-rise-prod` | GCP project ID |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider` | Workload Identity Provider resource name |
| `GCP_SERVICE_ACCOUNT` | `github-actions@financial-rise-prod.iam.gserviceaccount.com` | Service account for GitHub Actions |
| `GCP_REGION` | `us-central1` | Primary GCP region |
| `ARTIFACT_REGISTRY_REPO` | `financial-rise-docker` | Docker image repository name |
| `STAGING_VM_NAME` | `financial-rise-staging-vm` | Staging VM instance name |
| `STAGING_VM_ZONE` | `us-central1-a` | Staging VM zone |
| `PRODUCTION_VM_NAME` | `financial-rise-production-vm` | Production VM instance name |
| `PRODUCTION_VM_ZONE` | `us-central1-a` | Production VM zone |

## GitHub CLI Quick Setup

```bash
gh secret set GCP_PROJECT_ID -b "financial-rise-prod"
gh secret set GCP_WORKLOAD_IDENTITY_PROVIDER -b "projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider"
gh secret set GCP_SERVICE_ACCOUNT -b "github-actions@financial-rise-prod.iam.gserviceaccount.com"
gh secret set GCP_REGION -b "us-central1"
gh secret set ARTIFACT_REGISTRY_REPO -b "financial-rise-docker"
gh secret set STAGING_VM_NAME -b "financial-rise-staging-vm"
gh secret set STAGING_VM_ZONE -b "us-central1-a"
gh secret set PRODUCTION_VM_NAME -b "financial-rise-production-vm"
gh secret set PRODUCTION_VM_ZONE -b "us-central1-a"
```

## Manual Configuration (GitHub Web UI)

1. Navigate to your repository on GitHub
2. Go to **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Enter the name and value from the table above
5. Click **Add secret**
6. Repeat for all 9 secrets

## Verification

After configuration, verify all secrets are set:

```bash
gh secret list
```

Expected output:
```
GCP_PROJECT_ID                      Updated YYYY-MM-DD
GCP_WORKLOAD_IDENTITY_PROVIDER      Updated YYYY-MM-DD
GCP_SERVICE_ACCOUNT                 Updated YYYY-MM-DD
GCP_REGION                          Updated YYYY-MM-DD
ARTIFACT_REGISTRY_REPO              Updated YYYY-MM-DD
STAGING_VM_NAME                     Updated YYYY-MM-DD
STAGING_VM_ZONE                     Updated YYYY-MM-DD
PRODUCTION_VM_NAME                  Updated YYYY-MM-DD
PRODUCTION_VM_ZONE                  Updated YYYY-MM-DD
```

## Security Notes

- These secrets are stored encrypted in GitHub
- Only used during GitHub Actions workflow execution
- Never logged or exposed in workflow output
- Uses Workload Identity Federation (no service account keys)
- Short-lived credentials obtained via OIDC token exchange

For detailed setup instructions, see: **GITHUB-ACTIONS-SETUP.md**
