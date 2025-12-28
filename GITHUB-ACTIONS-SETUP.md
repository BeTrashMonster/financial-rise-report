# GitHub Actions Setup Guide - GCP Workload Identity Federation

This guide documents the required GitHub secrets configuration for the Financial RISE CI/CD pipeline using Google Cloud Platform (GCP) Workload Identity Federation.

## Overview

The Financial RISE project uses **Workload Identity Federation** to authenticate GitHub Actions to GCP without storing service account keys. This is more secure than using long-lived credentials and complies with organizational security policies.

## Prerequisites

1. GCP infrastructure must be set up (see `GCP-SETUP-QUICKSTART.md`)
2. Repository admin access to configure GitHub secrets
3. The Workload Identity Provider and Service Account must be created in GCP

## Architecture

```
GitHub Actions → Workload Identity Federation → Service Account → GCP Resources
```

The workflow uses `google-github-actions/auth@v2` with `workload_identity_provider` parameter instead of `credentials_json`. This allows GitHub Actions to exchange OIDC tokens for short-lived GCP credentials.

---

## Required GitHub Secrets

Configure these secrets in your GitHub repository settings:
**Settings → Secrets and variables → Actions → New repository secret**

### Core GCP Configuration

#### `GCP_PROJECT_ID`
- **Value:** `financial-rise-prod`
- **Description:** The GCP project ID where all resources are deployed
- **Usage:** Used throughout the workflow to reference the correct project

#### `GCP_WORKLOAD_IDENTITY_PROVIDER`
- **Value:** `projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider`
- **Description:** The full resource name of the Workload Identity Provider
- **Format:** `projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_NAME/providers/PROVIDER_NAME`
- **Usage:** Authenticates GitHub Actions via OIDC token exchange

#### `GCP_SERVICE_ACCOUNT`
- **Value:** `github-actions@financial-rise-prod.iam.gserviceaccount.com`
- **Description:** The service account that GitHub Actions will impersonate
- **Permissions:** This service account has the following roles:
  - `roles/compute.admin` - Manage VMs and deployments
  - `roles/artifactregistry.writer` - Push Docker images
  - `roles/storage.admin` - Access Cloud Storage buckets
  - `roles/secretmanager.secretAccessor` - Read secrets
  - `roles/cloudsql.client` - Connect to Cloud SQL

#### `GCP_REGION`
- **Value:** `us-central1`
- **Description:** Primary GCP region for all resources
- **Usage:** Used for regional resources like Artifact Registry and static IPs

### Artifact Registry Configuration

#### `ARTIFACT_REGISTRY_REPO`
- **Value:** `financial-rise-docker`
- **Description:** Name of the Artifact Registry repository for Docker images
- **Usage:** Docker images are pushed to `us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker/`

### Staging Environment

#### `STAGING_VM_NAME`
- **Value:** `financial-rise-staging-vm`
- **Description:** Name of the staging Compute Engine VM
- **Usage:** Used in `gcloud compute ssh` and `gcloud compute scp` commands

#### `STAGING_VM_ZONE`
- **Value:** `us-central1-a`
- **Description:** GCP zone where the staging VM is located
- **Usage:** Required for all compute operations on the staging VM

### Production Environment

#### `PRODUCTION_VM_NAME`
- **Value:** `financial-rise-production-vm`
- **Description:** Name of the production Compute Engine VM
- **Usage:** Used in `gcloud compute ssh` and `gcloud compute scp` commands

#### `PRODUCTION_VM_ZONE`
- **Value:** `us-central1-a`
- **Description:** GCP zone where the production VM is located
- **Usage:** Required for all compute operations on the production VM

---

## Quick Setup Commands

You can configure these secrets using the GitHub CLI:

```bash
# Install GitHub CLI if needed
# https://cli.github.com/

# Login to GitHub
gh auth login

# Navigate to your repository
cd /path/to/financial-rise

# Set all required secrets
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

---

## Workflow Overview

The CI/CD pipeline (`.github/workflows/deploy-gcp.yml`) consists of:

### 1. Backend Tests (`backend-test`)
- Runs on every push and PR
- Sets up PostgreSQL service container
- Executes linting, unit tests, and coverage reporting
- Uploads coverage to Codecov

### 2. Frontend Tests (`frontend-test`)
- Runs on every push and PR
- Executes linting, type checking, and tests
- Builds the frontend application
- Uploads coverage to Codecov

### 3. Build and Push (`build-and-push`)
- Runs only on `main` branch pushes
- **Uses Workload Identity Federation for authentication**
- Builds Docker images for backend and frontend
- Tags with commit SHA and `latest`
- Pushes to Artifact Registry

### 4. Deploy to Staging (`deploy-staging`)
- Runs after successful build
- **Uses Workload Identity Federation for authentication**
- Copies deployment files to staging VM
- Pulls environment variables from Secret Manager
- Runs database migrations
- Deploys new containers
- Performs health checks
- Automatic rollback on failure

### 5. Deploy to Production (`deploy-production`)
- Requires manual approval (GitHub environment protection)
- **Uses Workload Identity Federation for authentication**
- Creates database backup before deployment
- Uploads backup to Cloud Storage
- Deploys with zero-downtime rolling restart
- Performs health checks
- Automatic rollback on failure

---

## Environment Protection Rules

To enable manual approval for production deployments:

1. Go to **Settings → Environments**
2. Create environment named `production`
3. Enable **Required reviewers**
4. Add authorized users/teams who can approve deployments
5. (Optional) Add wait timer for additional safety

The `staging` environment can be configured similarly if you want approval for staging deployments.

---

## Workload Identity Federation Details

### How It Works

1. GitHub Actions workflow requests an OIDC token from GitHub
2. Token includes claims about the repository, branch, and workflow
3. GCP validates the token against the Workload Identity Provider configuration
4. If valid, GCP issues short-lived credentials for the service account
5. Credentials are used for the duration of the workflow job

### Security Benefits

- No long-lived credentials stored in GitHub secrets
- Automatic credential rotation
- Fine-grained access control via service account permissions
- Audit trail in GCP Cloud Logging
- Complies with enterprise security policies

### Permissions Model

The `github-actions@financial-rise-prod.iam.gserviceaccount.com` service account has minimal permissions required for CI/CD:

```yaml
# Artifact Registry - Push Docker images
roles/artifactregistry.writer

# Compute Engine - Deploy to VMs
roles/compute.admin

# Cloud Storage - Access backups and reports
roles/storage.admin

# Secret Manager - Read environment variables
roles/secretmanager.secretAccessor

# Cloud SQL - Connect to databases
roles/cloudsql.client
```

### Troubleshooting

If authentication fails:

```bash
# Verify the Workload Identity Provider exists
gcloud iam workload-identity-pools providers describe github-provider \
  --project=financial-rise-prod \
  --location=global \
  --workload-identity-pool=github-actions-pool

# Check service account bindings
gcloud iam service-accounts get-iam-policy \
  github-actions@financial-rise-prod.iam.gserviceaccount.com

# View recent authentication attempts
gcloud logging read "resource.type=iam_workload_identity_pool" \
  --project=financial-rise-prod \
  --limit=10 \
  --format=json
```

---

## Verification

After configuring secrets, verify the setup:

### 1. Check Secrets Are Set

```bash
gh secret list
```

You should see all 9 secrets listed.

### 2. Trigger a Test Run

```bash
# Create a test commit to trigger the workflow
git commit --allow-empty -m "Test GitHub Actions workflow"
git push origin main
```

### 3. Monitor the Workflow

Go to **Actions** tab in GitHub and watch the workflow run. Check that:
- Backend and frontend tests pass
- Build and push succeeds with Workload Identity auth
- Staging deployment completes successfully
- Health checks pass

### 4. Verify Artifact Registry

```bash
# List images in Artifact Registry
gcloud artifacts docker images list \
  us-central1-docker.pkg.dev/financial-rise-prod/financial-rise-docker \
  --project=financial-rise-prod
```

You should see `backend` and `frontend` images with commit SHA tags.

---

## Common Issues

### Issue: "Workload Identity Provider not found"

**Solution:** Ensure `GCP_WORKLOAD_IDENTITY_PROVIDER` secret matches exactly:
```
projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/providers/github-provider
```

### Issue: "Permission denied"

**Solution:** Verify service account has required roles:
```bash
gcloud projects get-iam-policy financial-rise-prod \
  --flatten="bindings[].members" \
  --filter="bindings.members:github-actions@financial-rise-prod.iam.gserviceaccount.com"
```

### Issue: "Could not authenticate with Workload Identity Federation"

**Possible causes:**
1. Repository attribute conditions in Workload Identity Provider are too restrictive
2. Service account doesn't have `roles/iam.workloadIdentityUser` binding
3. Workflow is running from a fork (WIF doesn't work with forked repos for security)

**Fix binding:**
```bash
gcloud iam service-accounts add-iam-policy-binding \
  github-actions@financial-rise-prod.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/942538168394/locations/global/workloadIdentityPools/github-actions-pool/attribute.repository/YOUR_GITHUB_ORG/YOUR_REPO" \
  --project=financial-rise-prod
```

### Issue: "VM not found"

**Solution:** Verify VM names and zones match:
```bash
gcloud compute instances list --project=financial-rise-prod
```

---

## Additional Resources

- [GitHub Actions: Configuring OpenID Connect in Google Cloud Platform](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-google-cloud-platform)
- [GCP Workload Identity Federation Documentation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [google-github-actions/auth Documentation](https://github.com/google-github-actions/auth)

---

## Summary

The Financial RISE CI/CD pipeline uses Workload Identity Federation for secure, keyless authentication to GCP. After configuring the 9 required GitHub secrets, the workflow automatically:

1. Tests backend and frontend code
2. Builds and pushes Docker images
3. Deploys to staging with automatic rollback
4. Deploys to production (with manual approval) with automatic rollback

All authentication is handled securely through OIDC token exchange, with no long-lived credentials stored in GitHub.
