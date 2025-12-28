# Secrets Management Guide

**Version:** 1.0
**Date:** 2025-12-28
**Security Level:** CRITICAL
**Related Security Finding:** CRIT-001

---

## Table of Contents

1. [Overview](#overview)
2. [Security Architecture](#security-architecture)
3. [Local Development](#local-development)
4. [Production Deployment](#production-deployment)
5. [Secret Rotation](#secret-rotation)
6. [Troubleshooting](#troubleshooting)
7. [Security Best Practices](#security-best-practices)

---

## Overview

The Financial RISE backend implements **enterprise-grade secrets management** using:

- **GCP Secret Manager** for production secret storage
- **Automatic secret validation** on application startup
- **Zero-trust security model** - no secrets in version control
- **Secret rotation support** for 90-day rotation policy

### Required Secrets

| Secret Name | Purpose | Min Length (Dev) | Min Length (Prod) |
|-------------|---------|------------------|-------------------|
| `JWT_SECRET` | JWT access token signing | 32 chars (16 bytes) | 64 chars (32 bytes) |
| `REFRESH_TOKEN_SECRET` | Refresh token signing | 32 chars (16 bytes) | 64 chars (32 bytes) |
| `DATABASE_PASSWORD` | PostgreSQL authentication | No minimum | 16 chars minimum |

---

## Security Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Startup                       │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│              SecretsModule.onModuleInit()                    │
│  - Validates all secrets meet security requirements          │
│  - Prevents startup if secrets are weak or missing           │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│          SecretsValidationService.validateSecrets()          │
│  - Checks minimum length (32 dev, 64 prod)                   │
│  - Blocks default values (dev-jwt-secret...)                 │
│  - Ensures uniqueness between JWT & refresh secrets          │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────┐
│     Environment Check: Development vs Production?            │
└─────────┬──────────────────────────────────────┬────────────┘
          │ Development                          │ Production
          ▼                                      ▼
┌──────────────────────┐           ┌─────────────────────────┐
│  Load from .env.local │           │ GCP Secret Manager      │
│  (fallback only)      │           │ (REQUIRED)              │
│  - Validates strength │           │ - JWT_SECRET            │
│  - Never commit!      │           │ - REFRESH_TOKEN_SECRET  │
└──────────────────────┘           │ - DATABASE_PASSWORD     │
                                    └─────────────────────────┘
```

### Secret Validation Rules

The `SecretsValidationService` enforces these rules:

1. **Existence Check**: Secret must not be undefined or empty
2. **Length Check**:
   - Development: Minimum 32 characters
   - Production: Minimum 64 characters
3. **Default Value Check**: Blocks these known weak values:
   - `dev-jwt-secret-change-in-production`
   - `dev-refresh-secret-change-in-production`
   - `financial_rise_dev`
   - `password`, `secret`, `changeme`
4. **Uniqueness Check**: `JWT_SECRET` must differ from `REFRESH_TOKEN_SECRET`

---

## Local Development

### Initial Setup

1. **Copy the example environment file:**
   ```bash
   cd financial-rise-app/backend
   cp .env.auth.example .env.local
   ```

2. **Generate strong secrets:**
   ```bash
   # Generate JWT_SECRET (64 hex characters = 32 bytes)
   node -e "console.log('JWT_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"

   # Generate REFRESH_TOKEN_SECRET
   node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"

   # Generate DATABASE_PASSWORD
   node -e "console.log('DATABASE_PASSWORD=' + require('crypto').randomBytes(16).toString('base64'))"
   ```

3. **Update `.env.local`:**
   ```env
   # IMPORTANT: This file is git-ignored and must NEVER be committed

   # JWT Configuration
   JWT_SECRET=<paste-generated-secret-here>
   JWT_EXPIRY=15m
   REFRESH_TOKEN_SECRET=<paste-different-secret-here>
   REFRESH_TOKEN_EXPIRY=7d

   # Database
   DATABASE_HOST=localhost
   DATABASE_PORT=5432
   DATABASE_USER=financial_rise
   DATABASE_PASSWORD=<paste-generated-password-here>
   DATABASE_NAME=financial_rise_dev
   DATABASE_SSL=false

   # Application
   NODE_ENV=development
   PORT=3000
   FRONTEND_URL=http://localhost:5173
   ```

4. **Verify secrets are valid:**
   ```bash
   npm run start:dev
   ```

   You should see:
   ```
   [SecretsModule] Initializing in development mode
   ✅ Secret validation passed - All secrets meet security requirements
   ```

### Development Workflow

- `.env.local` is **git-ignored** - it will never be committed
- Each developer must generate their own secrets
- **NEVER share secrets** via Slack, email, or any insecure channel
- **NEVER commit** `.env.local` to version control

---

## Production Deployment

### Prerequisites

1. **GCP Secret Manager Setup:**
   ```bash
   # Enable Secret Manager API
   gcloud services enable secretmanager.googleapis.com

   # Set your GCP project ID
   export GCP_PROJECT_ID="financial-rise-production"
   ```

2. **Create Secrets in GCP:**
   ```bash
   # Generate and store JWT_SECRET
   JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
   echo -n "$JWT_SECRET" | gcloud secrets create JWT_SECRET \
     --replication-policy="automatic" \
     --data-file=-

   # Generate and store REFRESH_TOKEN_SECRET
   REFRESH_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
   echo -n "$REFRESH_SECRET" | gcloud secrets create REFRESH_TOKEN_SECRET \
     --replication-policy="automatic" \
     --data-file=-

   # Store DATABASE_PASSWORD (use your actual database password)
   echo -n "YOUR_ACTUAL_DB_PASSWORD" | gcloud secrets create DATABASE_PASSWORD \
     --replication-policy="automatic" \
     --data-file=-
   ```

3. **Grant Application Access:**
   ```bash
   # Get your service account email
   SA_EMAIL="financial-rise-backend@${GCP_PROJECT_ID}.iam.gserviceaccount.com"

   # Grant Secret Manager access
   gcloud projects add-iam-policy-binding $GCP_PROJECT_ID \
     --member="serviceAccount:${SA_EMAIL}" \
     --role="roles/secretmanager.secretAccessor"
   ```

### Environment Variables (Production)

Set these in your production environment (Cloud Run, GKE, etc.):

```env
NODE_ENV=production
GCP_PROJECT_ID=financial-rise-production
PORT=8080
FRONTEND_URL=https://financial-rise.com

# Secrets are loaded from Secret Manager - DO NOT set JWT_SECRET, etc. here
```

### Deployment Checklist

- [ ] All secrets created in GCP Secret Manager
- [ ] Service account has `secretmanager.secretAccessor` role
- [ ] `GCP_PROJECT_ID` environment variable set
- [ ] `NODE_ENV=production` environment variable set
- [ ] Application credentials configured (Workload Identity or service account key)
- [ ] Verified application starts without errors
- [ ] Checked logs for secret validation success

---

## Secret Rotation

### Why Rotate Secrets?

- **Security best practice**: Limit exposure window if a secret is compromised
- **Compliance requirement**: Many security frameworks require regular rotation
- **Recommended frequency**: Every 90 days

### Rotation Process

#### 1. Generate New Secret

```bash
# Generate new JWT_SECRET
NEW_JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
echo "New secret generated (not shown for security)"
```

#### 2. Add New Version in GCP Secret Manager

```bash
echo -n "$NEW_JWT_SECRET" | gcloud secrets versions add JWT_SECRET --data-file=-
```

#### 3. Verify New Version is Active

```bash
# Get latest version
gcloud secrets versions access latest --secret="JWT_SECRET"
```

#### 4. Restart Application

```bash
# Cloud Run
gcloud run services update financial-rise-backend --region=us-central1

# Kubernetes
kubectl rollout restart deployment/financial-rise-backend
```

#### 5. Verify Application Uses New Secret

Check application logs:
```
[SecretsModule] Initializing in production mode
✅ Secret validation passed - All secrets meet security requirements
```

#### 6. Disable Old Secret Version (After Grace Period)

Wait 24-48 hours to ensure all instances use the new secret, then:

```bash
# List versions
gcloud secrets versions list JWT_SECRET

# Disable old version (replace VERSION_NUMBER)
gcloud secrets versions disable VERSION_NUMBER --secret="JWT_SECRET"
```

### Automated Rotation (Optional)

Create a Cloud Scheduler job to rotate secrets automatically:

```bash
# Create rotation script
cat > rotate-jwt-secret.sh <<'EOF'
#!/bin/bash
NEW_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
echo -n "$NEW_SECRET" | gcloud secrets versions add JWT_SECRET --data-file=-
gcloud run services update financial-rise-backend --region=us-central1
EOF

chmod +x rotate-jwt-secret.sh

# Schedule rotation every 90 days
gcloud scheduler jobs create http rotate-jwt-secret \
  --schedule="0 0 1 */3 *" \
  --uri="https://YOUR_ROTATION_ENDPOINT" \
  --http-method=POST \
  --oidc-service-account-email="YOUR_SA_EMAIL"
```

---

## Troubleshooting

### Error: "JWT_SECRET is required and must not be empty"

**Cause**: Secret is not set in environment variables or Secret Manager

**Solution**:
```bash
# Development
echo "JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" >> .env.local

# Production
echo -n "$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" | \
  gcloud secrets create JWT_SECRET --replication-policy="automatic" --data-file=-
```

### Error: "JWT_SECRET must be at least 64 characters"

**Cause**: Production secret is too short

**Solution**:
```bash
# Generate 64-character secret (32 bytes in hex)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Output: 64 hexadecimal characters
```

### Error: "Default JWT_SECRET detected"

**Cause**: Using the default development secret in production

**Solution**: Generate a new unique secret (see above)

### Error: "Failed to retrieve secret JWT_SECRET"

**Cause**: Secret doesn't exist in GCP or permissions are missing

**Solution**:
```bash
# Check if secret exists
gcloud secrets describe JWT_SECRET

# If not found, create it
echo -n "$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")" | \
  gcloud secrets create JWT_SECRET --replication-policy="automatic" --data-file=-

# Check permissions
gcloud secrets get-iam-policy JWT_SECRET
```

### Error: "GCP_PROJECT_ID is required in production"

**Cause**: Missing project ID environment variable

**Solution**:
```bash
# Set environment variable
export GCP_PROJECT_ID="your-project-id"

# Or in Cloud Run
gcloud run services update financial-rise-backend \
  --set-env-vars GCP_PROJECT_ID=your-project-id
```

---

## Security Best Practices

### DO

✅ **Generate cryptographically secure random secrets:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

✅ **Use different secrets for JWT and refresh tokens**

✅ **Rotate secrets every 90 days**

✅ **Use GCP Secret Manager in production**

✅ **Validate secrets on application startup**

✅ **Set minimum length: 64 characters in production**

✅ **Use Workload Identity instead of service account keys**

✅ **Monitor Secret Manager audit logs:**
```bash
gcloud logging read "resource.type=secretmanager.googleapis.com/Secret"
```

### DO NOT

❌ **Never commit `.env.local` to git**

❌ **Never use default secrets (`dev-jwt-secret-change-in-production`)**

❌ **Never share secrets via email, Slack, or insecure channels**

❌ **Never log secret values** (even in development)

❌ **Never use the same secret for multiple purposes**

❌ **Never store secrets in code or configuration files**

❌ **Never use weak passwords (`password123`, `secret`)**

---

## Audit & Compliance

### Security Audit Checklist

- [ ] No secrets in git history
- [ ] All secrets meet minimum length requirements
- [ ] Secret validation runs on every application startup
- [ ] Secrets stored in GCP Secret Manager (production)
- [ ] Service account has least-privilege access
- [ ] Secrets rotated within 90 days
- [ ] Audit logging enabled for Secret Manager access

### Scan for Hardcoded Secrets

```bash
# Scan codebase for common secret patterns
cd financial-rise-app/backend
grep -r "dev-jwt-secret" src/ || echo "✅ No default secrets found"
grep -r "financial_rise_dev" src/ || echo "✅ No default passwords found"
grep -r "secret.*=.*['\"]" src/ --include="*.ts" | grep -v "spec.ts" || echo "✅ No hardcoded secrets"

# Check git history
git log --all -p --grep="JWT_SECRET" --grep="PASSWORD" --grep="secret"
```

### GDPR/CCPA Compliance

- **Data Classification**: JWT secrets are Tier 1 (highest sensitivity)
- **Encryption**: All secrets encrypted at rest in GCP Secret Manager
- **Access Control**: Role-based access with audit logging
- **Retention**: Disabled secret versions retained for 30 days (configurable)
- **Breach Notification**: Rotate all secrets immediately if compromised

---

## References

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GCP Secret Manager Documentation](https://cloud.google.com/secret-manager/docs)
- [NIST SP 800-57: Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- Security Audit Report: `SECURITY-AUDIT-REPORT.md` (Finding CRIT-001)

---

**Document Version:** 1.0
**Last Updated:** 2025-12-28
**Next Review:** 2026-03-28 (90 days)
**Owner:** Security Team
**Approver:** Technical Lead
