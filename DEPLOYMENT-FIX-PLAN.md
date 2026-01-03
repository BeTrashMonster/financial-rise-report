# Production Deployment Fix Plan

**Date:** 2026-01-02
**Status:** Ready to Execute
**Issue:** Docker Compose `.env` parsing error with escaped quotes

---

## Problem Summary

**Error:**
```
failed to read /opt/financial-rise/.env: line 12: unexpected character "+" in variable name "NRpc8sfc1zWS2lJCbyq+kA=\"\""
```

**Root Cause:**
- Secret Manager contains escaped quotes: `JWT_SECRET=\"value\"`
- Docker Compose `.env` parser requires clean quotes: `JWT_SECRET="value"`
- The `+`, `/`, and `=` characters in base64-encoded JWT secrets confuse the parser when quotes are malformed

**Why This Happened:**
Previous fix attempts using `awk` and `sed` likely created escaped quotes when trying to add quotes to unquoted values. The `create-production-secret.sh` script should have fixed this, but may not have been executed properly.

---

## Fix Instructions

### Step 1: Run Diagnostic and Fix Script

**In WSL (where you ran the 24-hour production setup):**

```bash
cd /mnt/c/Users/Admin/src
bash diagnose-and-fix-secrets.sh
```

**What This Does:**
1. ✅ Checks current Secret Manager version
2. ✅ Analyzes for formatting issues (escaped quotes, missing quotes)
3. ✅ Creates clean secret from scratch if needed
4. ✅ Updates Secret Manager with properly formatted secret
5. ✅ Starts staging VM (fixing the connectivity issue)
6. ✅ Verifies the fix

**Expected Output:**
```
✅ Secret format appears correct
```
OR
```
❌ FOUND ESCAPED QUOTES (\")
Creating CLEAN secret from scratch...
✅ Secret Manager updated!
```

---

### Step 2: Verify Secret Format

**The secret should look like this (with clean double quotes):**
```env
DATABASE_HOST="34.134.76.171"
DATABASE_PORT="5432"
JWT_SECRET="K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ=="
```

**NOT like this (with escaped quotes):**
```env
DATABASE_HOST=\"34.134.76.171\"
DATABASE_PORT=\"5432\"
JWT_SECRET=\"K7+X7LOckZ6pAmf1lEU+7hckdex6C16dF8jqqg5GgNboYkEPUc4WRwwLqQuLRbzb1Q1PtjaTmfbaipteA53zEQ==\"
```

---

### Step 3: Deploy to Production

**After the secret is fixed:**

```bash
cd /mnt/c/Users/Admin/src
git add -A
git commit -m "Fix: Clean secret format for Docker Compose .env parser"
git push origin main
```

**Monitor deployment:**
1. Go to: https://github.com/[your-repo]/actions
2. Watch the "Deploy to GCP" workflow
3. Check both staging and production deployments

---

### Step 4: Verify Deployment Success

**Staging Health Check:**
```bash
# Get staging IP
gcloud compute instances describe financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'

# Test health (replace <STAGING_IP> with output above)
curl http://<STAGING_IP>/api/v1/health
curl http://<STAGING_IP>/
```

**Production Health Check:**
```bash
# Production IP: 34.72.61.170
curl http://34.72.61.170/api/v1/health
curl http://34.72.61.170/
```

**Expected Response:**
```json
{"status":"ok","timestamp":"..."}
```

---

## Alternative: Manual Secret Verification

If the diagnostic script doesn't work, manually verify the secret:

```bash
# View current secret
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod | head -20

# Check for escaped quotes
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod | grep '\\"'

# If you see \" (backslash-quote), the secret is malformed
```

**Manual fix:**
```bash
# Create clean secret
bash create-production-secret.sh

# Verify it worked
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod | grep "JWT_REFRESH_SECRET"

# Should show: JWT_REFRESH_SECRET="nKqbXDP7..." (clean quotes)
```

---

## Troubleshooting

### If Deployment Still Fails

**Check 1: Verify workflow is using latest secret**
- Workflow uses: `gcloud secrets versions access latest`
- Should automatically get newest version
- GitHub Actions may cache secrets (wait 5-10 minutes between deployments)

**Check 2: Manually inspect .env on VM**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="cat /opt/financial-rise/.env | head -15"
```

Look for escaped quotes in the output.

**Check 3: Test docker-compose locally on VM**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod

# On VM:
cd /opt/financial-rise
docker compose -f docker-compose.prod.yml config

# This will show if docker-compose can parse the .env file
# If it fails here, the .env format is wrong
```

### If Staging VM Still Has Connectivity Issues

```bash
# Start the VM
gcloud compute instances start financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod

# Wait 30 seconds for startup
sleep 30

# Check status
gcloud compute instances describe financial-rise-staging-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --format="value(status)"

# Should show: RUNNING
```

---

## Success Criteria

✅ Staging VM: RUNNING status
✅ Secret Manager: Clean quotes (no `\"`), version 4 or later
✅ Deployment: Both staging and production succeed
✅ Health checks: API returns `{"status":"ok"}`
✅ Frontend: Loads without errors

---

## Files Created

- `diagnose-and-fix-secrets.sh` - Main fix script (comprehensive)
- `create-production-secret.sh` - Alternative manual fix (already exists)
- `verify-and-fix-secrets.sh` - Verification script
- `fix-workflow-env-handling.sh` - Shows workflow modification option (not recommended, fix secret instead)

---

## Next Steps After Success

1. ✅ Update ERROR-LOGS.md with resolution
2. ✅ Document in PRODUCTION-QUICKSTART.md (if exists)
3. ✅ Clean up temporary fix scripts
4. ✅ Monitor production for 24 hours
5. ✅ Set up SSL/HTTPS with domain
6. ✅ Configure SendGrid for email notifications

---

## Questions?

- Secret format issue: Check Docker Compose .env file format documentation
- Staging VM preemptible: Consider upgrading to standard VM if frequent restarts are problematic
- GitHub Actions caching: Clear cache by creating empty commit if needed

**Ready to execute:** Run `bash diagnose-and-fix-secrets.sh` in WSL
