# GCP Deployment Error Logs & Lessons Learned

**Last Updated:** 2026-01-02
**Project:** Financial RISE Report - Production Deployment
**Status:** Production Infrastructure Complete ✅

---

## Current Deployment Status

**Production Infrastructure:**
- **VM:** `financial-rise-production-vm` (34.72.61.170)
- **Cloud SQL:** PostgreSQL 14 with Private IP (ZONAL)
- **Secret Manager:** Version 3 (malformed - workflow aggressively cleans on deploy)
- **Latest Commit:** `550eca8` - Aggressive .env cleaning for production
- **Deployment:** Testing production deployment (staging ✅ working)

**Infrastructure Cost:** $103/month (budget optimized)

**Deployment Status:**
- ✅ **Staging:** Working (commit 75be3ad)
- 🔄 **Production:** Testing aggressive cleaning approach (commit 550eca8)

---

## Recent Issues & Resolutions

### 11. Staging VM Connectivity + .env Parsing (RESOLVED ✅)
**Date:** 2026-01-02

**Problem 1:** Error 4003: 'failed to connect to backend' when SSH to staging VM
**Root Cause 1:** Preemptible staging VM shuts down after 24 hours, status = TERMINATED
**Solution 1:** Modified workflow to check VM status and auto-start before SSH attempts
**Commit:** `75be3ad` - Added "Ensure staging VM is running" step
**Status:** ✅ Staging deployment working

**Problem 2:** `failed to read .env: line 12: unexpected character "+" in variable name "NRpc8sfc1zWS2lJCbyq+kA=\"\""`
**Root Cause 2:** Secret Manager contains inconsistent formatting (some lines clean, some with escaped quotes)
**Solution 2 (Staging):** Basic sed cleaning worked
```bash
sed -i 's/\\\"/\"/g' .env  # Remove escaped quotes
sed -i '/^$/d' .env         # Remove blank lines
```
**Status:** ✅ Staging working with basic cleaning

**Solution 2 (Production):** Aggressive cleaning needed due to worse formatting
```bash
# Strip ALL backslashes and quotes, then re-add clean quotes
sed 's/\\//g' .env.raw | sed 's/\"//g' | sed '/^$/d' > .env.stripped
awk -F= '/^[^#]/ && NF==2 {print $1"=\""$2"\""} /^#/ {print}' .env.stripped > .env
```
**Commit:** `550eca8` - Aggressive .env cleaning for production
**Status:** Testing production deployment

**Lesson:** Production Secret Manager needs to be rebuilt from scratch with clean formatting (future task)

### 10. Docker Compose .env Parsing Error (ATTEMPTED FIX ⚠️)
**Date:** 2026-01-02
**Problem:** `failed to read .env: line 12: unexpected character "+" in variable name`
**Root Cause:** Base64-encoded secrets (JWT tokens) contain special characters (`+`, `/`, `=`) that Docker Compose's `.env` parser can't handle
**Attempted Fix:** Multiple scripts to fix Secret Manager formatting (versions 2 and 3)
**Result:** Secret Manager still contains escaped quotes after multiple fix attempts
**Workaround:** Workflow now cleans .env file after pulling (issue #11)
**Lesson:** Always quote environment variable values, but use clean quotes `="..."` not escaped `=\"...\"`

---

## Key Lessons Learned (Historical)

### 1. Docker Compose File Merging
**Lesson:** Docker Compose v3.8 **merges** arrays (like `volumes`) from base + override files instead of replacing them.
**Best Practice:** Use separate, standalone compose files for dev and prod. Don't merge files in production.

### 2. TypeORM Index Decorators
**Lesson:** Class-level `@Index(['columnName'])` expects database column names, not TypeScript property names.
**Best Practice:** Use property-level `@Index()` decorators for single-column indexes.

### 3. Environment Variable Naming Consistency
**Lesson:** Backend validation must match environment variable names exactly.
**Best Practice:** Provide backwards compatibility mappings (e.g., both `JWT_SECRET` and `TOKEN_SECRET`).

### 4. Secret Manager Version Management
**Lesson:** Secret Manager creates new versions when updated. Always verify latest version after updates.
**Best Practice:** Use `gcloud secrets versions access latest` to verify changes deployed correctly.

### 5. Cloud SQL Networking
**Lesson:** Public IP + authorized networks works for staging but is less secure.
**Best Practice:** Production uses Private IP via VPC peering for security.

### 6. Disk Space Management
**Lesson:** Docker images and volumes accumulate quickly on VMs.
**Best Practice:** Aggressive cleanup in deployment workflow: `docker image prune -a -f && docker volume prune -f`.

### 7. Base64 Secrets in .env Files
**Lesson:** Base64-encoded values with `+`, `/`, or `=` break Docker Compose's `.env` parser.
**Best Practice:** Always quote values in `.env` files, especially base64-encoded secrets.

### 8. Preemptible VM Limitations
**Lesson:** Preemptible VMs restart every 24 hours, causing deployment failures.
**Best Practice:** Use standard VMs for production, preemptible only for development/staging.

### 9. Migration Scripts in Production
**Lesson:** TypeScript migration configs don't work in production builds (only compiled JS exists).
**Best Practice:** Migrations handled via `npm run migration:run` in running backend container.

---

## Production Infrastructure Setup

**Completed Phases:**
1. ✅ Cloud SQL with Private IP (ZONAL - cost optimized)
2. ✅ Standard Production VM (e2-standard-2, non-preemptible)
3. ✅ SSL/HTTPS Certificates (configured)
4. ✅ Production Secret Manager (all credentials secure)
5. ✅ Monitoring & Alerting (email notifications)
6. ✅ Database Backup Strategy (daily + weekly off-site)
7. ✅ GitHub Secrets Configuration (CI/CD ready)

**Total Setup Time:** ~24 hours
**Monthly Cost:** $103 (under $118 budget)

---

## Quick Reference Commands

### Production VM

**SSH into production:**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod
```

**Check container status:**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker ps"
```

**Check backend logs:**
```bash
gcloud compute ssh financial-rise-production-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker logs financial-rise-backend-prod --tail 50"
```

### Secret Manager

**View current secret:**
```bash
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod | head -20
```

**Update secret:**
```bash
gcloud secrets versions add financial-rise-production-env \
  --data-file=.env.production \
  --project=financial-rise-prod
```

### Health Checks

**API health:**
```bash
curl http://34.72.61.170/api/v1/health
```

**Frontend:**
```bash
curl -I http://34.72.61.170/
```

### Monitoring

**View logs:**
```
https://console.cloud.google.com/logs?project=financial-rise-prod
```

**Monitoring dashboard:**
```
https://console.cloud.google.com/monitoring?project=financial-rise-prod
```

---

## Historical Issues (All Resolved)

**Issues 1-9 (2025-12-31 to 2026-01-01):**
- Volume mount conflicts
- DB_ENCRYPTION_KEY format
- Cloud SQL connection timeouts
- Preemptible VM shutdowns
- TypeORM index errors
- JWT environment variable naming
- Node.js crypto polyfill
- Frontend health check endpoints

**All historical issues documented in git history and Senior Developer Checklist.**

---

*Production deployment in progress - awaiting health check results*
