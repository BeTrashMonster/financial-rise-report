# GCP Deployment Error Logs & Lessons Learned

**Last Updated:** 2026-01-01
**Project:** Financial RISE Report - GCP Staging Deployment

---

## Summary of Issues Resolved

### 1. Volume Mount Issue (RESOLVED ✅)
**Problem:** Backend container couldn't find `/app/dist/main.js`
**Root Cause:** Docker Compose v3.8 merges volume arrays from base + override files. Development volumes (`./backend:/app`) were mounting empty directories over built files in production.
**Solution:** Stopped merging base file in production. Use only `docker-compose.prod.yml` (standalone).
**Commit:** `feb8306`, `bcd43b4`

### 2. DB_ENCRYPTION_KEY Missing (RESOLVED ✅)
**Problem:** Backend crash with "DB_ENCRYPTION_KEY environment variable is required"
**Root Cause:** Secret Manager env file not being loaded by docker-compose
**Solution:** Added `env_file: [".env"]` to backend service in docker-compose.prod.yml
**Commit:** `651d587`

### 3. DB_ENCRYPTION_KEY Invalid Format (RESOLVED ✅)
**Problem:** "DB_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)"
**Root Cause:** Placeholder string instead of proper hex-encoded key
**Solution:** Generated 32-byte hex key: `e0940e7c8aacdf19a470d085472fc75bcfe006c438ab1f0300f812365d19e5af`
**Command:** `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
**Secret Manager:** Updated to version 4
**Commit:** `72476bd`

### 4. Cloud SQL Connection Timeout (RESOLVED ✅)
**Problem:** `Error: connect ETIMEDOUT 34.71.154.167:5432`
**Root Cause:** Staging VM IP not authorized in Cloud SQL
**Solution:** Added VM IP `34.122.8.87` to Cloud SQL authorized networks (quick fix for staging)
**Command:** `gcloud sql instances patch financial-rise-staging --authorized-networks=34.122.8.87`
**Note:** Production should use Cloud SQL Auth Proxy or Private IP for better security

### 5. Preemptible VM Shutdown (RESOLVED ✅)
**Problem:** VM status `TERMINATED`, deployment failing on SSH
**Root Cause:** Preemptible VMs restart every 24 hours automatically
**Solution:** Manual `gcloud compute instances start financial-rise-staging-vm --zone=us-central1-a` before deployment
**Note:** Workflow now handles this gracefully with proper error messages

### 6. TypeORM RefreshToken Entity Index Error (RESOLVED ✅)
**Problem:** `TypeORMError: Index contains column that is missing in the entity (RefreshToken): user_id`
**Root Cause:** Class-level `@Index(['userId'])` decorator - TypeORM interprets array values as column names, not property names
**Failed Attempt 1:** Changed to `@Index(['user_id'])` - didn't work (commit `936d439`)
**Successful Fix:** Moved to property-level `@Index()` decorator on userId property (commit `15449e7`)
**Lesson:** Use property-level `@Index()` for single-column indexes, not class-level with arrays

### 7. TypeORM Migration Error (IDENTIFIED ⚠️)
**Problem:** Migration fails in production with "Cannot find module '/app/src/config/typeorm.config.ts'"
**Root Cause:** Workflow runs `npm run migration:run` which expects TypeScript files, but production image only has compiled JS in `/app/dist`
**Current Status:** Error suppressed by `|| echo 'Migrations completed or skipped'` in workflow
**Impact:** Migrations may not be running in production
**Solution Needed:** Create production-compatible migration script that uses compiled JS

### 8. JWT Environment Variable Name Mismatch (RESOLVED ✅)
**Problem:** Backend crash with "REFRESH_TOKEN_SECRET is required and must not be empty"
**Root Cause:** Backend's `SecretsValidationService` expects `TOKEN_SECRET` and `REFRESH_TOKEN_SECRET`, but environment provided `JWT_SECRET` and `JWT_REFRESH_SECRET`
**Solution:** Added backwards compatibility mapping in docker-compose.prod.yml to provide both naming conventions
**Commit:** `5291ecb`
```yaml
JWT_SECRET: ${JWT_SECRET}
JWT_REFRESH_SECRET: ${JWT_REFRESH_SECRET}
# Backwards compatibility
TOKEN_SECRET: ${JWT_SECRET}
REFRESH_TOKEN_SECRET: ${JWT_REFRESH_SECRET}
```

### 9. Node.js Crypto Polyfill Issue with @nestjs/schedule (IN PROGRESS 🔄)
**Problem:** `ReferenceError: crypto is not defined` in `@nestjs/schedule/dist/scheduler.orchestrator.js`
**Root Cause:** NestJS scheduler module trying to use `crypto` without importing it in production build
**Stack Trace:** Happens during module initialization when setting up cron jobs
**Current Status:** Backend crash-looping on startup
**Next Steps:**
- Option 1: Add crypto polyfill to main.ts bootstrap
- Option 2: Update @nestjs/schedule version
- Option 3: Remove scheduled tasks if not needed for MVP
- Option 4: Fix production build to properly bundle Node.js globals

---

## Current Deployment Status

**Latest Commit:** `5291ecb` (Fix environment variable names for JWT secrets)
**VM Status:** RUNNING (`34.122.8.87`)
**Cloud SQL:** Authorized network configured (public IP: `34.71.154.167`)
**Secret Manager:** Version 4 with correct DB_ENCRYPTION_KEY
**Health Check:** ❌ FAILING - Backend crash-looping due to crypto error
**Container Status:**
- Frontend: Up, health starting ✅
- Redis: Up, healthy ✅
- Backend: Restarting (exit code 1) ❌

**Next Steps:**
1. Fix crypto polyfill issue in @nestjs/schedule
2. Verify backend starts successfully
3. Test health endpoint at `http://34.122.8.87/api/v1/health`
4. Address migration error for proper database schema management

---

## Architecture Notes

**Docker Compose Strategy:**
- Development: Use `docker-compose.yml` with volume mounts for hot-reload
- Production: Use ONLY `docker-compose.prod.yml` (no file merging)
- Images: Built in CI/CD, pushed to Artifact Registry
- **Critical:** Never merge base + override files in production - causes volume inheritance issues

**Environment Variables:**
- Stored in GCP Secret Manager (`financial-rise-staging-env`)
- Pulled to VM as `.env` file during deployment
- Loaded via `env_file: [".env"]` in docker-compose.prod.yml
- Naming conventions must match backend expectations (TOKEN_SECRET, REFRESH_TOKEN_SECRET)

**Networking:**
- Frontend: nginx on ports 80/443
- Backend: Internal on port 4000 (proxied via nginx `/api` route)
- Redis: Internal on port 6379
- Cloud SQL: Public IP with authorized networks (temporary security compromise)

**Database:**
- Development: Local PostgreSQL in Docker
- Staging: Cloud SQL with public IP + authorized networks
- Production: Should use Cloud SQL with Private IP or Cloud SQL Auth Proxy

**VM Configuration:**
- Type: Preemptible (auto-restarts every 24 hours)
- Disk: 29GB total (monitor usage - hit 100% during deployment)
- Automatic cleanup: Images, volumes, networks pruned on each deployment

---

## Key Lessons Learned

### 1. Docker Compose File Merging
**Lesson:** Docker Compose v3.8 **merges** arrays (like `volumes`) from base + override files instead of replacing them. This caused production containers to inherit development volume mounts.
**Best Practice:** Use separate, standalone compose files for dev and prod. Don't use `-f` merging in production.

### 2. TypeORM Index Decorators
**Lesson:** Class-level `@Index(['columnName'])` expects database column names, not TypeScript property names. Property-level `@Index()` is simpler and less error-prone.
**Best Practice:** Use property-level decorators for single-column indexes.

### 3. Environment Variable Naming Consistency
**Lesson:** Backend code and environment configuration must use exact same variable names. Mismatch causes cryptic "required and must not be empty" errors.
**Best Practice:** Document expected environment variable names in backend validation service and ensure all configs match.

### 4. Secret Manager Version Management
**Lesson:** Secret Manager creates new versions when updated. Always verify with `gcloud secrets versions access latest` after updates.
**Best Practice:** Test changes locally with `.env.staging.fixed` before updating Secret Manager.

### 5. Cloud SQL Networking
**Lesson:** Public IP + authorized networks is quick but less secure. Private IP or Cloud SQL Auth Proxy is production-grade.
**Best Practice:** Use quick fix for staging, proper security for production.

### 6. Disk Space Management
**Lesson:** Docker images and volumes accumulate quickly. A 29GB disk hit 100% capacity after several deployments.
**Best Practice:** Aggressive cleanup in deployment workflow: `docker image prune -a -f`, `docker volume prune -f`, `docker network prune -f`.

### 7. Migration Scripts in Production
**Lesson:** TypeScript migration configs don't work in production builds. Production only has compiled JavaScript.
**Best Practice:** Create separate migration script that uses compiled JS or build migrations into dist folder.

### 8. Debugging Production Crashes
**Lesson:** `|| echo 'completed or skipped'` in workflows can hide critical errors. Monitor actual container logs, not just workflow output.
**Best Practice:** Check `docker logs <container>` to see real errors, not suppressed ones.

---

## Latest Deployment Logs

### Deploy to Staging VM (Commit: 5291ecb - JWT Secret Fix)

**Status:** ❌ FAILED - Backend crash-looping

**Error:**
```
ReferenceError: crypto is not defined
    at SchedulerOrchestrator.addCron (/app/node_modules/@nestjs/schedule/dist/scheduler.orchestrator.js:90:38)
    at ScheduleExplorer.lookupSchedulers (/app/node_modules/@nestjs/schedule/dist/schedule.explorer.js:67:51)
```

**Container Status (line 1167-1170):**
- Frontend: Up 22s, health starting ✅
- Redis: Up 22s, healthy ✅
- Backend: Restarting (exit code 1) ❌

**Analysis:** NestJS schedule module initialization failing because `crypto` is not defined in production build context.

---

## Quick Reference Commands

**Check backend logs:**
```bash
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --tunnel-through-iap --command="docker logs --tail 50 financial-rise-backend-prod 2>&1"
```

**Check container status:**
```bash
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --tunnel-through-iap --command="docker ps"
```

**Update Secret Manager:**
```bash
gcloud secrets versions add financial-rise-staging-env --data-file=.env.staging.fixed --project=financial-rise-prod
```

**Manual VM start (after preemptible shutdown):**
```bash
gcloud compute instances start financial-rise-staging-vm --zone=us-central1-a
```

**Health check:**
```bash
curl http://34.122.8.87/api/v1/health
```

---

*End of Error Log*
