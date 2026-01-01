# Staging Verification Checklist

**Before Production Deployment - Run All Checks**
**Last Updated:** 2026-01-01

---

## ✅ Quick Status

- **Staging IP:** `34.122.8.87`
- **Health Endpoint:** http://34.122.8.87/api/v1/health
- **Cloud SQL:** `34.71.154.167:5432` (financial_rise_staging)
- **Latest Commit:** `c734576` (Crypto polyfill fix)

---

## 1. ✅ Health Check (CRITICAL)

**Status:** ✅ PASSING

```bash
curl http://34.122.8.87/api/v1/health
```

**Expected Response:**
```json
{"status":"ok","timestamp":"2026-01-01T21:19:58.484Z","service":"financial-rise-api"}
```

**✅ VERIFIED:** Backend is responding successfully

---

## 2. Container Status (CRITICAL)

**Check all containers are running and healthy:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker ps"
```

**Expected Output:**
- `financial-rise-frontend-prod` - Up, healthy
- `financial-rise-backend-prod` - Up, running (not restarting)
- `financial-rise-redis-prod` - Up, healthy

**What to Check:**
- ❌ Backend should NOT say "Restarting"
- ❌ Backend should NOT show recent crash timestamp
- ✅ All containers should show "Up XX seconds/minutes"

---

## 3. Backend Logs Review (CRITICAL)

**Check for startup errors:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker logs --tail 50 financial-rise-backend-prod 2>&1"
```

**What to Look For:**

✅ **Good Signs:**
- `[NestFactory] Starting Nest application...`
- `Nest application successfully started`
- `🚀 Financial RISE API running on port 4000`
- `🛡️ CSRF Protection: ENABLED`
- `[InstanceLoader] * dependencies initialized`

❌ **Bad Signs:**
- `Error:` or `ReferenceError:` or `TypeError:`
- `ECONNREFUSED` (database connection failed)
- `Cannot find module`
- Container restarting repeatedly

---

## 4. Environment Variables (CRITICAL)

**Verify all critical env vars are loaded:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker exec financial-rise-backend-prod env | grep -E '^(NODE_ENV|DATABASE_HOST|JWT_SECRET|TOKEN_SECRET|REFRESH_TOKEN_SECRET|DB_ENCRYPTION_KEY|GCS_BUCKET|FRONTEND_URL)'"
```

**Required Variables:**
- ✅ `NODE_ENV=staging`
- ✅ `DATABASE_HOST=34.71.154.167`
- ✅ `DATABASE_NAME=financial_rise_staging`
- ✅ `JWT_SECRET` (should be set, value doesn't matter here)
- ✅ `TOKEN_SECRET` (should be set)
- ✅ `REFRESH_TOKEN_SECRET` (should be set)
- ✅ `DB_ENCRYPTION_KEY` (should be 64 hex characters)
- ✅ `GCS_BUCKET=financial-rise-reports-staging`
- ✅ `FRONTEND_URL=http://34.122.8.87`

**If any are missing:** Update `.env.staging.fixed` and Secret Manager

---

## 5. Database Connectivity (CRITICAL)

**Test database connection:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker exec financial-rise-backend-prod sh -c 'echo SELECT 1 | nc 34.71.154.167 5432' 2>&1 | head -1"
```

**Or check backend logs for:**
- ✅ `[TypeOrmModule] TypeOrmCoreModule dependencies initialized`
- ❌ `Error: connect ETIMEDOUT`

**Cloud SQL Instance Check:**

```bash
gcloud sql instances describe financial-rise-staging \
  --format="value(state,ipAddresses[0].ipAddress)"
```

**Expected:** `RUNNABLE 34.71.154.167`

---

## 6. Database Migrations (HIGH PRIORITY)

**Known Issue:** Migrations may not be running in production (see ERROR-LOGS.md #7)

**Check migration status:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker exec financial-rise-backend-prod sh -c 'cd /app && npm run typeorm migration:show || echo Migration check failed'"
```

**What This Checks:**
- Whether migrations have run
- Which migrations are pending

**⚠️ Known Issue:** Migration command expects TypeScript files but production has only compiled JS

**Workaround for Production:**
- Run migrations manually from development environment against production database
- OR: Fix migration script to use compiled JS (see ERROR-LOGS.md)

---

## 7. Frontend Nginx (IMPORTANT)

**Test frontend is accessible:**

```bash
curl -I http://34.122.8.87/
```

**Expected:** `HTTP/1.1 200 OK`

**Test nginx -> backend proxy:**

```bash
curl http://34.122.8.87/api/v1/health
```

**Expected:** Same response as direct backend health check

**What This Tests:**
- Frontend nginx is serving correctly
- Nginx reverse proxy to backend is working
- `/api` route is properly configured

---

## 8. Redis Connectivity (IMPORTANT)

**Test Redis is running:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker exec financial-rise-redis-prod redis-cli ping"
```

**Expected:** `PONG`

**Check Redis health:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker inspect financial-rise-redis-prod --format='{{.State.Health.Status}}'"
```

**Expected:** `healthy`

---

## 9. Disk Space (IMPORTANT)

**Check VM disk usage:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="df -h /dev/root"
```

**Warning Thresholds:**
- ⚠️ **>70% used** - Monitor closely
- ❌ **>85% used** - Run cleanup before next deployment
- 🚨 **>95% used** - URGENT cleanup needed

**If high disk usage, run cleanup:**

```bash
gcloud compute ssh financial-rise-staging-vm \
  --zone=us-central1-a \
  --tunnel-through-iap \
  --command="docker image prune -a -f && docker volume prune -f"
```

---

## 10. Security Headers (OPTIONAL)

**Test security headers are present:**

```bash
curl -I http://34.122.8.87/api/v1/health | grep -E "(X-Frame-Options|X-Content-Type|Strict-Transport)"
```

**Expected Headers:**
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security` (if HTTPS is configured)

---

## 11. CORS Configuration (OPTIONAL)

**Test CORS headers:**

```bash
curl -X OPTIONS -I http://34.122.8.87/api/v1/health \
  -H "Origin: http://34.122.8.87" \
  -H "Access-Control-Request-Method: GET"
```

**Expected:**
- `Access-Control-Allow-Origin: http://34.122.8.87`
- `Access-Control-Allow-Methods: GET,POST,PUT,DELETE,PATCH`

---

## 12. CSRF Protection (OPTIONAL - If Endpoint Exists)

**Test CSRF token endpoint:**

```bash
curl http://34.122.8.87/api/v1/auth/csrf-token
```

**Expected (if implemented):**
```json
{"csrfToken":"..."}
```

**Note:** CSRF may not be fully implemented in MVP - check requirements

---

## Known Issues & Limitations

### Staging Environment

✅ **Acceptable for Staging:**
1. Cloud SQL using public IP + authorized networks (vs Private IP)
2. Preemptible VM (restarts every 24h)
3. No SSL/HTTPS (HTTP only)
4. Smaller VM resources (e2-medium)
5. Single instance (no high availability)

❌ **NOT Acceptable for Production:**
- All of the above staging limitations must be fixed for production

### Outstanding Issues

From ERROR-LOGS.md:

1. **TypeORM Migration Error (⚠️ HIGH)**
   - Migrations may not be running
   - Suppressed by `|| echo 'completed or skipped'` in workflow
   - Solution: Create production migration script or run manually

2. **Cloud SQL Security (⚠️ MEDIUM for staging, HIGH for production)**
   - Currently using public IP + authorized networks
   - Production should use Cloud SQL Auth Proxy or Private IP

3. **Preemptible VM (⚠️ LOW for staging, HIGH for production)**
   - VM restarts every 24 hours
   - Production needs standard VM with proper uptime

---

## Pre-Production Checklist

Before deploying to production, ensure:

### Critical Fixes
- [ ] Fix TypeORM migration script for production
- [ ] Configure Cloud SQL Private IP or Auth Proxy
- [ ] Switch to standard (non-preemptible) VM
- [ ] Set up SSL/HTTPS with Let's Encrypt
- [ ] Configure proper production environment variables
- [ ] Set up production Secret Manager
- [ ] Configure production GCS bucket
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategy for database
- [ ] Test disaster recovery procedures

### Production Environment
- [ ] Production VM created and configured
- [ ] Production Cloud SQL instance created
- [ ] Production database initialized with schema
- [ ] Production DNS configured (if applicable)
- [ ] Production GitHub environment created with approvals
- [ ] Production secrets configured in GitHub Actions

### Testing
- [ ] All staging checks above pass
- [ ] Load testing completed
- [ ] Security scan completed
- [ ] Backup and restore tested
- [ ] Rollback procedure tested

---

## Quick Verification Commands

**Run all checks in sequence:**

```bash
# 1. Health check
curl http://34.122.8.87/api/v1/health

# 2. Container status
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --tunnel-through-iap --command="docker ps"

# 3. Backend logs
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --tunnel-through-iap --command="docker logs --tail 30 financial-rise-backend-prod"

# 4. Disk space
gcloud compute ssh financial-rise-staging-vm --zone=us-central1-a --tunnel-through-iap --command="df -h /dev/root"

# 5. Frontend test
curl -I http://34.122.8.87/
```

---

## Summary

### ✅ READY FOR PRODUCTION IF:
1. Health check returns `{"status":"ok"}`
2. All containers running (not restarting)
3. Backend logs show successful startup
4. No errors in last 50 log lines
5. Frontend accessible via HTTP
6. Nginx proxy working
7. Disk space < 70%

### ❌ DO NOT DEPLOY TO PRODUCTION IF:
1. Backend is crash-looping
2. Health check failing
3. Database connection errors
4. Environment variables missing
5. Migrations have not run
6. Disk space > 85%

---

*Last Updated: 2026-01-01*
*Review after each staging deployment*
