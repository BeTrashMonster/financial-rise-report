# Financial RISE Report - Error Logs & Lessons Learned

**Last Updated:** 2026-01-04
**Project:** Financial RISE Report - Production Deployment
**Status:** Production Live ✅

---

## Current Production Status

**Live Site:** https://getoffthemoneyshametrain.com
**Production VM:** `financial-rise-prod-vm` (34.72.61.170)
**Cloud SQL:** PostgreSQL 14 with Private IP (ZONAL)
**HTTPS:** Caddy automatic SSL with Let's Encrypt
**Monthly Cost:** $103 (budget optimized)

**Latest Commits:**
- `a2d1a7c` - Fix all remaining userId to id references in test files (2026-01-04) ✅ ALL TESTS PASSING
- `6f63646` - Complete userId to id migration across all services and tests (2026-01-04)
- `35e0e2d` - Fix users-processing-restriction tests (2026-01-04)
- `7d20212` - Fix JWT user object to use 'id' instead of 'userId' (2026-01-04)
- `33b058f` - Fix CSRF interceptor production tests (2026-01-04)
- `3f78ea1` - Enable automatic HTTPS with Let's Encrypt (2026-01-04)

---

## Recent Issues & Resolutions

### Issue 13: JWT User Object Inconsistency (RESOLVED ✅)
**Date:** 2026-01-04
**Problem:** POST /api/v1/assessments returns 500 Internal Server Error when creating assessments
**Root Cause:** JWT strategy returns `userId` but controllers expect `user.id`, causing `consultantId` to be undefined
**Solution:** Updated jwt.strategy.ts to return `id` instead of `userId`, updated all affected controllers and tests
**Commits:**
- `7d20212` - Fix JWT user object to use 'id' instead of 'userId'
- `35e0e2d` - Fix users-processing-restriction tests (partial)
- `6f63646` - Complete userId to id migration across all services and tests
- `a2d1a7c` - Fix all remaining userId to id references in test files ✅ ALL TESTS PASSING

**Files Changed (15 total):**
- jwt.strategy.ts - Changed return value property name from userId to id
- processing-restriction.guard.ts - Updated user.id reference
- consents.controller.ts - Updated 3 instances to use user.id
- users.controller.ts - Updated all instances to use user.id
- auth.controller.ts - Updated logout endpoint to use user.id
- users.service.ts - Updated getProcessingStatus to return id instead of userId
- jwt.strategy.spec.ts - Updated test expectations (lines 158, 203) and test description
- users-processing-restriction.spec.ts - Updated all mock request objects (14 instances)
- processing-restriction.guard.spec.ts - Updated all mock user objects (10 instances)
- users-data-export.spec.ts - Updated all mock request objects (12 instances)
- consents.controller.spec.ts - Updated all mock request objects (10 instances)
- users-account-deletion.spec.ts - Updated all mock request objects
- users.controller.spec.ts - Updated all mock request objects
- users-right-to-object.spec.ts - Updated all mock request objects
- auth.rate-limiting.spec.ts - Updated mock request object (line 201)

**Test Results (All Passing ✅):**
- users-processing-restriction.spec.ts: 32/32 passing ✅
- processing-restriction.guard.spec.ts: 13/13 passing ✅
- jwt.strategy.spec.ts: All tests passing ✅
- users-data-export.spec.ts: All tests passing ✅
- consents.controller.spec.ts: All tests passing ✅
- users-account-deletion.spec.ts: All tests passing ✅
- users.controller.spec.ts: All tests passing ✅
- csrf.interceptor.spec.ts: 23/23 passing ✅

**Lesson:** Maintain consistent property names across authentication layers. JWT strategy return value must match controller expectations. When making such changes, do comprehensive search across ALL files (services, controllers, guards, tests) to avoid missing instances. Test mocks must accurately reflect production runtime behavior.

---

### Issue 12: CSRF Cookie Not Set Over HTTP (RESOLVED ✅)
**Date:** 2026-01-04
**Problem:** "CSRF token missing" error when creating assessments
**Root Cause 1:** CSRF interceptor set `secure: true` based on NODE_ENV, but site was running HTTP (not HTTPS)
**Solution 1:** Changed to detect actual connection security: `request.secure || request.headers?.['x-forwarded-proto'] === 'https'`
**Commit:** `453e607`

**Root Cause 2:** Site needed HTTPS with automatic SSL certificates
**Solution 2:** Updated Caddyfile to use domain name (triggers Let's Encrypt) and added certificate volume persistence
**Commit:** `3f78ea1`
**Changes:**
- Caddyfile: Changed from `:80` to `getoffthemoneyshametrain.com` for auto-HTTPS
- docker-compose.prod.yml: Added caddy_data and caddy_config volumes
- Added HSTS security header and www redirect

**Root Cause 3:** DNS not configured to point to production VM
**Solution 3:** Added A records in Cloudflare DNS for apex and www domains
**DNS Records:**
- `getoffthemoneyshametrain.com` → 34.72.61.170
- `www.getoffthemoneyshametrain.com` → 34.72.61.170

**Root Cause 4:** CSRF interceptor tests failing after security detection change
**Solution 4:** Updated test mocks to include security headers
**Commit:** `33b058f`
**Test Results:** All 23 CSRF interceptor tests passing ✅

**Lesson:**
- Browser rejects `secure: true` cookies over HTTP connections
- Caddy provides automatic HTTPS when configured with domain name
- Let's Encrypt certificates auto-renew via Caddy
- Test mocks must accurately simulate production environment (headers, security properties)

---

### Issue 11: Staging VM Connectivity + .env Parsing (RESOLVED ✅)
**Date:** 2026-01-02
**Problem 1:** Error 4003: 'failed to connect to backend' when SSH to staging VM
**Root Cause:** Preemptible staging VM shuts down after 24 hours
**Solution:** Modified workflow to check VM status and auto-start before SSH attempts
**Commit:** `75be3ad`

**Problem 2:** `failed to read .env: line 12: unexpected character "+" in variable name`
**Root Cause:** Secret Manager formatting issues (escaped quotes, special characters)
**Solution:** Workflow cleans .env file after pulling from Secret Manager
```bash
sed -i 's/\\\"/\"/g' .env  # Remove escaped quotes
sed -i '/^$/d' .env         # Remove blank lines
```

**Lesson:** Preemptible VMs require state checks before deployment. Use standard VMs for production.

---

### Issue 10: Base64 Secrets in .env Files (RESOLVED ✅)
**Date:** 2026-01-02
**Problem:** Docker Compose .env parser can't handle base64-encoded values with `+`, `/`, `=`
**Solution:** Always quote environment variable values in .env files
**Best Practice:** Use clean quotes `="..."` not escaped `=\"...\"`

---

## Key Lessons Learned

### 1. Authentication & Authorization
- **JWT Property Consistency:** JWT strategy return value must match controller expectations (`id` not `userId`)
- **CSRF Protection:** Requires both server-side token generation and client-side header submission
- **Cookie Security:** `secure` flag requires HTTPS, detect actual connection security not NODE_ENV
- **Token Blacklist:** Check blacklist before user validation for performance

### 2. HTTPS & SSL
- **Caddy Auto-HTTPS:** Using domain name instead of `:80` triggers Let's Encrypt certificate acquisition
- **Certificate Persistence:** Store Let's Encrypt certificates in Docker volumes (`caddy_data`, `caddy_config`)
- **Security Headers:** Always include HSTS header in production (`Strict-Transport-Security`)
- **DNS Configuration:** Cloudflare A records must point to VM IP, use DNS-only mode (not proxied)

### 3. Docker & Environment Variables
- **File Merging:** Docker Compose v3.8 merges arrays (volumes) from base + override files
- **Secret Formatting:** Always quote values in .env files, especially base64-encoded secrets
- **Volume Cleanup:** Aggressive cleanup in deployment: `docker image prune -a -f && docker volume prune -f`

### 4. Database & ORM
- **TypeORM Indexes:** Use property-level `@Index()` for single-column indexes, not class-level with database column names
- **Cloud SQL Networking:** Private IP via VPC peering for production security
- **Migrations:** Handle via `npm run migration:run` in running container (TypeScript configs don't work in builds)

### 5. Testing & CI/CD
- **Test Mocks:** Must accurately simulate production environment (headers, security properties)
- **Test Environment:** Tests expecting production behavior need production-like mock data
- **GitHub Actions:** Preemptible VMs require state checks before deployment steps

### 6. Cost Optimization
- **Cloud SQL:** Use ZONAL (not REGIONAL) for development to save ~$70/month
- **VM Types:** Standard e2-standard-2 for production, preemptible for staging only
- **Disk Space:** Regular cleanup prevents disk space issues and reduces costs
- **Total Monthly Cost:** $103 (Cloud SQL $60 + VM $35 + Storage/Network $8)

---

## Production Infrastructure

**Completed Components:**
1. ✅ Cloud SQL PostgreSQL 14 with Private IP (ZONAL)
2. ✅ Production VM: e2-standard-2 (non-preemptible)
3. ✅ Automatic HTTPS with Let's Encrypt (Caddy)
4. ✅ Secret Manager (all credentials encrypted)
5. ✅ Redis for session storage
6. ✅ GitHub Actions CI/CD pipeline
7. ✅ Monitoring & Alerting (email notifications)
8. ✅ Database Backups (daily + weekly off-site)
9. ✅ CSRF Protection with double-submit cookie pattern
10. ✅ JWT Authentication with token blacklist

**Security Features:**
- HTTPS with HSTS header
- CSRF protection (interceptor + guard)
- JWT authentication with blacklist
- Rate limiting on auth endpoints
- Secure cookie flags (httpOnly, sameSite, secure)
- Private IP database connection
- Encrypted environment variables
- Input validation & sanitization

---

## Quick Reference Commands

### Production VM Access

**SSH into production:**
```bash
gcloud compute ssh financial-rise-prod-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod
```

**Check container status:**
```bash
gcloud compute ssh financial-rise-prod-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker ps"
```

**Check backend logs:**
```bash
gcloud compute ssh financial-rise-prod-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker logs financial-rise-backend-prod --tail 50"
```

**Check frontend logs:**
```bash
gcloud compute ssh financial-rise-prod-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker logs financial-rise-frontend-prod --tail 50"
```

### Secret Manager

**View current production secret:**
```bash
gcloud secrets versions access latest \
  --secret=financial-rise-production-env \
  --project=financial-rise-prod
```

**Update production secret:**
```bash
gcloud secrets versions add financial-rise-production-env \
  --data-file=.env.production \
  --project=financial-rise-prod
```

### Health Checks

**API health:**
```bash
curl https://getoffthemoneyshametrain.com/api/v1/health
```

**Frontend:**
```bash
curl -I https://getoffthemoneyshametrain.com/
```

**Check SSL certificate:**
```bash
curl -vI https://getoffthemoneyshametrain.com/ 2>&1 | grep -A 10 "Server certificate"
```

### Database Access

**Connect to Cloud SQL (via Cloud SQL Proxy):**
```bash
cloud_sql_proxy -instances=financial-rise-prod:us-central1:financial-rise-db=tcp:5432
psql -h localhost -U financial_rise_user -d financial_rise_db
```

**Run migrations:**
```bash
gcloud compute ssh financial-rise-prod-vm \
  --zone=us-central1-a \
  --project=financial-rise-prod \
  --command="docker exec financial-rise-backend-prod npm run migration:run"
```

### Monitoring

**View logs in Cloud Console:**
```
https://console.cloud.google.com/logs?project=financial-rise-prod
```

**Monitoring dashboard:**
```
https://console.cloud.google.com/monitoring?project=financial-rise-prod
```

**Check GitHub Actions workflows:**
```
https://github.com/BeTrashMonster/financial-rise-report/actions
```

---

## Troubleshooting Guide

### Issue: CSRF Token Missing
**Symptoms:** "CSRF token missing" error on POST/PUT/PATCH/DELETE requests
**Check:**
1. Verify cookie is set: Check browser DevTools → Application → Cookies → `XSRF-TOKEN`
2. Verify HTTPS is enabled: Check URL uses `https://`
3. Check cookie flags: `httpOnly=false`, `sameSite=lax`, `secure=true` (in production)
4. Verify frontend sends header: Check Network tab → Request Headers → `X-CSRF-Token`

**Fix:**
- If no cookie: Backend CSRF interceptor not running
- If cookie but no header: Frontend not reading cookie or not sending header
- If both present but error: CSRF guard validation failing (check token matches)

### Issue: 500 Internal Server Error
**Symptoms:** API returns 500 error with no details
**Check:**
1. View backend logs: `docker logs financial-rise-backend-prod --tail 100`
2. Check for TypeScript/validation errors
3. Verify environment variables are set correctly
4. Check database connectivity

**Common Causes:**
- Missing environment variables
- Database connection failures
- Undefined property access (user.id vs user.userId)
- Validation errors (DTO mismatches)

### Issue: HTTPS Not Working
**Symptoms:** Certificate errors or forced HTTP
**Check:**
1. Verify Caddyfile uses domain name (not `:80`)
2. Check DNS points to correct IP: `nslookup getoffthemoneyshametrain.com`
3. Check certificate volume exists: `docker volume ls | grep caddy`
4. View Caddy logs: `docker logs financial-rise-frontend-prod`

**Fix:**
- Wait 1-2 minutes for Let's Encrypt certificate acquisition
- Ensure port 443 is open in firewall
- Verify domain is accessible externally

### Issue: Database Connection Failed
**Symptoms:** "Connection refused" or "Connection timeout"
**Check:**
1. Verify Cloud SQL instance is running
2. Check private IP connectivity from VM
3. Verify DATABASE_HOST matches Cloud SQL private IP
4. Check VPC peering is active

**Fix:**
- Start Cloud SQL instance if stopped
- Verify VPC peering configuration
- Check environment variables in .env file

---

## Historical Issues Archive

**Issues 1-9 (2025-12-31 to 2026-01-01):**
All resolved. Topics included:
- Docker volume mount conflicts
- DB_ENCRYPTION_KEY formatting
- Cloud SQL connection timeouts
- Preemptible VM automatic shutdowns
- Environment variable naming inconsistencies
- Secret Manager version management
- TypeORM index configuration issues
- Migration script execution in production

Detailed logs available in git history: `git log --all --grep="RESOLVED"`

---

## Next Steps & Future Improvements

**Immediate (This Week):**
- ✅ Fix CSRF cookie over HTTP/HTTPS
- ✅ Enable automatic HTTPS with Let's Encrypt
- ✅ Fix JWT user object property inconsistency
- ⏳ Test full assessment creation workflow end-to-end

**Short-term (This Month):**
- Set up automated database backups verification
- Configure email alerts for critical errors
- Add health check monitoring with uptime alerts
- Implement rate limiting on all API endpoints
- Add request/response logging for debugging

**Medium-term (Next Quarter):**
- Rebuild Secret Manager with clean formatting
- Add automated integration tests in CI/CD
- Implement blue-green deployment strategy
- Add CDN for static assets
- Optimize Docker image sizes

**Long-term (Next 6 Months):**
- Migrate to Cloud Run for better scaling
- Implement distributed caching with Redis Cluster
- Add comprehensive E2E testing
- Set up multi-region failover
- Implement automated security scanning

---

**Document Version:** 2.0
**Maintained By:** Claude Code Assistant
**Last Review:** 2026-01-04
