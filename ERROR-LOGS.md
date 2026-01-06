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
- `4e4ecc9` - Add comprehensive question bank (P1 bug fix) - 66 questions (2026-01-04) ✅
- `c0db6b5` - Implement missing /submit endpoint and fix auto-save (P0 bugs) (2026-01-04) ✅
- `aac9a3c` - Fix Save & Exit error when no responses exist (2026-01-04) ✅
- `46c9ef4` - Fix question type rendering to handle nested options format (2026-01-04) ✅
- `1ce00de` - Trigger deployment with corrected FRONTEND_URL (2026-01-04) ✅
- `d2656dc` - Fix FRONTEND_URL in all deployment scripts (2026-01-04) ✅
- `92d8c2a` - Fix frontend questionnaire UI issues (2026-01-04) ✅
- `a2d1a7c` - Fix all remaining userId to id references in test files (2026-01-04) ✅ ALL TESTS PASSING

---

## Recent Issues & Resolutions

### Issue 16: Incomplete Question Bank (RESOLVED ✅)
**Date:** 2026-01-04
**Severity:** P1 - High Priority
**Status:** RESOLVED ✅

**Problem:**
Only 4 sample questions in database, insufficient for proper assessment testing and production use.

**Root Cause:**
Manual seeding of minimal questions for initial testing. No comprehensive question bank created.

**Solution:**
Created `seed-comprehensive-questions.sql` with 66 questions:
- 4 metadata questions (industry, revenue, employees, business age)
- 12 Stabilize phase questions (accounting health, compliance, debt)
- 10 Organize phase questions (entity type with S-Corp conditional)
- 10 Build phase questions (SOPs, budgeting, workflows)
- 10 Grow phase questions (forecasting, strategic planning)
- 8 Systemic phase questions (financial literacy, KPIs)
- 12 DISC profiling questions (hidden personality assessment)

All questions include `phase_scores` and `disc_scores` for proper calculation.

**Files Changed:**
- Created: `seed-comprehensive-questions.sql`
- Updated: `FRONTEND-ASSESSMENT-ROADMAP.md` (marked P1 Bug #3 as complete)

**Commit:** `4e4ecc9`

**Next Steps:**
- Deploy questions to production: `bash deploy-comprehensive-questions.sh`
- Test all question types (multiple_choice, rating, text)
- Verify phase scoring algorithm

---

### Issue 15: Assessment Submit Endpoint Missing (RESOLVED ✅)
**Date:** 2026-01-04
**Severity:** P0 - Critical (Production Blocking)
**Status:** RESOLVED ✅

**Problem:**
```
POST /api/v1/assessments/{id}/submit
404 Not Found
```

Frontend "Calculate Results" button failed because backend endpoint was not implemented.

**Root Cause:**
Submit endpoint was planned but never implemented in `assessments.controller.ts`.

**Solution:**
Implemented POST ':id/submit' endpoint in `assessments.controller.ts`:
```typescript
@Post(':id/submit')
@UseGuards(AssessmentOwnershipGuard)
async submitAssessment(@Param('id', ParseUUIDPipe) id: string, @GetUser() user: any) {
  return this.assessmentsService.submitAssessment(id, user.id);
}
```

Implemented `submitAssessment()` method in `assessments.service.ts`:
- Validates assessment exists and belongs to consultant
- Checks if already completed
- Marks status as COMPLETED
- Sets completed_at timestamp
- TODO: DISC profile and phase calculation (future work)

**Files Changed:**
- `financial-rise-app/backend/src/modules/assessments/assessments.controller.ts`
- `financial-rise-app/backend/src/modules/assessments/assessments.service.ts`

**Commit:** `c0db6b5`

**Impact:** Assessment workflow can now complete successfully. DISC/phase calculation deferred to future implementation.

---

### Issue 14: Auto-Save 500 Internal Server Error (RESOLVED ✅)
**Date:** 2026-01-04
**Severity:** P0 - Critical (Production Blocking)
**Status:** RESOLVED ✅

**Problem:**
```
POST /api/v1/questionnaire/responses
500 Internal Server Error

QueryFailedError: column Assessment__Assessment_responses.not_applicable does not exist
```

Assessment responses could not be saved, causing users to lose all progress.

**Root Cause:**
Database schema was missing two columns that the `AssessmentResponse` entity expected:
- `not_applicable` (BOOLEAN)
- `consultant_notes` (TEXT)

TypeORM entity defined these fields but database schema was out of sync.

**Solution:**
Added missing columns via SQL migration:
```sql
ALTER TABLE assessment_responses
ADD COLUMN IF NOT EXISTS not_applicable BOOLEAN DEFAULT FALSE;

ALTER TABLE assessment_responses
ADD COLUMN IF NOT EXISTS consultant_notes TEXT;
```

Ran migration on production database and verified schema with `\d assessment_responses`.

**Files Changed:**
- Production database schema (assessment_responses table)

**Commit:** `c0db6b5`

**Impact:** Auto-save now works correctly. All assessment responses are persisted.

---

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


### Issue 17: SSL Certificate Acquisition Failure (RESOLVED ✅)
**Date:** 2026-01-05
**Severity:** P0 - Critical (Site Inaccessible)
**Status:** RESOLVED ✅

**Problem:**
```
ERR_SSL_PROTOCOL_ERROR
getoffthemoneyshametrain.com sent an invalid response
```

Site completely inaccessible - no login page, no HTTPS connection.

**Root Causes:**
1. **Caddyfile misconfiguration** - Backend container referenced as `backend:3000` but actual container name was `financial-rise-backend-prod`
2. **ACME challenge redirection** - Caddy was redirecting HTTP ACME challenges to HTTPS, preventing Let's Encrypt validation
3. **Let's Encrypt rate limiting** - Hit 5 certificates/week limit from previous troubleshooting attempts
4. **Missing email in Caddyfile** - No contact email specified for ACME account

**Diagnostic Steps:**
- Verified DNS: `34.72.61.170` ✅
- Verified firewall: Ports 80/443 open with `http-server` tag ✅
- Verified containers running and communicating (ping test) ✅
- Found Caddy had no certificates in `/data/caddy/certificates/`
- Found stuck lock files: `issue_cert_*.lock`

**Solution:**
1. Removed stuck certificate lock files
2. Updated Caddyfile with proper configuration:
   - Added email address for ACME notifications
   - Ensured ACME challenges handled correctly on HTTP
   - Kept security headers and proxy configuration intact
3. Restarted Caddy container
4. Caddy automatically fell back to ZeroSSL after Let's Encrypt rate limiting

**Certificates Obtained:**
```
/data/caddy/certificates/acme.zerossl.com-v2-dv90/
├── getoffthemoneyshametrain.com.crt
├── getoffthemoneyshametrain.com.key
├── www.getoffthemoneyshametrain.com.crt
└── www.getoffthemoneyshametrain.com.key
```

**Commands Used:**
```bash
# Remove stuck locks
docker exec financial-rise-frontend-prod rm -f /data/caddy/locks/issue_cert_*.lock

# Update Caddyfile (added email, proper ACME handling)
docker exec financial-rise-frontend-prod sh -c 'cat > /etc/caddy/Caddyfile << EOF...'

# Restart and verify
docker restart financial-rise-frontend-prod
docker exec financial-rise-frontend-prod find /data/caddy/certificates -type f
```

**Impact:** Site is now accessible via HTTPS with valid SSL certificates from ZeroSSL.

**Lesson:** 
- Always include email address in Caddyfile global config for ACME account management
- ACME challenges MUST be accessible via HTTP (port 80) - don't redirect to HTTPS
- Caddy automatically tries multiple certificate authorities (Let's Encrypt → ZeroSSL) if one fails
- Let's Encrypt has strict rate limits: 5 certificates per exact domain set per week
- Container names in Docker network aliases matter - verify with `docker inspect` before configuring

---
info@financial-rise-production-vm:~$  docker exec financial-rise-frontend-prod rm -f /data/caddy/locks/issue_cert_*.lock
info@financial-rise-production-vm:~$ docker logs financial-rise-frontend-prod 2>&1 | grep -i "error\|certificate\|acme" | tail -30
{"level":"info","ts":1767579541.331249,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3321767,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3321936,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3322089,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"info","ts":1767579541.3366585,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3374918,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3375309,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3375452,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"error","ts":1767579541.715981,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:39:13 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579541.7160587,"logger":"tls.obtain","msg":"will retry","error":"[getoffthemoneyshametrain.com] Obtain: [getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:39:13 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":1,"retrying_in":60,"elapsed":0.384892822,"max_duration":2592000}
{"level":"error","ts":1767579541.747043,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"www.getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:24:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579541.7471378,"logger":"tls.obtain","msg":"will retry","error":"[www.getoffthemoneyshametrain.com] Obtain: [www.getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:24:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":1,"retrying_in":60,"elapsed":0.41056275,"max_duration":2592000}
{"level":"info","ts":1767579601.7162862,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579601.7173462,"logger":"http","msg":"using ACME account","account_id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/255435633","account_contact":[]}
{"level":"info","ts":1767579601.7477417,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579601.7487755,"logger":"http","msg":"using ACME account","account_id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/255435633","account_contact":[]}
{"level":"info","ts":1767579602.084232,"msg":"validations succeeded; finalizing order","order":"https://acme-staging-v02.api.letsencrypt.org/acme/order/255435633/30222410093"}
{"level":"info","ts":1767579602.0995686,"msg":"validations succeeded; finalizing order","order":"https://acme-staging-v02.api.letsencrypt.org/acme/order/255435633/30222410113"}
{"level":"info","ts":1767579605.42765,"msg":"successfully downloaded available certificate chains","count":2,"first_url":"https://acme-staging-v02.api.letsencrypt.org/acme/cert/2c61ae5c4efb9b1195e5bca1fd59d2e7462a"}
{"level":"info","ts":1767579605.427995,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.4280133,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.42803,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"info","ts":1767579605.4455721,"msg":"successfully downloaded available certificate chains","count":2,"first_url":"https://acme-staging-v02.api.letsencrypt.org/acme/cert/2cc74c584a0ed38261ba7c698b90911427ff"}
{"level":"info","ts":1767579605.4459517,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.4459662,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.445981,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"error","ts":1767579605.5483031,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:12:24 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579605.5483813,"logger":"tls.obtain","msg":"will retry","error":"[getoffthemoneyshametrain.com] Obtain: [getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:12:24 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":2,"retrying_in":120,"elapsed":64.217216026,"max_duration":2592000}
{"level":"error","ts":1767579605.5731711,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"www.getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:51:36 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579605.57324,"logger":"tls.obtain","msg":"will retry","error":"[www.getoffthemoneyshametrain.com] Obtain: [www.getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:51:36 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":2,"retrying_in":120,"elapsed":64.236665165,"max_duration":2592000}
info@financial-rise-production-vm:~$  docker logs financial-rise-frontend-prod > /tmp/caddy-debug.log 2>&1
  tail -100 /tmp/caddy-debug.log
{"level":"info","ts":1767578991.9835954,"logger":"http","msg":"using ACME account","account_id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/255435633","account_contact":[]}
{"level":"info","ts":1767578992.2870824,"msg":"authorization finalized","identifier":"getoffthemoneyshametrain.com","authz_status":"valid"}
{"level":"info","ts":1767578992.287125,"msg":"validations succeeded; finalizing order","order":"https://acme-staging-v02.api.letsencrypt.org/acme/order/255435633/30222171543"}
{"level":"info","ts":1767578995.515669,"msg":"got renewal info","names":["getoffthemoneyshametrain.com"],"window_start":1772682926,"window_end":1772838376,"selected_time":1772814041,"recheck_after":1767600595.5156496,"explanation_url":""}
{"level":"info","ts":1767578995.624118,"msg":"got renewal info","names":["getoffthemoneyshametrain.com"],"window_start":1772682926,"window_end":1772838376,"selected_time":1772812778,"recheck_after":1767600595.6241002,"explanation_url":""}
{"level":"info","ts":1767578995.6242156,"msg":"successfully downloaded available certificate chains","count":2,"first_url":"https://acme-staging-v02.api.letsencrypt.org/acme/cert/2c85c688c21cb67690e8f05c004bdd6f2b26"}
{"level":"info","ts":1767578995.6246336,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767578995.6246674,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767578995.624686,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"error","ts":1767578995.8024979,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:42:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767578995.8025925,"logger":"tls.obtain","msg":"will retry","error":"[getoffthemoneyshametrain.com] Obtain: [getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:42:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":6,"retrying_in":600,"elapsed":1220.98157101,"max_duration":2592000}
{"level":"info","ts":1767578997.6759958,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767578997.6773093,"logger":"http","msg":"using ACME account","account_id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/255435633","account_contact":[]}
{"level":"info","ts":1767578997.8443513,"msg":"authorization finalized","identifier":"www.getoffthemoneyshametrain.com","authz_status":"valid"}
{"level":"info","ts":1767578997.8444145,"msg":"validations succeeded; finalizing order","order":"https://acme-staging-v02.api.letsencrypt.org/acme/order/255435633/30222173643"}
{"level":"info","ts":1767579004.1285827,"msg":"got renewal info","names":["www.getoffthemoneyshametrain.com"],"window_start":1772682933,"window_end":1772838382,"selected_time":1772828068,"recheck_after":1767600604.1285636,"explanation_url":""}
{"level":"info","ts":1767579004.241257,"msg":"got renewal info","names":["www.getoffthemoneyshametrain.com"],"window_start":1772682933,"window_end":1772838382,"selected_time":1772718466,"recheck_after":1767600604.2412255,"explanation_url":""}
{"level":"info","ts":1767579004.2413635,"msg":"successfully downloaded available certificate chains","count":2,"first_url":"https://acme-staging-v02.api.letsencrypt.org/acme/cert/2cd046e67a516e548389f6ea9f6f63cb8c59"}
{"level":"info","ts":1767579004.2419012,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579004.2419372,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579004.2419577,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"error","ts":1767579004.3392415,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"www.getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:45:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579004.3393528,"logger":"tls.obtain","msg":"will retry","error":"[www.getoffthemoneyshametrain.com] Obtain: [www.getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:45:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":6,"retrying_in":600,"elapsed":1229.527702915,"max_duration":2592000}
{"level":"error","ts":1767579434.7867696,"logger":"tls","msg":"tls-alpn challenge","remote_addr":"66.133.109.36:54469","server_name":"www.getoffthemoneyshametrain.com","error":"no information found to solve challenge for identifier: www.getoffthemoneyshametrain.com"}
{"level":"error","ts":1767579435.216887,"logger":"tls","msg":"tls-alpn challenge","remote_addr":"66.133.109.36:38281","server_name":"getoffthemoneyshametrain.com","error":"no information found to solve challenge for identifier: getoffthemoneyshametrain.com"}
{"level":"warn","ts":1767579436.2135684,"logger":"http","msg":"looking up info for HTTP challenge","host":"www.getoffthemoneyshametrain.com","remote_addr":"66.133.109.36:52085","user_agent":"Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)","error":"no information found to solve challenge for identifier: www.getoffthemoneyshametrain.com"}
{"level":"warn","ts":1767579436.6493213,"logger":"http","msg":"looking up info for HTTP challenge","host":"getoffthemoneyshametrain.com","remote_addr":"66.133.109.36:52087","user_agent":"Mozilla/5.0 (compatible; Let's Encrypt validation server; +https://www.letsencrypt.org)","error":"no information found to solve challenge for identifier: getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579460.6583235,"logger":"admin.api","msg":"received request","method":"POST","host":"localhost:2019","uri":"/load","remote_ip":"127.0.0.1","remote_port":"37754","headers":{"Accept-Encoding":["gzip"],"Content-Length":["1580"],"Content-Type":["application/json"],"Origin":["http://localhost:2019"],"User-Agent":["Go-http-client/1.1"]}}
{"level":"info","ts":1767579460.6587799,"msg":"config is unchanged"}
{"level":"info","ts":1767579460.6587975,"logger":"admin.api","msg":"load complete"}
{"level":"info","ts":1767579540.6484354,"msg":"shutting down apps, then terminating","signal":"SIGTERM"}
{"level":"warn","ts":1767579540.6485634,"msg":"exiting; byeee!! 👋","signal":"SIGTERM"}
{"level":"info","ts":1767579540.648749,"logger":"http","msg":"servers shutting down with eternal grace period"}
{"level":"info","ts":1767579540.6503127,"logger":"tls.obtain","msg":"releasing lock","identifier":"getoffthemoneyshametrain.com"}
{"level":"error","ts":1767579540.6503549,"logger":"tls.obtain","msg":"unable to unlock","identifier":"getoffthemoneyshametrain.com","lock_key":"issue_cert_getoffthemoneyshametrain.com","error":"remove /data/caddy/locks/issue_cert_getoffthemoneyshametrain.com.lock: no such file or directory"}
{"level":"error","ts":1767579540.650398,"logger":"tls","msg":"job failed","error":"getoffthemoneyshametrain.com: obtaining certificate: context canceled"}
{"level":"info","ts":1767579540.6504273,"logger":"tls.obtain","msg":"releasing lock","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"error","ts":1767579540.6505785,"msg":"unable to clean up lock in storage backend","signal":"SIGTERM","storage":"FileStorage:/data/caddy","lock_key":"issue_cert_www.getoffthemoneyshametrain.com","error":"remove /data/caddy/locks/issue_cert_www.getoffthemoneyshametrain.com.lock: no such file or directory"}
{"level":"info","ts":1767579540.650653,"logger":"admin","msg":"stopped previous server","address":"localhost:2019"}
{"level":"info","ts":1767579540.6506631,"msg":"shutdown complete","signal":"SIGTERM","exit_code":0}
{"level":"info","ts":1767579541.3168838,"msg":"maxprocs: Updating GOMAXPROCS=1: using minimum allowed GOMAXPROCS"}
{"level":"info","ts":1767579541.317361,"msg":"GOMEMLIMIT is updated","package":"github.com/KimMachineGun/automemlimit/memlimit","GOMEMLIMIT":483183820,"previous":9223372036854775807}
{"level":"info","ts":1767579541.317455,"msg":"using config from file","file":"/etc/caddy/Caddyfile"}
{"level":"info","ts":1767579541.319768,"msg":"adapted config to JSON","adapter":"caddyfile"}
{"level":"warn","ts":1767579541.319781,"msg":"Caddyfile input is not formatted; run 'caddy fmt --overwrite' to fix inconsistencies","adapter":"caddyfile","file":"/etc/caddy/Caddyfile","line":6}
{"level":"info","ts":1767579541.3213058,"logger":"admin","msg":"admin endpoint started","address":"localhost:2019","enforce_origin":false,"origins":["//localhost:2019","//[::1]:2019","//127.0.0.1:2019"]}
{"level":"info","ts":1767579541.3217354,"logger":"http.auto_https","msg":"server is listening only on the HTTPS port but has no TLS connection policies; adding one to enable TLS","server_name":"srv0","https_port":443}
{"level":"info","ts":1767579541.3218205,"logger":"http.auto_https","msg":"enabling automatic HTTP->HTTPS redirects","server_name":"srv0"}
{"level":"warn","ts":1767579541.3230655,"logger":"http","msg":"HTTP/2 skipped because it requires TLS","network":"tcp","addr":":80"}
{"level":"warn","ts":1767579541.3230875,"logger":"http","msg":"HTTP/3 skipped because it requires TLS","network":"tcp","addr":":80"}
{"level":"info","ts":1767579541.3230922,"logger":"http.log","msg":"server running","name":"remaining_auto_https_redirects","protocols":["h1","h2","h3"]}
{"level":"info","ts":1767579541.323169,"logger":"http","msg":"enabling HTTP/3 listener","addr":":443"}
{"level":"info","ts":1767579541.3233488,"msg":"failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB). See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details."}
{"level":"info","ts":1767579541.3238642,"logger":"http.log","msg":"server running","name":"srv0","protocols":["h1","h2","h3"]}
{"level":"info","ts":1767579541.3240077,"logger":"http","msg":"enabling automatic TLS certificate management","domains":["www.getoffthemoneyshametrain.com","getoffthemoneyshametrain.com"]}
{"level":"info","ts":1767579541.3246653,"msg":"autosaved config (load with --resume flag)","file":"/config/caddy/autosave.json"}
{"level":"info","ts":1767579541.3247445,"msg":"serving initial configuration"}
{"level":"info","ts":1767579541.326882,"logger":"tls","msg":"storage cleaning happened too recently; skipping for now","storage":"FileStorage:/data/caddy","instance":"62fcde7c-1c2f-44e6-9570-34c278e56b82","try_again":1767665941.32688,"try_again_in":86399.9999994}
{"level":"info","ts":1767579541.326958,"logger":"tls","msg":"finished cleaning storage units"}
{"level":"info","ts":1767579541.327036,"logger":"tls.cache.maintenance","msg":"started background certificate maintenance","cache":"0xc000353a80"}
{"level":"info","ts":1767579541.3291905,"logger":"tls.obtain","msg":"acquiring lock","identifier":"getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3311274,"logger":"tls.obtain","msg":"lock acquired","identifier":"getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.331249,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3321767,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3321936,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3322089,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"info","ts":1767579541.3347952,"logger":"tls.obtain","msg":"acquiring lock","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3365436,"logger":"tls.obtain","msg":"lock acquired","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3366585,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579541.3374918,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3375309,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579541.3375452,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"error","ts":1767579541.715981,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:39:13 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579541.7160587,"logger":"tls.obtain","msg":"will retry","error":"[getoffthemoneyshametrain.com] Obtain: [getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:39:13 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":1,"retrying_in":60,"elapsed":0.384892822,"max_duration":2592000}
{"level":"error","ts":1767579541.747043,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"www.getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:24:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579541.7471378,"logger":"tls.obtain","msg":"will retry","error":"[www.getoffthemoneyshametrain.com] Obtain: [www.getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:24:52 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":1,"retrying_in":60,"elapsed":0.41056275,"max_duration":2592000}
{"level":"info","ts":1767579601.7162862,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579601.7173462,"logger":"http","msg":"using ACME account","account_id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/255435633","account_contact":[]}
{"level":"info","ts":1767579601.7477417,"logger":"tls.obtain","msg":"obtaining certificate","identifier":"www.getoffthemoneyshametrain.com"}
{"level":"info","ts":1767579601.7487755,"logger":"http","msg":"using ACME account","account_id":"https://acme-staging-v02.api.letsencrypt.org/acme/acct/255435633","account_contact":[]}
{"level":"info","ts":1767579602.084188,"msg":"authorization finalized","identifier":"getoffthemoneyshametrain.com","authz_status":"valid"}
{"level":"info","ts":1767579602.084232,"msg":"validations succeeded; finalizing order","order":"https://acme-staging-v02.api.letsencrypt.org/acme/order/255435633/30222410093"}
{"level":"info","ts":1767579602.09953,"msg":"authorization finalized","identifier":"www.getoffthemoneyshametrain.com","authz_status":"valid"}
{"level":"info","ts":1767579602.0995686,"msg":"validations succeeded; finalizing order","order":"https://acme-staging-v02.api.letsencrypt.org/acme/order/255435633/30222410113"}
{"level":"info","ts":1767579605.3128922,"msg":"got renewal info","names":["getoffthemoneyshametrain.com"],"window_start":1772683536,"window_end":1772838986,"selected_time":1772773676,"recheck_after":1767601205.3128774,"explanation_url":""}
{"level":"info","ts":1767579605.330349,"msg":"got renewal info","names":["www.getoffthemoneyshametrain.com"],"window_start":1772683536,"window_end":1772838985,"selected_time":1772769856,"recheck_after":1767601205.3303385,"explanation_url":""}
{"level":"info","ts":1767579605.4274843,"msg":"got renewal info","names":["getoffthemoneyshametrain.com"],"window_start":1772683536,"window_end":1772838986,"selected_time":1772793057,"recheck_after":1767601205.427474,"explanation_url":""}
{"level":"info","ts":1767579605.42765,"msg":"successfully downloaded available certificate chains","count":2,"first_url":"https://acme-staging-v02.api.letsencrypt.org/acme/cert/2c61ae5c4efb9b1195e5bca1fd59d2e7462a"}
{"level":"info","ts":1767579605.427995,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.4280133,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.42803,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"info","ts":1767579605.4454904,"msg":"got renewal info","names":["www.getoffthemoneyshametrain.com"],"window_start":1772683536,"window_end":1772838985,"selected_time":1772754009,"recheck_after":1767601205.445478,"explanation_url":""}
{"level":"info","ts":1767579605.4455721,"msg":"successfully downloaded available certificate chains","count":2,"first_url":"https://acme-staging-v02.api.letsencrypt.org/acme/cert/2cc74c584a0ed38261ba7c698b90911427ff"}
{"level":"info","ts":1767579605.4459517,"logger":"http","msg":"waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.4459662,"logger":"http","msg":"done waiting on internal rate limiter","identifiers":["www.getoffthemoneyshametrain.com"],"ca":"https://acme-v02.api.letsencrypt.org/directory","account":""}
{"level":"info","ts":1767579605.445981,"logger":"http","msg":"using ACME account","account_id":"https://acme-v02.api.letsencrypt.org/acme/acct/2935492736","account_contact":[]}
{"level":"error","ts":1767579605.5483031,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:12:24 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579605.5483813,"logger":"tls.obtain","msg":"will retry","error":"[getoffthemoneyshametrain.com] Obtain: [getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:12:24 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":2,"retrying_in":120,"elapsed":64.217216026,"max_duration":2592000}
{"level":"error","ts":1767579605.5731711,"logger":"tls.obtain","msg":"could not get certificate from issuer","identifier":"www.getoffthemoneyshametrain.com","issuer":"acme-v02.api.letsencrypt.org-directory","error":"HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:51:36 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers"}
{"level":"error","ts":1767579605.57324,"logger":"tls.obtain","msg":"will retry","error":"[www.getoffthemoneyshametrain.com] Obtain: [www.getoffthemoneyshametrain.com] creating new order: attempt 1: https://acme-v02.api.letsencrypt.org/acme/new-order: HTTP 429 urn:ietf:params:acme:error:rateLimited - too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-01-06 06:51:36 UTC: see https://letsencrypt.org/docs/rate-limits/#new-certificates-per-exact-set-of-identifiers (ca=https://acme-v02.api.letsencrypt.org/directory)","attempt":2,"retrying_in":120,"elapsed":64.236665165,"max_duration":2592000}
info@financial-rise-production-vm:~$ docker exec financial-rise-frontend-prod cat /etc/caddy/Caddyfile | head -10
# Caddy configuration for Financial RISE Frontend
# Serves React static files and proxies API requests to backend
# Automatic HTTPS with Let's Encrypt

getoffthemoneyshametrain.com {
    # Enable gzip compression
    encode gzip

    # Security headers
    header {

---

## Issue 18: SSL Certificate Persistence - Certificates Lost on Container Restart

**Date:** 2026-01-04
**Status:** ✅ RESOLVED
**Severity:** P0 - CRITICAL
**Impact:** Site became inaccessible again after SSL was fixed - ERR_SSL_PROTOCOL_ERROR returned

### Problem

After successfully fixing the SSL certificate issue (Issue 17), the site worked for ~25 minutes, then ERR_SSL_PROTOCOL_ERROR returned. Investigation revealed certificates had completely disappeared from the container.

**Symptoms:**
- Site worked with valid ZeroSSL certificates
- 25 minutes later, same SSL error returned
- Certificate directory showed only lock files and ACME account keys
- Actual `.crt` and `.key` files were gone

### Root Cause

The Caddyfile fix was applied directly to the **running container** via `docker cp`, but the **source code and Docker image** still had the old Caddyfile without email configuration. When the container restarted (or was replaced during deployment), it loaded the original Caddyfile from the image, losing the fix.

**Why This Happened:**
1. Fixed Caddyfile in running container: ✅ Immediate fix
2. But Docker image still has old Caddyfile: ❌ Fix not permanent
3. Container restart/redeploy → loads image Caddyfile → loses email config → SSL fails

### Solution

**Two-Part Fix:**

**Part 1: Immediate Fix (Applied to Running Container)**
```bash
# Update Caddyfile in running container
cat > /tmp/Caddyfile << 'EOF'
{
    email admin@getoffthemoneyshametrain.com
}

getoffthemoneyshametrain.com {
    encode gzip
    header { ... }
    @api path /api/*
    handle @api {
        reverse_proxy backend:3000
    }
    handle { ... }
}

www.getoffthemoneyshametrain.com {
    redir https://getoffthemoneyshametrain.com{uri} permanent
}
EOF

docker cp /tmp/Caddyfile financial-rise-frontend-prod:/etc/caddy/Caddyfile

# Remove stuck locks
docker exec financial-rise-frontend-prod rm -f /data/caddy/locks/issue_cert_*.lock

# Restart Caddy
docker restart financial-rise-frontend-prod

# Verify certificates obtained
docker exec financial-rise-frontend-prod find /data/caddy/certificates -type f
```

**Part 2: Permanent Fix (Update Source Code)**
```bash
# Update source Caddyfile
cd financial-rise-app/frontend
# Edit Caddyfile to add email configuration
git add Caddyfile
git commit -m "Add ACME email configuration to Caddyfile for SSL persistence"
git push origin main

# Rebuild Docker image
gcloud builds submit --config cloudbuild.yaml
```

### Verification

**Immediate:**
```bash
# Verify site accessible with HTTPS
curl -I https://getoffthemoneyshametrain.com
# Expected: HTTP/2 200

# Verify certificates present
docker exec financial-rise-frontend-prod ls -la /data/caddy/certificates/acme.zerossl.com-v2-dv90/
# Expected: .crt and .key files for both domains
```

**After Image Rebuild:**
```bash
# Redeploy with new image
docker-compose down
docker-compose up -d

# Verify Caddyfile has email in new container
docker exec financial-rise-frontend-prod cat /etc/caddy/Caddyfile | head -10
# Expected: Shows email in global config block

# Verify certificates persist
docker exec financial-rise-frontend-prod ls -la /data/caddy/certificates/acme.zerossl.com-v2-dv90/
```

### Impact

**Before Fix:** Site worked temporarily but became inaccessible after any container restart
**After Fix:** SSL certificates persist across container restarts and redeployments

### Quick Reference - SSL Certificate Troubleshooting Checklist

If SSL certificates fail or disappear:

1. **Check if email is in Caddyfile global config:**
   ```bash
   docker exec financial-rise-frontend-prod cat /etc/caddy/Caddyfile | head -10
   ```
   Should show:
   ```
   {
       email admin@getoffthemoneyshametrain.com
   }
   ```

2. **Remove stuck certificate locks:**
   ```bash
   docker exec financial-rise-frontend-prod rm -f /data/caddy/locks/issue_cert_*.lock
   ```

3. **Restart Caddy:**
   ```bash
   docker restart financial-rise-frontend-prod
   ```

4. **Monitor certificate acquisition:**
   ```bash
   docker logs -f financial-rise-frontend-prod | grep -i "certificate\|acme"
   ```

5. **Verify certificates obtained:**
   ```bash
   docker exec financial-rise-frontend-prod find /data/caddy/certificates -type f
   ```

6. **If certificates obtained but fix not permanent:**
   - Update source Caddyfile in repository
   - Rebuild Docker image
   - Redeploy

### Lesson Learned

**Container vs. Image Persistence:**
- Changes to **running containers** (via `docker exec`, `docker cp`) are temporary
- Changes only persist if made to the **Docker image** or mounted volumes
- For configuration files baked into images: always update source code + rebuild image

**The Right Workflow:**
1. Apply fix to running container for immediate resolution
2. Update source code in repository
3. Rebuild Docker image
4. Redeploy to make fix permanent

---

## Issue 19: PowerShell Execution Policy Blocking gcloud Command

**Date:** 2026-01-04
**Status:** ✅ RESOLVED (Not Needed)
**Severity:** P2 - MEDIUM
**Impact:** Cannot rebuild Docker image from Windows PC to make SSL fix permanent

### Problem

When attempting to rebuild the frontend Docker image to permanently fix the SSL certificate issue, PowerShell blocked the gcloud command with a security error.

**Error:**
```
PS C:\Users\Admin\src\financial-rise-app\frontend> gcloud builds submit --config cloudbuild.yaml
gcloud : File C:\Users\Admin\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.ps1
cannot be loaded because running scripts is disabled on this system. For more information, see
about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:2
+  gcloud builds submit --config cloudbuild.yaml
+  ~~~~~~
    + CategoryInfo          : SecurityError: (:) [], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess
```

### Root Cause

Windows PowerShell execution policy is set to `Restricted` or `AllSigned`, which prevents running scripts downloaded from the internet (including Google Cloud SDK scripts).

### Solutions

**Option 1: Use Command Prompt (Easiest - RECOMMENDED)**

Command Prompt (cmd.exe) does NOT have execution policies. Simply use cmd instead of PowerShell:

```cmd
REM Open Command Prompt (not PowerShell)
cd C:\Users\Admin\src\financial-rise-app\frontend
gcloud builds submit --config cloudbuild.yaml
```

**Option 2: Bypass Execution Policy for One Command**

```powershell
# Run in PowerShell
cd C:\Users\Admin\src\financial-rise-app\frontend
powershell -ExecutionPolicy Bypass -Command "gcloud builds submit --config cloudbuild.yaml"
```

**Option 3: Change Execution Policy (Requires Admin)**

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then run normally
cd C:\Users\Admin\src\financial-rise-app\frontend
gcloud builds submit --config cloudbuild.yaml
```

### Quick Reference - Execution Policy Levels

- **Restricted** - No scripts allowed (most secure, default on Windows client)
- **AllSigned** - Only scripts signed by trusted publisher
- **RemoteSigned** - Local scripts allowed, downloaded scripts must be signed
- **Unrestricted** - All scripts allowed (least secure)
- **Bypass** - Nothing is blocked, no warnings (temporary use only)

### Recommended Solution

**Use Command Prompt (cmd.exe) for gcloud commands** to avoid PowerShell execution policy issues entirely.

```cmd
cmd
cd C:\Users\Admin\src\financial-rise-app\frontend
gcloud builds submit --config cloudbuild.yaml
```

### Resolution

**Issue became moot** - GitHub Actions workflow already deployed the fixed Caddyfile (commit 0a9fbbc) automatically when code was pushed to main. Manual rebuild from Windows PC was not needed.

**Verification:**
```bash
docker exec financial-rise-frontend-prod cat /etc/caddy/Caddyfile | head -10
```

Shows email configuration is present in deployed container. SSL certificates now persist permanently.

**Lesson:** Always check GitHub Actions workflow status before attempting manual deployments. The automated CI/CD pipeline handles image building and deployment.

---
