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
36s
Run npm run test:cov

> financial-rise-backend@1.0.0 test:cov
> jest --coverage

ts-jest[ts-jest-transformer] (WARN) Define `ts-jest` config under `globals` is deprecated. Please do
transform: {
    <transform_regex>: ['ts-jest', { /* ts-jest config goes here in Jest */ }],
},
See more at https://kulshekhar.github.io/ts-jest/docs/getting-started/presets#advanced
ts-jest[ts-jest-transformer] (WARN) Define `ts-jest` config under `globals` is deprecated. Please do
transform: {
    <transform_regex>: ['ts-jest', { /* ts-jest config goes here in Jest */ }],
},
See more at https://kulshekhar.github.io/ts-jest/docs/getting-started/presets#advanced
ts-jest[ts-jest-transformer] (WARN) Define `ts-jest` config under `globals` is deprecated. Please do
transform: {
    <transform_regex>: ['ts-jest', { /* ts-jest config goes here in Jest */ }],
},
See more at https://kulshekhar.github.io/ts-jest/docs/getting-started/presets#advanced
PASS src/common/utils/log-sanitizer.spec.ts (9.785 s)
PASS src/modules/assessments/services/validation.service.spec.ts
PASS src/modules/users/users-processing-restriction.spec.ts (12.463 s)
PASS src/config/typeorm-ssl.config.spec.ts
  ● Console

    console.warn
      [TypeORM SSL] CA certificate file not found: /invalid/path/that/does/not/exist.pem

      46 |       } else {
      47 |         // Log warning but don't fail - connection attempt will reveal if cert is actually needed
    > 48 |         console.warn(`[TypeORM SSL] CA certificate file not found: ${caPath}`);
         |                 ^
      49 |       }
      50 |     } catch (error) {
      51 |       // Log error but don't throw - allow TypeORM to handle connection failure

      at warn (config/typeorm.config.ts:48:17)
      at getSSLConfig (config/typeorm.config.ts:81:8)
      at config/typeorm-ssl.config.spec.ts:389:33
      at Object.<anonymous> (../node_modules/expect/build/toThrowMatchers.js:74:11)
      at Object.throwingMatcher [as toThrow] (../node_modules/expect/build/index.js:320:21)
      at Object.<anonymous> (config/typeorm-ssl.config.spec.ts:389:58)

    console.warn
      [TypeORM SSL] CA certificate file not found: /invalid/path/that/does/not/exist.pem

      46 |       } else {
      47 |         // Log warning but don't fail - connection attempt will reveal if cert is actually needed
    > 48 |         console.warn(`[TypeORM SSL] CA certificate file not found: ${caPath}`);
         |                 ^
      49 |       }
      50 |     } catch (error) {
      51 |       // Log error but don't throw - allow TypeORM to handle connection failure

      at warn (config/typeorm.config.ts:48:17)
      at getSSLConfig (config/typeorm.config.ts:81:8)
      at Object.<anonymous> (config/typeorm-ssl.config.spec.ts:391:40)

PASS src/modules/auth/auth.service.spec.ts (13.71 s)
[Nest] 3591  - 01/06/2026, 5:53:07 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:07 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:08 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at urlencodedParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/urlencoded.js:119:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:122:7)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/modules/assessments/services/progress.service.spec.ts
PASS src/modules/questionnaire/questionnaire.service.spec.ts
PASS src/modules/consents/consents.service.spec.ts
PASS src/modules/users/users.service.spec.ts
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at urlencodedParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/urlencoded.js:119:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:122:7)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
[Nest] 3591  - 01/06/2026, 5:53:10 AM   ERROR [ExceptionsHandler] request entity too large
PayloadTooLargeError: request entity too large
    at readStream (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:163:17)
    at getRawBody (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/raw-body/index.js:116:12)
    at read (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/read.js:79:3)
    at jsonParser (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/body-parser/lib/types/json.js:138:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at expressInit (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/init.js:40:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at query (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/middleware/query.js:45:5)
    at Layer.handle [as handle_request] (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/layer.js:95:5)
    at trim_prefix (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:328:13)
    at /home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:286:9
    at Function.process_params (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:346:12)
    at next (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:280:10)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/router/index.js:175:3)
    at Function.handle (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/application.js:181:10)
    at Server.app (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/express/lib/express.js:39:9)
    at Server.emit (node:events:517:28)
    at parserOnIncoming (node:_http_server:1130:12)
    at HTTPParser.parserOnHeadersComplete (node:_http_common:119:17)
PASS src/security/request-size-limits.spec.ts
PASS src/modules/algorithms/phase/phase-calculator.service.spec.ts
PASS src/modules/algorithms/entities/disc-profile.encryption.spec.ts
PASS src/modules/auth/strategies/jwt.strategy.spec.ts
PASS src/modules/auth/refresh-token.service.spec.ts
PASS src/modules/algorithms/disc/disc-calculator.service.spec.ts
PASS src/config/cors.config.spec.ts
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 3 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - https://app.financialrise.com
[Nest] 3590  - 01/06/2026, 5:53:12 AM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: https://app.financialrise.com
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 3 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - https://staging.financialrise.com
[Nest] 3590  - 01/06/2026, 5:53:12 AM   DEBUG [CORSConfiguration] CORS: Allowed request from whitelisted origin: https://staging.financialrise.com
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://evil.com
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] Object:
{
  "origin": "http://evil.com",
  "timestamp": "2026-01-06T05:53:12.783Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://localhost:9999
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] Object:
{
  "origin": "http://localhost:9999",
  "timestamp": "2026-01-06T05:53:12.787Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: https://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] Object:
{
  "origin": "https://localhost:3001",
  "timestamp": "2026-01-06T05:53:12.788Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM   DEBUG [CORSConfiguration] CORS: Request with no origin header - allowing
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://LOCALHOST:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] Object:
{
  "origin": "http://LOCALHOST:3001",
  "timestamp": "2026-01-06T05:53:12.789Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://malicious.localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] Object:
{
  "origin": "http://malicious.localhost:3001",
  "timestamp": "2026-01-06T05:53:12.790Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Configured 2 allowed origins
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM     LOG [CORSConfiguration] CORS: Whitelisted origin - http://localhost:5173
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] 🚫 CORS: Blocked request from unauthorized origin: http://127.0.0.1:3001
[Nest] 3590  - 01/06/2026, 5:53:12 AM    WARN [CORSConfiguration] Object:
{
  "origin": "http://127.0.0.1:3001",
  "timestamp": "2026-01-06T05:53:12.791Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}

PASS src/modules/users/users-data-export.spec.ts
PASS src/config/secrets.config.spec.ts
  ● Console

    console.log
      ✅ Secret validation passed - All secrets meet security requirements

      at SecretsValidationService.log [as validateSecrets] (config/secrets-validation.service.ts:48:13)

    console.log
      ✅ Secret validation passed - All secrets meet security requirements

      at SecretsValidationService.log [as validateSecrets] (config/secrets-validation.service.ts:48:13)

PASS src/security/sql-injection-prevention.spec.ts
PASS src/modules/assessments/assessments.service.spec.ts
PASS src/common/services/encryption.service.spec.ts
PASS src/modules/consents/consents.controller.spec.ts
PASS src/common/interceptors/csrf.interceptor.spec.ts
PASS src/modules/users/users-account-deletion.spec.ts
PASS src/common/guards/csrf.guard.spec.ts
PASS src/config/request-size-limits.config.spec.ts
PASS src/common/guards/report-ownership.guard.spec.ts
PASS src/modules/algorithms/algorithms.service.spec.ts
PASS src/common/guards/assessment-ownership.guard.spec.ts
[Nest] 3590  - 01/06/2026, 5:53:17 AM   ERROR [DataRetentionService] [GDPR COMPLIANCE ERROR] Data retention enforcement failed: Database connection lost
Error: Database connection lost
    at Object.<anonymous> (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/src/common/services/data-retention.service.spec.ts:140:9)
    at Promise.then.completed (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/utils.js:298:28)
    at new Promise (<anonymous>)
    at callAsyncCircusFn (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/utils.js:231:10)
    at _callCircusTest (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:316:40)
    at processTicksAndRejections (node:internal/process/task_queues:95:5)
    at _runTest (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:252:3)
    at _runTestsForDescribeBlock (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:126:9)
    at _runTestsForDescribeBlock (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:121:9)
    at _runTestsForDescribeBlock (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:121:9)
    at run (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/run.js:71:3)
    at runAndTransformResultsToJestFormat (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/legacy-code-todo-rewrite/jestAdapterInit.js:122:21)
    at jestAdapter (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-circus/build/legacy-code-todo-rewrite/jestAdapter.js:79:19)
    at runTestInternal (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-runner/build/runTest.js:367:16)
    at runTest (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-runner/build/runTest.js:444:34)
    at Object.worker (/home/runner/work/financial-rise-report/financial-rise-report/financial-rise-app/backend/node_modules/jest-runner/build/testWorker.js:106:12)
PASS src/common/services/data-retention.service.spec.ts
PASS src/modules/questionnaire/questionnaire.controller.spec.ts
PASS src/modules/auth/strategies/local.strategy.spec.ts
PASS src/modules/auth/services/token-blacklist.service.spec.ts (5.188 s)
PASS src/common/guards/processing-restriction.guard.spec.ts
PASS src/modules/algorithms/algorithms.controller.spec.ts
[Nest] 3597  - 01/06/2026, 5:53:19 AM   ERROR [HTTP] Request failed: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM   ERROR [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "error": "Test error",
  "statusCode": 500,
  "duration": "4ms",
  "timestamp": "2026-01-06T05:53:19.756Z"
}

PASS src/common/interceptors/logging.interceptor.spec.ts
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-06T05:53:19.717Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "2ms",
  "timestamp": "2026-01-06T05:53:19.719Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-06T05:53:19.722Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "1ms",
  "timestamp": "2026-01-06T05:53:19.723Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-06T05:53:19.746Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "0ms",
  "timestamp": "2026-01-06T05:53:19.746Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/auth/login
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/auth/login",
  "body": {
    "email": "***@test.com",
    "password": "[REDACTED - PASSWORD]"
  },
  "timestamp": "2026-01-06T05:53:19.751Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Request completed: POST /api/auth/login
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/auth/login",
  "statusCode": 200,
  "duration": "0ms",
  "timestamp": "2026-01-06T05:53:19.751Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-06T05:53:19.752Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-06T05:53:19.761Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "1ms",
  "timestamp": "2026-01-06T05:53:19.762Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Incoming request: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "controller": "TestController",
  "handler": "testHandler",
  "method": "POST",
  "url": "/api/test",
  "body": {
    "email": "***@example.com",
    "password": "[REDACTED - PASSWORD]",
    "name": "J***"
  },
  "user": {
    "id": "user-123",
    "email": "***@test.com"
  },
  "timestamp": "2026-01-06T05:53:19.764Z"
}

[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Request completed: POST /api/test
[Nest] 3597  - 01/06/2026, 5:53:19 AM     LOG [HTTP] Object:
{
  "method": "POST",
  "url": "/api/test",
  "statusCode": 200,
  "duration": "1ms",
  "timestamp": "2026-01-06T05:53:19.764Z"
}

PASS src/modules/auth/guards/roles.guard.spec.ts
PASS src/modules/assessments/assessments.controller.spec.ts
PASS src/modules/users/users.controller.spec.ts
PASS src/modules/questions/questions.service.spec.ts
PASS src/modules/auth/guards/jwt-auth.guard.spec.ts
PASS src/common/transformers/encrypted-column.transformer.spec.ts
PASS src/modules/questions/questions.controller.spec.ts
PASS src/modules/auth/guards/local-auth.guard.spec.ts
-------------------------------------|---------|----------|---------|---------|-------------------------------------------
File                                 | % Stmts | % Branch | % Funcs | % Lines | Uncovered Line #s                         
-------------------------------------|---------|----------|---------|---------|-------------------------------------------
All files                            |   85.11 |    74.95 |   81.72 |   85.09 |                                           
 common/decorators                   |      90 |      100 |      50 |     100 |                                           
  allow-when-restricted.decorator.ts |     100 |      100 |     100 |     100 |                                           
  public.decorator.ts                |      80 |      100 |       0 |     100 |                                           
 common/guards                       |     100 |      100 |     100 |     100 |                                           
  assessment-ownership.guard.ts      |     100 |      100 |     100 |     100 |                                           
  csrf.guard.ts                      |     100 |      100 |     100 |     100 |                                           
  processing-restriction.guard.ts    |     100 |      100 |     100 |     100 |                                           
  report-ownership.guard.ts          |     100 |      100 |     100 |     100 |                                           
 common/interceptors                 |   97.29 |       75 |     100 |   97.05 |                                           
  csrf.interceptor.ts                |     100 |      100 |     100 |     100 |                                           
  logging.interceptor.ts             |   95.65 |    66.66 |     100 |   95.23 | 22                                        
 common/services                     |    98.8 |       76 |     100 |   98.75 |                                           
  data-retention.service.ts          |     100 |    66.66 |     100 |     100 | 155-160                                   
  encryption.service.ts              |    97.5 |    84.61 |     100 |   97.36 | 71                                        
 common/transformers                 |     100 |      100 |     100 |     100 |                                           
  encrypted-column.transformer.ts    |     100 |      100 |     100 |     100 |                                           
 common/utils                        |   77.59 |    83.33 |   58.82 |   79.65 |                                           
  log-sanitizer.ts                   |   95.94 |    96.15 |   95.23 |   96.47 | 149,266,306,345,426                       
  pii-safe-logger.ts                 |       0 |        0 |       0 |       0 | 1-130                                     
 config                              |   80.87 |     70.9 |   73.07 |   80.44 |                                           
  cors.config.ts                     |    87.5 |    66.66 |      80 |    87.5 | 36-39                                     
  request-size-limits.config.ts      |   58.69 |    57.14 |   42.85 |   58.69 | 114-128,147-164                           
  secrets-validation.service.ts      |   90.47 |       84 |     100 |   90.24 | 79,83,93,112                              
  secrets.service.ts                 |   96.77 |    44.44 |     100 |   96.66 | 92                                        
  security-headers.config.ts         |       0 |      100 |       0 |       0 | 22-101                                    
  typeorm.config.ts                  |   96.96 |      100 |     100 |   96.77 | 52                                        
 modules/algorithms                  |   80.86 |    35.29 |   88.88 |   81.65 |                                           
  algorithms.controller.ts           |     100 |       75 |     100 |     100 | 184                                       
  algorithms.service.ts              |   73.17 |    31.91 |   81.81 |   74.35 | 192,231-232,256-279,312-323               
 modules/algorithms/disc             |    97.5 |    95.65 |     100 |   97.29 |                                           
  disc-calculator.service.ts         |    97.5 |    95.65 |     100 |   97.29 | 62-63                                     
 modules/algorithms/phase            |   97.14 |    90.47 |     100 |   96.92 |                                           
  phase-calculator.service.ts        |   97.14 |    90.47 |     100 |   96.92 | 249-250                                   
 modules/assessments                 |    78.7 |    69.44 |   82.35 |   80.61 |                                           
  assessments.controller.ts          |   96.15 |      100 |   85.71 |   95.83 | 190                                       
  assessments.service.ts             |   73.17 |    65.62 |      80 |   75.67 | 80,179-229                                
 modules/assessments/services        |   98.29 |    85.45 |     100 |   98.11 |                                           
  progress.service.ts                |     100 |       70 |     100 |     100 | 70,116-163                                
  validation.service.ts              |   97.36 |    88.88 |     100 |   97.14 | 100,154                                   
 modules/auth                        |    64.2 |    62.79 |      60 |   64.11 |                                           
  auth.controller.ts                 |       0 |        0 |       0 |       0 | 1-105                                     
  auth.service.ts                    |   71.79 |       60 |   77.77 |    71.3 | 34-73,155,185,196,265-292,299,307,312-313 
  refresh-token.service.ts           |     100 |      100 |     100 |     100 |                                           
 modules/auth/decorators             |   66.66 |      100 |       0 |   71.42 |                                           
  get-user.decorator.ts              |      50 |      100 |       0 |      50 | 4-5                                       
  roles.decorator.ts                 |      80 |      100 |       0 |     100 |                                           
 modules/auth/guards                 |     100 |      100 |     100 |     100 |                                           
  jwt-auth.guard.ts                  |     100 |      100 |     100 |     100 |                                           
  local-auth.guard.ts                |     100 |      100 |     100 |     100 |                                           
  roles.guard.ts                     |     100 |      100 |     100 |     100 |                                           
 modules/auth/services               |     100 |      100 |     100 |     100 |                                           
  token-blacklist.service.ts         |     100 |      100 |     100 |     100 |                                           
 modules/auth/strategies             |     100 |      100 |     100 |     100 |                                           
  jwt.strategy.ts                    |     100 |      100 |     100 |     100 |                                           
  local.strategy.ts                  |     100 |      100 |     100 |     100 |                                           
 modules/consents                    |     100 |    76.19 |     100 |     100 |                                           
  consents.controller.ts             |     100 |     92.3 |     100 |     100 | 53                                        
  consents.service.ts                |     100 |       50 |     100 |     100 | 21-65                                     
 modules/questionnaire               |     100 |    94.11 |     100 |     100 |                                           
  questionnaire.controller.ts        |     100 |      100 |     100 |     100 |                                           
  questionnaire.service.ts           |     100 |    94.11 |     100 |     100 | 70                                        
 modules/questions                   |     100 |      100 |     100 |     100 |                                           
  questions.controller.ts            |     100 |      100 |     100 |     100 |                                           
  questions.service.ts               |     100 |      100 |     100 |     100 |                                           
 modules/users                       |   69.66 |    61.11 |   65.85 |   69.18 |                                           
  users.controller.ts                |   79.54 |     62.5 |      70 |   78.57 | 132-136,152-156,173-177                   
  users.service.ts                   |   66.41 |       60 |   64.51 |   66.15 | 147,265,280-303,333-334,350-445           
-------------------------------------|---------|----------|---------|---------|-------------------------------------------
Jest: "global" coverage threshold for branches (79%) not met: 74.95%

Test Suites: 44 passed, 44 total
Tests:       908 passed, 908 total
Snapshots:   0 total
Time:        34.641 s
Ran all test suites.
Error: Process completed with exit code 1.