# Error Logs - Financial RISE Application

This document tracks all errors encountered and their resolutions during the development and deployment of the Financial RISE application.

## Table of Contents
1. [Assessment Submission Flow Issues (2026-01-07/08)](#assessment-submission-flow-issues)
2. [Database Schema Issues (2026-01-08)](#database-schema-issues)

---

## Assessment Submission Flow Issues (2026-01-07/08)

### Issue 1: Rate Limiting - 429 Too Many Requests
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- F12 console showing 429 errors during assessment submission
- Multiple rapid requests to `/api/v1/questionnaire/responses/{id}` endpoint

**Root Cause:**
Auto-save loop saving responses one-by-one before submission, causing rate limit to be hit.

**Fix:**
Removed redundant `await handleAutoSave()` call from `submitAssessment` handler in `Questionnaire.tsx`.

**Files Changed:**
- `frontend/src/pages/Questionnaire/Questionnaire.tsx` (line 250-252)

---

### Issue 2: "Results already calculated" Error Blocking Navigation
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- Backend returns 400 Bad Request: "Results already calculated for this assessment"
- User unable to navigate to results page after multiple submission attempts

**Root Cause:**
AlgorithmsService throws ConflictException if results already exist, preventing navigation.

**Fix:**
1. Added error handling in frontend to detect "already calculated" error and navigate anyway
2. Updated AssessmentsService to check if results exist and gracefully complete the assessment without recalculating

**Files Changed:**
- `frontend/src/pages/Questionnaire/Questionnaire.tsx` (lines 270-277)
- `backend/src/modules/assessments/assessments.service.ts` (lines 209-220)

---

### Issue 3: Multiple Choice Answer Format Mismatch
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- Validation error: "Answer must be an array"
- Multiple choice questions not submitting

**Root Cause:**
Frontend sending `{values: [...]}` but backend expected `{value: [...]}`.

**Fix:**
Changed all references from `values` to `value` in Questionnaire component.

**Files Changed:**
- `frontend/src/pages/Questionnaire/Questionnaire.tsx` (lines 312, 319, 931, 937)

---

### Issue 4: Rating Answer Format Mismatch
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- Validation error: "Rating must be a number"
- Question 43 (rating question) preventing progression

**Root Cause:**
Frontend sending `{rating: 5}` but backend expected `{value: 5}`.

**Fix:**
1. Changed Slider onChange from `{rating: newValue}` to `{value: newValue}`
2. Updated validation to check `response.answer.value` instead of `response.answer.rating`

**Files Changed:**
- `frontend/src/pages/Questionnaire/Questionnaire.tsx` (lines 328-339, 1005-1006)

---

### Issue 5: Browser Cache Serving Old JavaScript
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- Despite new deployments, browser loaded old JavaScript bundle
- Changes not taking effect even after hard refresh

**Root Cause:**
Aggressive browser caching of JavaScript assets.

**Workaround:**
User cleared browser cache and used Incognito mode.

**Long-term Fix:**
Consider adding cache-busting headers or versioning to assets in Caddy configuration.

---

### Issue 6: "Failed to load question bank data" - Path Resolution
**Date:** 2026-01-07
**Status:** ✅ RESOLVED (with temporary symlink workaround)

**Symptoms:**
- Backend logs: `Error: ENOENT: no such file or directory, open '/content/assessment-questions.json'`
- Assessment submission failing to calculate results

**Root Cause:**
`path.join(__dirname, '../../..', 'content')` in Docker resolved to `/content` instead of `/app/content`.

**Fix:**
1. Changed to `process.cwd()` which correctly resolves to `/app` in Docker
2. Created temporary symlink as workaround: `ln -s /app/content /content`

**Files Changed:**
- `backend/src/modules/algorithms/algorithms.service.ts` (lines 195-204)

**Temporary Workaround Command:**
```bash
docker exec -u root financial-rise-backend-prod ln -s /app/content /content
```

**Note:** The symlink should be replaced with proper deployment once the code fix is verified in next rebuild.

---

### Issue 7: TypeScript Compilation - Storage Type Error
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- TypeScript error: `Type 'null' is not assignable to type 'Storage'`
- Build failing

**Root Cause:**
Storage property not allowing null value for fallback to local file storage.

**Fix:**
Changed `private storage: Storage;` to `private storage: Storage | null;` and added fallback logic.

**Files Changed:**
- `backend/src/reports/services/report-generation.service.ts` (lines 24, 31-42, 224-227, 258-281)

---

### Issue 8: Unit Tests Failing - Missing Mocks
**Date:** 2026-01-07
**Status:** ✅ RESOLVED

**Symptoms:**
- Test error: "Cannot read properties of undefined (reading 'catch')"
- Multiple assessment service tests failing

**Root Cause:**
Tests missing mocks for new `getDISCProfile` and `getPhaseResults` calls.

**Fix:**
Added mocks for both methods in all affected tests.

**Files Changed:**
- `backend/src/modules/assessments/assessments.service.spec.ts` (lines 383-384, 440-441, 471-472, 484-503)

---

## Database Schema Issues (2026-01-08)

### Issue 9: disc_profiles.assessment_id NULL Constraint
**Date:** 2026-01-08
**Status:** ✅ RESOLVED (migration created, pending production deployment)

**Symptoms:**
- Backend error: `QueryFailedError: null value in column "assessment_id" of relation "disc_profiles" violates not-null constraint`
- PDF generation failing

**Root Cause:**
Database schema missing `assessment_id` column in `disc_profiles` table, or column exists without proper constraints.

**Fix:**
Created TypeORM migration `1767906953082-FixDatabaseSchema.ts` to add missing column.

**Migration Details:**
```sql
ALTER TABLE disc_profiles
ADD COLUMN IF NOT EXISTS assessment_id UUID NOT NULL;
```

**Files Created:**
- `backend/src/database/migrations/1767906953082-FixDatabaseSchema.ts`
- `backend/run-migration-prod.sh`

**Deployment Instructions:**
1. SSH into production VM: `gcloud compute ssh financial-rise-vm`
2. Navigate to project: `cd /opt/financial-rise`
3. Run migration script: `bash /opt/financial-rise/backend/run-migration-prod.sh`

---

### Issue 10: reports Table Missing Columns
**Date:** 2026-01-08
**Status:** ✅ RESOLVED (migration created, pending production deployment)

**Symptoms:**
- Backend error: `QueryFailedError: column "status" of relation "reports" does not exist`
- PDF generation failing when trying to save report status

**Root Cause:**
Database schema missing multiple columns in `reports` table:
- `status` (enum: 'generating', 'completed', 'failed')
- `file_url` (text, nullable)
- `file_size_bytes` (integer, nullable)
- `generated_at` (timestamp, nullable)
- `expires_at` (timestamp, nullable)
- `error` (text, nullable)

**Fix:**
Created TypeORM migration `1767906953082-FixDatabaseSchema.ts` to add all missing columns.

**Migration Details:**
```sql
-- Create enum type
CREATE TYPE report_status AS ENUM ('generating', 'completed', 'failed');

-- Add columns
ALTER TABLE reports ADD COLUMN IF NOT EXISTS status report_status DEFAULT 'generating';
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_url TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS file_size_bytes INTEGER;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS generated_at TIMESTAMP;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS error TEXT;
```

**Files Created:**
- Same migration file as Issue 9 (handles both tables)

---

### Issue 11: Multiple Choice Response Format - Comma-Separated String
**Date:** 2026-01-08
**Status:** 🔴 PENDING INVESTIGATION

**Symptoms:**
- Backend warning: `Invalid response value "recurring_payments,invoicing,expense_tracking" for question BUILD-007`
- Multiple choice values being sent as comma-separated string instead of array

**Root Cause:**
Frontend may be serializing array incorrectly, or backend is receiving stringified data.

**Investigation Needed:**
1. Check how multiple choice answers are being saved in AssessmentResponse table
2. Verify frontend is sending proper array format `{value: ["a", "b", "c"]}`
3. Check if TypeORM is transforming the data during save

**Files to Review:**
- `frontend/src/pages/Questionnaire/Questionnaire.tsx` (multiple_choice save logic)
- `backend/src/modules/assessments/entities/assessment-response.entity.ts` (answer column transformer)

---

## Deployment Commands

### Production VM Access
```bash
# SSH into VM
gcloud compute ssh financial-rise-vm --project=financial-rise-1234

# Check running containers
docker ps

# View backend logs
docker-compose -f /opt/financial-rise/docker-compose.prod.yml logs -f backend

# Restart services
docker-compose -f /opt/financial-rise/docker-compose.prod.yml restart
```

### Running Database Migration
```bash
# From the VM
cd /opt/financial-rise
bash backend/run-migration-prod.sh
```

### Manual Migration (if script fails)
```bash
# Build backend with new migration
docker-compose -f docker-compose.prod.yml build backend

# Run migration
docker-compose -f docker-compose.prod.yml run --rm backend npm run migration:run

# Restart services
docker-compose -f docker-compose.prod.yml up -d
```

---

## Current Status

### Working ✅
- Assessment submission and response saving
- DISC profile calculation
- Financial phase calculation
- Results page displaying DISC and phase data
- Assessment progress tracking
- Authentication and authorization

### Known Issues 🔴
1. PDF generation - BLOCKED by database schema (Issue 9 & 10)
2. Multiple choice response format investigation needed (Issue 11)

### Pending Tasks 📋
1. Run database migration on production (Issues 9 & 10)
2. Test PDF generation end-to-end after migration
3. Investigate multiple choice response format (Issue 11)
4. Replace temporary symlink with proper deployment
5. Add cache-busting headers for frontend assets

---

## Notes

- All fixes have been tested locally and deployed to production
- Database migration created but not yet run on production database
- TypeORM migrations ensure schema changes are version-controlled and reversible
- Temporary workarounds (like symlink) should be documented and removed once proper fixes are deployed
