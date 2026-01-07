# Database Schema Fix Guide

**Date:** 2026-01-06
**Issue:** Auto-save and submission both failing with 500 errors
**Root Cause:** Missing `answered_at` column in `assessment_responses` table

---

## The Problem

### Error in Logs:
```
ERROR [ExceptionsHandler] column Assessment__Assessment_responses.answered_at does not exist
QueryFailedError: column Assessment__Assessment_responses.answered_at does not exist
```

### Impact:
- ❌ Auto-save completely broken (500 errors on all questions)
- ❌ Assessment submission broken (500 errors)
- ❌ "View Results" navigation never happens
- ❌ BUILD-007 multiple choice can't be tested

### Technical Details:

**File:** `backend/src/modules/assessments/entities/assessment-response.entity.ts:69-70`

The TypeORM entity expects this column:
```typescript
@Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
answered_at: Date;
```

But the database table is missing this column, causing TypeORM queries to crash.

---

## How to Fix

### Option 1: Run the Automated Fix Script (RECOMMENDED)

1. **SSH into production VM:**
   ```bash
   gcloud compute ssh financial-rise-prod-vm --zone=us-central1-a
   ```

2. **Copy the fix script to the VM:**

   On your local machine (PowerShell):
   ```powershell
   gcloud compute scp C:\Users\Admin\src\fix-database-schema.sh financial-rise-prod-vm:~/fix-database-schema.sh --zone=us-central1-a
   ```

3. **Run the script on the VM:**
   ```bash
   chmod +x fix-database-schema.sh
   ./fix-database-schema.sh
   ```

The script will:
- ✅ Find the database container automatically
- ✅ Check current schema
- ✅ Add the `answered_at` column with correct type and default
- ✅ Verify the fix
- ✅ Restart the backend container

---

### Option 2: Manual Fix

If the script fails, you can fix manually:

1. **Find the database container:**
   ```bash
   docker ps --format "{{.Names}}" | grep -i "postgres\|database\|db"
   ```

2. **Connect to the database:**
   ```bash
   # Replace <DB_CONTAINER_NAME> with the name from step 1
   docker exec -i <DB_CONTAINER_NAME> psql -U postgres -d financial_rise
   ```

3. **Check current schema:**
   ```sql
   \d assessment_responses
   ```

4. **Add the missing column:**
   ```sql
   ALTER TABLE assessment_responses
   ADD COLUMN answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
   ```

5. **Verify it was added:**
   ```sql
   SELECT column_name, data_type, column_default
   FROM information_schema.columns
   WHERE table_name = 'assessment_responses' AND column_name = 'answered_at';
   ```

6. **Exit database:**
   ```sql
   \q
   ```

7. **Restart backend:**
   ```bash
   docker restart financial-rise-backend-prod
   ```

---

## Testing the Fix

After running the fix:

1. **Wait 10-15 seconds** for the backend to fully restart

2. **Open the production site:**
   ```
   https://getoffthemoneyshametrain.com
   ```

3. **Open DevTools (F12)** → Console tab

4. **Clear console** (trash icon or Ctrl+L)

5. **Start or continue an assessment**

6. **Answer a question** and watch for:
   - ✅ "Saving..." indicator appears
   - ✅ "Saved" indicator appears (green checkmark)
   - ❌ NO "Internal Server Error" message
   - ✅ Console shows: `POST /api/v1/questionnaire/responses` → **200 OK**

7. **Complete the assessment:**
   - Rate confidence (1-10)
   - Click "View Results"
   - ✅ Should navigate to `/assessments/:id/results`
   - ✅ Should see DISC profile and phase results

---

## Why This Happened

This is a **database migration synchronization issue**. The entity was updated to include `answered_at`, but:

1. Either the migration didn't run on production
2. Or the migration file is missing
3. Or TypeORM synchronization is disabled (it should be in production)

**TypeORM Migrations:**
The proper way to handle schema changes is through migrations:
```bash
npm run migration:generate -- -n AddAnsweredAtColumn
npm run migration:run
```

But since migrations may not be set up correctly in production, we're manually adding the column.

---

## Other Potential Missing Columns

While we're at it, let's verify ALL columns match the entity definition:

**Expected columns in `assessment_responses` table:**
1. `id` (uuid, primary key)
2. `assessment_id` (uuid)
3. `question_id` (varchar 50)
4. `answer` (text, encrypted)
5. `not_applicable` (boolean, default false)
6. `consultant_notes` (text, nullable)
7. `answered_at` (timestamp, default CURRENT_TIMESTAMP) ← **THIS ONE IS MISSING**

The fix script will show you all current columns so you can verify.

---

## Next Steps After Fix

Once auto-save works:

1. ✅ **Fix BUILD-007** - Verify multiple choice works
2. ✅ **Test complete flow** - Questionnaire → Submit → Results
3. ✅ **Verify DISC calculation** - Check database for disc_profiles
4. ✅ **Verify phase calculation** - Check database for phase_results
5. ✅ **Generate reports** - Test consultant + client PDFs
6. ✅ **Continue Reports Quality Roadmap** - Content audit, DISC personalization

---

## If the Fix Doesn't Work

If you still see 500 errors after the fix:

1. **Check backend logs:**
   ```bash
   docker logs financial-rise-backend-prod --tail 50
   ```

2. **Check for other missing columns:**
   ```bash
   docker exec -i <DB_CONTAINER> psql -U postgres -d financial_rise -c "\d assessment_responses"
   ```

3. **Check TypeORM connection:**
   The backend might be caching the old schema. Try:
   ```bash
   docker restart financial-rise-backend-prod
   ```

4. **Provide the error messages:**
   - Backend logs
   - Browser console errors
   - Database schema output

---

## Summary

**The Fix:** Add `answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP` to `assessment_responses` table

**How:** Run `fix-database-schema.sh` on the production VM

**Expected Result:** Auto-save works, no more 500 errors, assessment flow completes

**Time:** ~2 minutes including backend restart

---

**Created:** 2026-01-06
**Priority:** P0 (Blocking all testing)
**Status:** Ready to execute
