# URGENT: Assessment Flow Fixes Needed

**Date:** 2026-01-06
**Issues:** 3 critical blockers preventing assessment completion

---

## 🔴 Critical Issues

### Issue 1: BUILD-007 Multiple Choice Still Broken
**Symptom:** Can only select one option, should allow multiple
**Status:** Likely the seed script ran but question type is still `single_choice` in database

### Issue 2: Auto-Save "Internal Server Error"
**Symptom:** Upper right corner shows "Internal Server Error" on all questions
**Status:** POST `/api/v1/questionnaire/responses` is failing with 500

### Issue 3: "View Results" Button Goes Nowhere
**Symptom:** Click "View Results" after assessment complete, nothing happens
**Status:** Navigation not triggering or submission endpoint failing

---

## 📋 Diagnostic Steps (Do These First)

### Step 1: Check Browser Console Errors

**In your browser:**
1. Press F12 to open DevTools
2. Go to Console tab
3. Clear console (trash can icon)
4. Complete an assessment question
5. **Copy/paste ALL error messages** you see

**Look for errors like:**
- `POST /api/v1/questionnaire/responses 500 (Internal Server Error)`
- `POST /api/v1/assessments/:id/submit 404 (Not Found)`
- `TypeError: Cannot read property...`
- Any stack traces

### Step 2: Check Network Tab

**In DevTools:**
1. Go to Network tab
2. Filter by "XHR" or "Fetch"
3. Try to answer a question (trigger auto-save)
4. Look for failed requests (red status codes)
5. Click the failed request
6. Go to "Response" tab
7. **Copy/paste the error response**

---

## 🔧 Manual Fixes (SSH into Production VM)

###Connect to VM:
```bash
gcloud compute ssh financial-rise-prod-vm --zone=us-central1-a
```

### Fix 1: Check and Fix BUILD-007 Question Type

```bash
# Connect to database
docker exec -it financial-rise-backend-prod psql -U postgres -d financial_rise

# Check BUILD-007 question type
SELECT question_key, question_type
FROM questions
WHERE question_text LIKE '%automated%';

# If it shows 'single_choice', update it to 'multiple_choice':
UPDATE questions
SET question_type = 'multiple_choice'
WHERE question_text LIKE '%automated%';

# Verify the change
SELECT question_key, question_type
FROM questions
WHERE question_text LIKE '%automated%';

# Exit database
\q
```

### Fix 2: Check Backend Logs for Auto-Save Errors

```bash
# View recent backend errors
docker logs financial-rise-backend-prod --tail 100 | grep -A 5 "Error\|500\|fail"

# Watch logs in real-time while testing
docker logs -f financial-rise-backend-prod
```

**Look for:**
- SQL errors (table not found, column not found)
- TypeScript errors (undefined property)
- Validation errors

### Fix 3: Check Database Schema

```bash
# Connect to database
docker exec -it financial-rise-backend-prod psql -U postgres -d financial_rise

# Check if assessment_responses table exists
\dt

# Check table structure
\d assessment_responses

# Check if there are responses being saved
SELECT COUNT(*) FROM assessment_responses;

# Check recent responses
SELECT id, assessment_id, question_id, created_at
FROM assessment_responses
ORDER BY created_at DESC
LIMIT 5;

# Exit
\q
```

### Fix 4: Check Assessment Submission

```bash
# Connect to database
docker exec -it financial-rise-backend-prod psql -U postgres -d financial_rise

# Check recent assessments
SELECT id, status, completed_at, created_at
FROM assessments
ORDER BY created_at DESC
LIMIT 5;

# Check if any are COMPLETED
SELECT id, status
FROM assessments
WHERE status = 'COMPLETED';

# Exit
\q
```

---

## 🚨 Common Errors and Quick Fixes

### Error: "Column 'not_applicable' does not exist"
**Fix:**
```bash
docker exec -it financial-rise-backend-prod npm run migration:run
```

### Error: "Table 'assessment_responses' does not exist"
**Fix:**
```bash
docker exec -it financial-rise-backend-prod npm run migration:run
```

### Error: "ECONNREFUSED" or "Database connection failed"
**Fix:**
```bash
# Check if database is running
docker ps | grep postgres

# If not, start it
cd /opt/financial-rise-backend
docker-compose up -d database
```

### Error: BUILD-007 Still Single Choice After Update
**Fix:**
```bash
# Force frontend to clear cache
# In browser DevTools Console:
localStorage.clear();
location.reload();
```

---

## ✅ ROOT CAUSE IDENTIFIED

**Issue:** Missing `answered_at` column in `assessment_responses` table

**Proof:** Backend logs show:
```
ERROR [ExceptionsHandler] column Assessment__Assessment_responses.answered_at does not exist
```

**Impact:** ALL auto-save and submission requests fail with 500 errors

**Fix:** Run `fix-database-schema.sh` on production VM

**See:** `DATABASE-SCHEMA-FIX-GUIDE.md` for complete instructions

---

## 🎯 Expected Behavior (After Fixes)

✅ **BUILD-007**: Shows checkboxes, allows selecting multiple options
✅ **Auto-Save**: Shows "Saving..." → "Saved" (no errors)
✅ **View Results**: Navigates to `/assessments/:id/results` page
✅ **Results Page**: Shows DISC profile, phase results, "Generate Reports" button

---

## 📞 Quick Communication

When you respond, just give me:
1. The console error messages (copy/paste)
2. Whether you can SSH into the VM and run the SQL queries
3. If not, I'll create a different approach

Then I'll write the exact fixes needed!

---

**Created:** 2026-01-06
**Priority:** P0 (Blocking all testing)
**Next:** Await diagnostic info from user
