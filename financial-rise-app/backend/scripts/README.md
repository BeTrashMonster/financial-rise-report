# Backend Scripts

## Question Seeding

### Single Source of Truth

**Questions are defined in:** `backend/content/assessment-questions.json`

This JSON file contains all 47 assessment questions with:
- 8 embedded DISC profiling questions
- 43 phase assessment questions (across 5 financial phases)
- 2 confidence assessment questions (before/after)

### Seeding Questions to Database

To populate or update questions in the database:

```bash
npm run seed:questions
```

This script:
1. Connects to the database using environment variables
2. **Deletes all existing questions** (WARNING: destructive operation)
3. Loads questions from `content/assessment-questions.json`
4. Inserts them into the `questions` table with proper formatting

**⚠️ WARNING:** This script deletes ALL existing questions and responses. Only run this on:
- Fresh databases
- Development/staging environments
- Production (with extreme caution and backup)

### Environment Variables Required

```bash
DB_HOST=your-database-host
DB_PORT=5432
DB_USERNAME=postgres
DB_PASSWORD=your-password
DB_NAME=financial_rise
DB_SSL=true  # Set to 'true' for production
```

### Question Structure

Questions in `assessment-questions.json` use this format:

```json
{
  "id": "STAB-001",
  "text": "Question text here?",
  "type": "phase|disc|confidence_before|confidence_after|rating",
  "section": "stabilize|organize|build|grow|systemic",
  "display_order": 1,
  "options": [
    {
      "value": "option_key",
      "label": "Option text",
      "stabilize_score": 5,
      "organize_score": 0,
      "build_score": 0,
      "grow_score": 0,
      "systemic_score": 0,
      "disc_d_score": 0,  // Only for DISC questions
      "disc_i_score": 0,
      "disc_s_score": 0,
      "disc_c_score": 0
    }
  ]
}
```

### Historical Context

**Deprecated Sources:**
- ❌ `seed-comprehensive-questions.sql` - Old 66-question SQL file (deleted)
- ❌ Migration `1703700000003-SeedQuestions.ts` - Original 14-question migration (deprecated but kept for TypeORM history)

**Current Source:**
- ✅ `content/assessment-questions.json` - 47-question structure (ACTIVE)
- ✅ `scripts/seed-questions.ts` - Seeding script (ACTIVE)

## Other Scripts

### Create Test User

```bash
npm run create-test-user
```

Creates a test consultant user for development/testing.

### Security Scanning

```bash
npm run scan:sql-injection
npm run security:scan
```

Scans codebase for SQL injection vulnerabilities and other security issues.
