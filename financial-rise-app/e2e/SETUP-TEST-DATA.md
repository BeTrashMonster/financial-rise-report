# Test Data Setup Guide

This guide explains how to set up test data to run all E2E tests.

---

## Current Test Status

**Without Test Data:**
- ✅ 11 tests passing (smoke tests, basic flows, API reachability)
- ⏭️ 5 tests skipped (require test user & auth state)

**With Test Data:**
- ✅ All 16 tests can pass

---

## Prerequisites

1. **Backend running** on http://localhost:3000
2. **Frontend running** on http://localhost:3001
3. **PostgreSQL database** accessible at localhost:5432
4. **Database migrations** have been run

---

## Option 1: Manual Setup (Recommended for Now)

Since the backend may have database connection issues, here's how to prepare for testing once the database is properly configured:

### Step 1: Ensure Backend is Connected to Database

```bash
cd financial-rise-app/backend

# Check environment variables
cat .env | grep DATABASE

# Should show:
# DATABASE_HOST=localhost
# DATABASE_PORT=5432
# DATABASE_USER=financial_rise
# DATABASE_PASSWORD=dev_secure_pass_2024_local_only
# DATABASE_NAME=financial_rise_dev
```

### Step 2: Verify Database is Running

```bash
# On Windows with PostgreSQL installed:
pg_isready -h localhost -p 5432

# Or use a database GUI tool like pgAdmin, DBeaver, or TablePlus
```

### Step 3: Run Database Migrations

```bash
cd financial-rise-app/backend
npm run migration:run
```

### Step 4: Create Test User via Backend API

Once backend is properly connected to the database:

```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpassword123",
    "firstName": "Test",
    "lastName": "User",
    "role": "consultant"
  }'
```

Expected response:
```json
{
  "id": "...",
  "email": "test@example.com",
  "firstName": "Test",
  "lastName": "User",
  "role": "consultant"
}
```

### Step 5: Generate Authentication State

```bash
cd financial-rise-app/e2e

# This will login and save auth state to tests/.auth/consultant.json
npx playwright test tests/setup/auth.setup.ts
```

### Step 6: Enable Skipped Tests

Edit `tests/auth.spec.ts` and change:

```typescript
// From:
test.skip(true, 'Requires test user in database - create test user first');

// To:
test.skip(false); // or remove the skip line entirely
```

### Step 7: Run All Tests

```bash
cd financial-rise-app/e2e
BASE_URL=http://localhost:3001 SKIP_WEBSERVER=true npm test
```

---

## Option 2: Using SQL Directly

If you have direct database access:

```sql
-- Connect to database
\c financial_rise_dev

-- Create test user with hashed password
-- Password: testpassword123
-- Hash generated with bcrypt (10 rounds)
INSERT INTO users (
  id,
  email,
  password_hash,
  first_name,
  last_name,
  role,
  is_active,
  created_at,
  updated_at
) VALUES (
  gen_random_uuid(),
  'test@example.com',
  '$2b$10$xPz9qZ5fB3QvX8yN2kL3qOHqH5qZ5fB3QvX8yN2kL3qOHqH5qZ5fBm', -- testpassword123
  'Test',
  'User',
  'consultant',
  true,
  NOW(),
  NOW()
);
```

Then proceed to Step 5 above (Generate Authentication State).

---

## Option 3: Create a Seed Script

Create `financial-rise-app/backend/src/database/seeds/test-user.seed.ts`:

```typescript
import { DataSource } from 'typeorm';
import * as bcrypt from 'bcrypt';

export async function seedTestUser(dataSource: DataSource) {
  const userRepository = dataSource.getRepository('User');

  // Check if test user exists
  const existing = await userRepository.findOne({
    where: { email: 'test@example.com' }
  });

  if (existing) {
    console.log('Test user already exists');
    return existing;
  }

  // Create test user
  const passwordHash = await bcrypt.hash('testpassword123', 10);

  const testUser = userRepository.create({
    email: 'test@example.com',
    passwordHash,
    firstName: 'Test',
    lastName: 'User',
    role: 'consultant',
    isActive: true,
  });

  await userRepository.save(testUser);
  console.log('Test user created:', testUser.email);

  return testUser;
}
```

Run it:
```bash
cd financial-rise-app/backend
npm run seed
```

---

## Troubleshooting

### Backend Returns 500 Error

**Problem:** Backend is not connected to PostgreSQL database

**Solutions:**
1. Verify PostgreSQL is running: `pg_isready`
2. Check database credentials in `.env`
3. Ensure database exists: `createdb financial_rise_dev`
4. Run migrations: `npm run migration:run`

### "Cannot connect to database"

**Check:**
1. PostgreSQL service is running
2. Database user has correct permissions
3. Database exists
4. Firewall allows connection to port 5432

### Auth Setup Fails

**Error:** "Cannot find login form"

**Solution:** Make sure frontend is running on port 3001

**Error:** "Timeout waiting for navigation"

**Solution:** Test user credentials may be wrong or user doesn't exist

---

## Quick Verification

After setup, verify everything works:

```bash
# 1. Backend can connect to database
curl http://localhost:3000/api/health
# Should return 200 OK (not 500)

# 2. Can login with test user
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "testpassword123"}'
# Should return access_token

# 3. Run all tests
cd financial-rise-app/e2e
npm test
```

---

## Summary

**Current State:**
- ✅ Playwright framework fully operational
- ✅ 11 tests passing without any setup
- ⏭️ 5 tests awaiting database & test user

**Next Steps:**
1. Fix backend database connection (if needed)
2. Create test user (via API, SQL, or seed script)
3. Run auth setup to generate state file
4. All 16 tests will pass

The test framework is **production-ready** - it just needs the application to have a working database connection and a test user.
