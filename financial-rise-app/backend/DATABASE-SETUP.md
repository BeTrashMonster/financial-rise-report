# Database Setup Guide

## Overview

This guide provides instructions for setting up the PostgreSQL database for the Financial RISE backend.

## Prerequisites

- PostgreSQL 14+ installed
- Node.js 18+ installed
- npm packages installed (`npm install`)

## Quick Start

### 1. Create Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database and user
CREATE DATABASE financial_rise_dev;
CREATE USER financial_rise WITH PASSWORD 'financial_rise_dev';
GRANT ALL PRIVILEGES ON DATABASE financial_rise_dev TO financial_rise;

# Exit psql
\q
```

### 2. Configure Environment

Copy `.env.local` and update if needed:

```bash
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_USER=financial_rise
DATABASE_PASSWORD=financial_rise_dev
DATABASE_NAME=financial_rise_dev
DATABASE_SSL=false
```

### 3. Run Migrations

```bash
npm run migration:run
```

Expected output:
```
Migration InitialSchema1703700000001 has been executed successfully.
Migration AddRefreshTokensAndReportsTables1703700000002 has been executed successfully.
Migration SeedQuestions1703700000003 has been executed successfully.
```

### 4. Verify Setup

```bash
# Connect to database
psql -U financial_rise -d financial_rise_dev

# Check tables
\dt

# Should see:
# assessments
# assessment_responses
# disc_profiles
# phase_results
# questions
# refresh_tokens
# reports
# users

# Check question count
SELECT COUNT(*) FROM questions;
# Should return: 14

# Exit
\q
```

## Migration Files

### 1703700000001-InitialSchema.ts

Creates core tables:
- **users** - Consultant and admin accounts
- **assessments** - Client assessments
- **assessment_responses** - Question responses
- **questions** - Question bank
- **disc_profiles** - DISC personality results
- **phase_results** - Financial phase results

Includes:
- Foreign key constraints
- Indexes for performance
- ENUM types for status fields
- Soft delete support (deleted_at)

### 1703700000002-AddRefreshTokensAndReportsTables.ts

Adds:
- **refresh_tokens** - Multi-device JWT refresh token support
- **reports** - Generated PDF report tracking
- **reset_password_used_at** column to users table (prevents token reuse)

### 1703700000003-SeedQuestions.ts

Seeds 14 initial questions:
- 2 confidence rating questions (before/after)
- 3 financial stability questions
- 3 organization questions
- 2 build phase questions
- 2 grow phase questions
- 3 systemic (financial literacy) questions

Each question includes:
- DISC scoring weights (D, I, S, C)
- Phase scoring weights (Stabilize, Organize, Build, Grow, Systemic)

## Available Commands

```bash
# Run all pending migrations
npm run migration:run

# Revert last migration
npm run migration:revert

# Create new empty migration
npm run migration:create src/database/migrations/MigrationName

# Generate migration from entity changes (requires running database)
npm run migration:generate src/database/migrations/MigrationName
```

## Database Schema

### Users Table

```sql
users
├── id (UUID, PK)
├── email (VARCHAR 255, UNIQUE)
├── password_hash (VARCHAR 255)
├── first_name (VARCHAR 100)
├── last_name (VARCHAR 100)
├── role (ENUM: consultant, admin)
├── status (ENUM: active, inactive, locked)
├── failed_login_attempts (INT)
├── locked_until (TIMESTAMP)
├── reset_password_token (VARCHAR 255)
├── reset_password_expires (TIMESTAMP)
├── reset_password_used_at (TIMESTAMP)
├── refresh_token (VARCHAR 255)
├── created_at (TIMESTAMP)
├── updated_at (TIMESTAMP)
└── last_login_at (TIMESTAMP)
```

### Assessments Table

```sql
assessments
├── id (UUID, PK)
├── consultant_id (UUID, FK → users.id)
├── client_name (VARCHAR 100)
├── business_name (VARCHAR 100)
├── client_email (VARCHAR 255)
├── status (ENUM: draft, in_progress, completed)
├── progress (DECIMAL 5,2)
├── notes (TEXT)
├── created_at (TIMESTAMP)
├── updated_at (TIMESTAMP)
├── started_at (TIMESTAMP)
├── completed_at (TIMESTAMP)
└── deleted_at (TIMESTAMP) -- Soft delete
```

### Questions Table

```sql
questions
├── id (UUID, PK)
├── question_key (VARCHAR 50, UNIQUE)
├── question_text (TEXT)
├── question_type (ENUM: single_choice, multiple_choice, rating, text)
├── options (JSONB)
├── required (BOOLEAN)
├── display_order (INT)
├── created_at (TIMESTAMP)
└── updated_at (TIMESTAMP)
```

### Assessment Responses Table

```sql
assessment_responses
├── id (UUID, PK)
├── assessment_id (UUID, FK → assessments.id)
├── question_id (VARCHAR 50, FK → questions.question_key)
├── answer (JSONB)
├── not_applicable (BOOLEAN)
├── consultant_notes (TEXT)
└── answered_at (TIMESTAMP)
```

## Troubleshooting

### Connection Refused

If you get `ECONNREFUSED ::1:5432`:

1. Check if PostgreSQL is running:
   ```bash
   # Windows
   net start postgresql-x64-14

   # Linux/Mac
   sudo systemctl status postgresql
   ```

2. Verify connection settings in `.env.local`

### Permission Denied

If you get permission errors:

```bash
# Grant all privileges on database
psql -U postgres
GRANT ALL PRIVILEGES ON DATABASE financial_rise_dev TO financial_rise;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO financial_rise;
```

### Migration Already Ran

If migrations fail because they've already run:

```bash
# Check migration status
psql -U financial_rise -d financial_rise_dev
SELECT * FROM migrations;

# Revert if needed
npm run migration:revert
```

### Clean Slate

To completely reset the database:

```bash
# Drop and recreate database
psql -U postgres
DROP DATABASE financial_rise_dev;
CREATE DATABASE financial_rise_dev;
GRANT ALL PRIVILEGES ON DATABASE financial_rise_dev TO financial_rise;
\q

# Run migrations again
npm run migration:run
```

## Production Deployment

For production:

1. **Never use synchronize: true** - Already set to false in config
2. **Use environment variables** - Configure via secrets manager
3. **Enable SSL** - Set `DATABASE_SSL=true`
4. **Backup before migrations** - Always backup production data first
5. **Test in staging** - Run migrations in staging environment first

### Production Migration Process

```bash
# 1. Backup database
pg_dump -U financial_rise financial_rise_prod > backup.sql

# 2. Test migrations in staging
DATABASE_NAME=financial_rise_staging npm run migration:run

# 3. Verify staging works
# ... run tests, manual QA ...

# 4. Run in production during maintenance window
DATABASE_NAME=financial_rise_prod npm run migration:run

# 5. Verify production
# ... smoke tests ...
```

## Next Steps

1. Start the NestJS backend: `npm run start:dev`
2. Verify entities load correctly
3. Test API endpoints
4. Run integration tests

## Questions or Issues?

See:
- `NESTJS-CONSOLIDATION-PLAN.md` - Migration plan
- `API-CONTRACT.md` - API specifications
- `IMPLEMENTATION-STATUS.md` - Current status
- `TEAM-COORDINATION.md` - Team updates
