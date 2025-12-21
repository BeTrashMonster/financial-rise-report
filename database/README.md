# Financial RISE Report - Database Documentation

**Version:** 1.0
**Date:** 2025-12-19
**Database:** PostgreSQL 14+
**ORM:** TypeORM

## Directory Structure

```
database/
├── schema/
│   ├── database-design.md      # Complete database design documentation
│   └── schema.sql              # Raw SQL schema definition
├── entities/
│   ├── User.ts                 # User entity (consultants, admins)
│   ├── Assessment.ts           # Assessment entity
│   ├── Question.ts             # Question bank entity
│   ├── Response.ts             # Assessment responses
│   ├── DiscProfile.ts          # DISC personality profiles
│   ├── PhaseResult.ts          # Financial phase results
│   ├── Report.ts               # Generated reports metadata
│   ├── ActivityLog.ts          # Audit logs
│   ├── ChecklistItem.ts        # Action items (Phase 2)
│   ├── ConsultantSettings.ts   # Consultant branding (Phase 2)
│   ├── SchedulerLink.ts        # Scheduler integration (Phase 2)
│   └── index.ts                # Entity exports
├── migrations/
│   ├── 001_initial_schema.ts   # Initial schema migration
│   └── 002_phase2_features.ts  # Phase 2 tables migration
├── seeds/
│   ├── 001_seed_users.sql      # Sample users for development
│   └── 002_seed_questions.sql  # Sample assessment questions
└── README.md                   # This file
```

## Quick Start

### 1. Database Setup

```bash
# Create PostgreSQL database
createdb financial_rise_dev

# Or using psql
psql -U postgres
CREATE DATABASE financial_rise_dev;
\q
```

### 2. Run Migrations

Using TypeORM CLI:

```bash
# Install TypeORM CLI globally (if not already installed)
npm install -g typeorm

# Run migrations
npm run typeorm migration:run

# Or with TypeORM CLI directly
typeorm-ts-node-commonjs migration:run -d path/to/data-source.ts
```

Using raw SQL (alternative):

```bash
# Apply initial schema
psql -U postgres -d financial_rise_dev -f schema/schema.sql

# Apply Phase 2 migration (when ready)
# This will be handled by TypeORM migrations in actual implementation
```

### 3. Seed Development Data

```bash
# Seed users
psql -U postgres -d financial_rise_dev -f seeds/001_seed_users.sql

# Seed questions
psql -U postgres -d financial_rise_dev -f seeds/002_seed_questions.sql
```

### 4. Verify Setup

```bash
# Connect to database
psql -U postgres -d financial_rise_dev

# List all tables
\dt

# Check user count
SELECT COUNT(*) FROM users;

# Check question count
SELECT COUNT(*) FROM questions;
```

## TypeORM Configuration

Example `data-source.ts`:

```typescript
import { DataSource } from 'typeorm';
import { entities } from './database/entities';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  username: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'financial_rise_dev',
  synchronize: false, // Never use in production
  logging: process.env.NODE_ENV === 'development',
  entities: entities,
  migrations: ['./database/migrations/*.ts'],
  subscribers: [],
});
```

## Entity Relationships

### Core Entities

```
User (1) ──── (N) Assessment
Assessment (1) ──── (N) Response
Assessment (1) ──── (1) DiscProfile
Assessment (1) ──── (1) PhaseResult
Assessment (1) ──── (N) Report
Question (1) ──── (N) Response
User (1) ──── (N) ActivityLog
```

### Phase 2 Entities

```
Assessment (1) ──── (N) ChecklistItem
User (1) ──── (1) ConsultantSettings
User (1) ──── (N) SchedulerLink
```

## Key Tables

### users
- **Purpose:** Store consultant and admin accounts
- **Key Fields:** email (unique), passwordHash, role, isActive
- **Relationships:** One-to-many with assessments, reports, logs

### assessments
- **Purpose:** Store client assessment records
- **Key Fields:** clientName, clientEmail, status, progressPercentage
- **Relationships:** Belongs to user, has many responses, has one discProfile, has one phaseResult

### questions
- **Purpose:** Store assessment question bank
- **Key Fields:** questionText, questionType, section, discTraitMapping, phaseWeightMapping
- **Relationships:** Has many responses, self-referential for conditional questions

### responses
- **Purpose:** Store individual question answers
- **Key Fields:** answerValue, answerNumeric, isNotApplicable, consultantNotes
- **Relationships:** Belongs to assessment and question

### disc_profiles
- **Purpose:** Store calculated DISC personality results
- **Key Fields:** dominanceScore, influenceScore, steadinessScore, complianceScore, primaryType
- **Relationships:** One-to-one with assessment

### phase_results
- **Purpose:** Store calculated financial readiness phase results
- **Key Fields:** stabilizeScore, organizeScore, buildScore, growScore, systemicScore, primaryPhase
- **Relationships:** One-to-one with assessment

### reports
- **Purpose:** Store generated report metadata and S3 links
- **Key Fields:** reportType, fileUrl, shareToken, viewCount
- **Relationships:** Belongs to assessment and user (generatedBy)

### activity_logs
- **Purpose:** Audit trail of all system activities
- **Key Fields:** eventType, eventCategory, severity, metadata
- **Relationships:** Belongs to user (nullable)

## Indexes

All tables include strategic indexes for performance:

- **Primary Keys:** All tables use UUID primary keys
- **Foreign Keys:** Automatically indexed for JOIN performance
- **Search Fields:** email, clientEmail indexed for lookups
- **Filter Fields:** status, section, eventCategory indexed
- **Timestamp Fields:** createdAt indexed with DESC for recent-first queries

## Security Features

1. **Password Hashing:** bcrypt with work factor 12
2. **Soft Deletes:** deletedAt column on user-facing tables
3. **Audit Logging:** All activities logged to activity_logs
4. **Row-Level Security:** consultantId filtering ensures data isolation
5. **Foreign Key Constraints:** CASCADE deletes for data integrity

## Development Credentials

**For development only - DO NOT use in production:**

- **Email:** admin@financialrise.com
- **Password:** SecurePass123!
- **Role:** admin

Sample consultants:
- john.smith@consultants.com
- sarah.johnson@consultants.com
- michael.chen@consultants.com

All use the same password: `SecurePass123!`

## Migration Best Practices

1. **Never edit existing migrations** - create new ones instead
2. **Always provide down() methods** for rollback capability
3. **Test migrations on a copy** of production data before deploying
4. **Use transactions** where possible to ensure atomicity
5. **Document breaking changes** in migration comments

## Maintenance Tasks

### Backup Database

```bash
# Full database backup
pg_dump -U postgres financial_rise_dev > backup_$(date +%Y%m%d).sql

# Schema only
pg_dump -U postgres --schema-only financial_rise_dev > schema_backup.sql

# Data only
pg_dump -U postgres --data-only financial_rise_dev > data_backup.sql
```

### Restore Database

```bash
# Restore full backup
psql -U postgres financial_rise_dev < backup_20251219.sql
```

### Reset Development Database

```bash
# Drop and recreate
dropdb financial_rise_dev
createdb financial_rise_dev

# Run migrations
npm run typeorm migration:run

# Seed data
psql -U postgres -d financial_rise_dev -f seeds/001_seed_users.sql
psql -U postgres -d financial_rise_dev -f seeds/002_seed_questions.sql
```

### Analyze Query Performance

```sql
-- Explain query plan
EXPLAIN ANALYZE
SELECT * FROM assessments
WHERE consultant_id = '00000000-0000-0000-0000-000000000002'
ORDER BY created_at DESC;

-- Check index usage
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

## Environment Variables

```bash
# Database Connection
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_secure_password
DB_NAME=financial_rise_dev

# Connection Pooling
DB_POOL_MIN=5
DB_POOL_MAX=20

# Logging
DB_LOGGING=true  # Set to false in production
```

## Troubleshooting

### Issue: Migration fails with "relation already exists"

**Solution:** Either drop the existing table or use `IF NOT EXISTS` in migration

```bash
# Check what tables exist
psql -U postgres -d financial_rise_dev -c "\dt"

# Drop specific table
psql -U postgres -d financial_rise_dev -c "DROP TABLE IF EXISTS table_name CASCADE"
```

### Issue: Foreign key constraint violation

**Solution:** Ensure parent records exist before creating child records

```bash
# Check referential integrity
SELECT * FROM users WHERE id = 'the-uuid-value';
```

### Issue: Slow queries

**Solution:** Check indexes and query plans

```sql
-- Missing indexes?
SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public';

-- Analyze table statistics
ANALYZE assessments;
```

## Next Steps

1. **Create Data Source Configuration:** Set up TypeORM DataSource with proper environment variables
2. **Implement Repositories:** Create repository pattern for data access
3. **Write Unit Tests:** Test entities and relationships
4. **Set up Migrations Pipeline:** Automate migration running in CI/CD
5. **Develop Seed Data:** Work with SME to create full question bank
6. **Performance Testing:** Load test with realistic data volumes

## References

- [TypeORM Documentation](https://typeorm.io/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Database Design Document](./schema/database-design.md)
- [Requirements Specification](../plans/requirements.md)

---

**Work Stream 2:** Database Schema & Data Model
**Status:** Complete ✅
**Date Completed:** 2025-12-19
