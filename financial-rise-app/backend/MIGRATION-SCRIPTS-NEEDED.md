# Database Migration Scripts Needed

This document outlines the database migration scripts that need to be created for the security vulnerability fixes.

**Status:** Migrations documented, awaiting DevOps Agent to generate actual migration files.

## Prerequisites

Before running migrations, ensure TypeORM CLI is configured:

```bash
# Install TypeORM CLI globally (if not already installed)
npm install -g typeorm

# Or use npx
npx typeorm
```

## Migration 1: Add reset_password_used_at Column

**Purpose:** Prevent reset token reuse attacks

**Entity Change:** `src/modules/users/entities/user.entity.ts`
- Added: `reset_password_used_at` column (TIMESTAMP, nullable)

**Migration Script:**

```bash
npx typeorm migration:create src/database/migrations/AddResetPasswordUsedAt
```

**Migration Content:**

```typescript
import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class AddResetPasswordUsedAt1234567890123 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'reset_password_used_at',
        type: 'timestamp',
        isNullable: true,
        default: null,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropColumn('users', 'reset_password_used_at');
  }
}
```

## Migration 2: Create refresh_tokens Table

**Purpose:** Support multiple devices per user and proper token revocation

**Entity:** `src/modules/auth/entities/refresh-token.entity.ts` (NEW)

**Migration Script:**

```bash
npx typeorm migration:create src/database/migrations/CreateRefreshTokensTable
```

**Migration Content:**

```typescript
import { MigrationInterface, QueryRunner, Table, TableIndex, TableForeignKey } from 'typeorm';

export class CreateRefreshTokensTable1234567890124 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create refresh_tokens table
    await queryRunner.createTable(
      new Table({
        name: 'refresh_tokens',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'user_id',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'token',
            type: 'varchar',
            length: '255',
            isUnique: true,
            isNullable: false,
          },
          {
            name: 'expires_at',
            type: 'timestamp',
            isNullable: false,
          },
          {
            name: 'revoked_at',
            type: 'timestamp',
            isNullable: true,
            default: null,
          },
          {
            name: 'device_info',
            type: 'varchar',
            length: '50',
            isNullable: true,
            default: null,
          },
          {
            name: 'ip_address',
            type: 'varchar',
            length: '45',
            isNullable: true,
            default: null,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'now()',
            isNullable: false,
          },
        ],
      }),
      true,
    );

    // Create index on user_id
    await queryRunner.createIndex(
      'refresh_tokens',
      new TableIndex({
        name: 'IDX_refresh_tokens_user_id',
        columnNames: ['user_id'],
      }),
    );

    // Create index on token
    await queryRunner.createIndex(
      'refresh_tokens',
      new TableIndex({
        name: 'IDX_refresh_tokens_token',
        columnNames: ['token'],
      }),
    );

    // Create foreign key to users table
    await queryRunner.createForeignKey(
      'refresh_tokens',
      new TableForeignKey({
        name: 'FK_refresh_tokens_user_id',
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key
    await queryRunner.dropForeignKey('refresh_tokens', 'FK_refresh_tokens_user_id');

    // Drop indexes
    await queryRunner.dropIndex('refresh_tokens', 'IDX_refresh_tokens_token');
    await queryRunner.dropIndex('refresh_tokens', 'IDX_refresh_tokens_user_id');

    // Drop table
    await queryRunner.dropTable('refresh_tokens');
  }
}
```

## Migration 3: (Optional) Remove refresh_token Column from Users Table

**Purpose:** Clean up deprecated column now that we use refresh_tokens table

**Note:** This should only be done AFTER verifying the new refresh_tokens table is working properly in production.

**Migration Script:**

```bash
npx typeorm migration:create src/database/migrations/RemoveUserRefreshTokenColumn
```

**Migration Content:**

```typescript
import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

export class RemoveUserRefreshTokenColumn1234567890125 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // First, ensure all users have null refresh_token (safety check)
    await queryRunner.query(`UPDATE users SET refresh_token = NULL WHERE refresh_token IS NOT NULL`);

    // Drop the column
    await queryRunner.dropColumn('users', 'refresh_token');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Restore the column if needed
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'refresh_token',
        type: 'varchar',
        length: '255',
        isNullable: true,
        default: null,
      }),
    );
  }
}
```

## Running Migrations

### Development Environment

```bash
# 1. Generate migrations (if using auto-generation)
npm run typeorm migration:generate -- -n SecurityFixes

# 2. Run migrations
npm run typeorm migration:run

# 3. Verify migrations
npm run typeorm migration:show
```

### Production Environment

```bash
# 1. Backup database first!
pg_dump -U postgres -d financial_rise_production > backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Run migrations
NODE_ENV=production npm run typeorm migration:run

# 3. Verify migrations
NODE_ENV=production npm run typeorm migration:show

# 4. Test application
# ... perform smoke tests ...

# 5. If issues occur, revert
NODE_ENV=production npm run typeorm migration:revert
```

## Testing Migration Scripts

### Test on Local Database

```bash
# 1. Create test database
createdb financial_rise_test

# 2. Run migrations
DATABASE_NAME=financial_rise_test npm run typeorm migration:run

# 3. Verify schema
psql financial_rise_test -c "\d users"
psql financial_rise_test -c "\d refresh_tokens"

# 4. Test revert
DATABASE_NAME=financial_rise_test npm run typeorm migration:revert

# 5. Clean up
dropdb financial_rise_test
```

### Verify Migration Safety

```sql
-- Check that reset_password_used_at column exists
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'users'
  AND column_name = 'reset_password_used_at';

-- Check that refresh_tokens table exists
SELECT table_name
FROM information_schema.tables
WHERE table_name = 'refresh_tokens';

-- Check foreign key constraint
SELECT constraint_name, table_name, constraint_type
FROM information_schema.table_constraints
WHERE table_name = 'refresh_tokens'
  AND constraint_type = 'FOREIGN KEY';

-- Check indexes
SELECT indexname, indexdef
FROM pg_indexes
WHERE tablename = 'refresh_tokens';
```

## Rollback Plan

If migrations cause issues in production:

```bash
# 1. Immediate rollback
npm run typeorm migration:revert

# 2. Restore from backup (if needed)
psql -U postgres -d financial_rise_production < backup_YYYYMMDD_HHMMSS.sql

# 3. Restart application
pm2 restart financial-rise-backend
```

## Post-Migration Verification

### Verify Security Features

```bash
# Test 1: Password complexity validation
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"weak","firstName":"Test","lastName":"User"}'
# Expected: 400 Bad Request with password complexity error

# Test 2: Reset token reuse prevention
# (Use /auth/forgot-password and /auth/reset-password endpoints)

# Test 3: Multiple device logins
# (Login from multiple clients, verify separate refresh tokens in database)

# Test 4: Token revocation
# (Test logout, verify tokens are revoked in database)
```

### Database Queries for Verification

```sql
-- Check for users with reset_password_used_at set
SELECT id, email, reset_password_used_at
FROM users
WHERE reset_password_used_at IS NOT NULL;

-- Check active refresh tokens
SELECT user_id, COUNT(*) as active_sessions
FROM refresh_tokens
WHERE revoked_at IS NULL
  AND expires_at > NOW()
GROUP BY user_id;

-- Check revoked tokens
SELECT user_id, COUNT(*) as revoked_sessions
FROM refresh_tokens
WHERE revoked_at IS NOT NULL
GROUP BY user_id;
```

## Data Migration (if needed)

If there are existing users with refresh tokens in the old format:

```sql
-- No data migration needed because:
-- 1. Old refresh_token column in users table will be deprecated
-- 2. New refresh_tokens table starts fresh
-- 3. Existing users will get new tokens on next login
-- 4. Old tokens will naturally expire within 7 days

-- Optional: Clear all existing refresh_token values
UPDATE users SET refresh_token = NULL WHERE refresh_token IS NOT NULL;
```

## Monitoring Post-Migration

### Metrics to Track

1. **Failed Login Attempts**
   - Monitor for increased failures due to password complexity

2. **Refresh Token Usage**
   - Track number of active sessions per user
   - Monitor token revocation events

3. **Password Reset Flow**
   - Monitor reset token usage
   - Track reuse attempts (should be blocked)

4. **Database Performance**
   - Monitor query performance on refresh_tokens table
   - Ensure indexes are being used

### Cleanup Task

Set up a cron job to clean up expired/revoked tokens:

```typescript
// In a scheduled task service
@Cron('0 2 * * *') // Run daily at 2 AM
async cleanupTokens() {
  const deletedCount = await this.refreshTokenService.cleanupExpiredTokens();
  this.logger.log(`Cleaned up ${deletedCount} expired refresh tokens`);
}
```

## Checklist

- [ ] Migration 1: AddResetPasswordUsedAt created
- [ ] Migration 2: CreateRefreshTokensTable created
- [ ] Migrations tested on local database
- [ ] Migrations tested on staging database
- [ ] Backup plan documented
- [ ] Rollback tested
- [ ] Production database backed up
- [ ] Migrations run in production
- [ ] Post-migration verification completed
- [ ] Monitoring configured
- [ ] Cleanup task scheduled
- [ ] Documentation updated
- [ ] Team notified of changes

---

**Created:** 2025-12-27
**Owner:** Backend Agent 1
**Status:** Awaiting DevOps Agent to generate migration scripts
**Next Step:** DevOps Agent should run TypeORM migration generation and execute these migrations
