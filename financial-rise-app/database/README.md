# Financial RISE - Database Documentation

**Version:** 1.0.0
**Database:** PostgreSQL 14+
**Last Updated:** 2025-12-19

## Overview

This document describes the database schema for the Financial RISE Report application.

## Schema Structure

The database is organized into the following functional areas:

### 1. Users and Authentication
- `users` - Consultant and admin users
- `refresh_tokens` - JWT refresh token management
- `password_reset_tokens` - Password reset workflow

### 2. Consultant Settings
- `consultant_branding` - Logo, colors, company info
- `consultant_scheduler_settings` - Calendly/Acuity integration URLs

### 3. Questionnaire Content
- `questions` - Assessment questions with DISC/phase mapping
- `question_options` - Multiple choice options with scoring
- `question_conditionals` - Conditional question logic (Phase 3)

### 4. Assessments
- `assessments` - Client assessment sessions
- `assessment_responses` - Client answers to questions
- `assessment_confidence` - Before/after confidence scores

### 5. DISC and Phase Results
- `disc_profiles` - DISC personality analysis results
- `phase_results` - Financial readiness phase determination

### 6. Reports
- `reports` - Generated PDF reports (S3 references)
- `shareable_report_links` - Secure share links with optional passwords

### 7. Action Checklists (Phase 2)
- `checklist_items` - Action items from recommendations

### 8. Email Templates (Phase 2)
- `email_templates` - Custom email templates per consultant

### 9. Activity Logging
- `activity_logs` - Audit trail of all system activities

### 10. Analytics
- `system_metrics` - System performance and usage metrics

## Key Design Decisions

### 1. UUID Primary Keys
All tables use UUIDs for primary keys to:
- Avoid exposing sequential IDs
- Enable distributed systems
- Improve security

### 2. ENUM Types
PostgreSQL ENUMs are used for:
- `user_role`: consultant, admin
- `user_status`: active, inactive, locked
- `assessment_status`: draft, in_progress, completed, archived
- `financial_phase`: stabilize, organize, build, grow, systemic
- `disc_type`: D, I, S, C
- `question_type`: multiple_choice, yes_no, scale, text
- `report_type`: consultant, client
- `activity_type`: Various system activities

### 3. Soft Deletes and Archiving
- Assessments can be archived (not deleted)
- Activity logs are never deleted (audit compliance)
- Users can be deactivated instead of deleted

### 4. Timestamps
All tables include:
- `created_at` - Record creation time
- `updated_at` - Last modification time (auto-updated via trigger)

### 5. Indexes
Strategic indexes on:
- Foreign keys
- Frequently queried columns (email, status, created_at)
- Composite indexes for complex queries

## Data Relationships

### Core Entity Relationships

```
users (consultants)
  └─ assessments
       ├─ assessment_responses
       │    └─ question_options
       ├─ disc_profiles
       ├─ phase_results
       ├─ assessment_confidence
       ├─ checklist_items
       └─ reports
            └─ shareable_report_links
```

### Question System

```
questions
  ├─ question_options (scoring data)
  └─ question_conditionals (conditional logic)
```

## DISC Scoring Algorithm

DISC scores are calculated from `question_options`:
- Each option has `disc_d_score`, `disc_i_score`, `disc_s_score`, `disc_c_score`
- Scores are aggregated across all responses
- Highest score determines `primary_type`
- Second highest determines `secondary_type`

## Phase Determination Algorithm

Financial phase is determined from `question_options`:
- Each option has `phase_stabilize_score`, `phase_organize_score`, etc.
- Scores are weighted by question importance
- Highest score determines `primary_phase`
- Can support multiple phases if scores are close (Phase 3)

## Security Considerations

### Password Storage
- Passwords are hashed using bcrypt (implemented in application layer)
- Never store plaintext passwords
- Minimum 10 rounds for bcrypt

### Token Management
- JWT refresh tokens stored in database
- Tokens can be revoked
- Automatic cleanup of expired tokens

### Account Lockout
- Failed login attempts tracked in `users.failed_login_attempts`
- Account locked after 5 failed attempts
- `locked_until` timestamp for automatic unlock

### Audit Trail
- All significant actions logged in `activity_logs`
- IP address and user agent captured
- Cannot be modified or deleted

## Performance Optimizations

### Indexes
All foreign keys are indexed automatically. Additional indexes:
- `idx_users_email` - Fast user lookup
- `idx_assessments_consultant_id` - Consultant's assessments
- `idx_assessments_created_at` - Recent assessments
- `idx_activity_logs_created_at` - Recent activity

### Views
Pre-computed views for common queries:
- `v_assessment_overview` - Assessment summary with related data
- `v_user_activity_summary` - User statistics

### Connection Pooling
Use connection pooling (configured in application):
- Min connections: 5
- Max connections: 20
- Idle timeout: 10 seconds

## Migrations

### Initial Setup

```sql
-- Run schema creation
psql -U postgres -d financial_rise_db -f schema.sql

-- Run seed data
psql -U postgres -d financial_rise_db -f seed.sql
```

### Using TypeORM Migrations (Recommended)

```bash
# Generate migration
npm run migration:generate -- -n MigrationName

# Run migrations
npm run migration:run

# Revert last migration
npm run migration:revert
```

## Backup Strategy

### Automated Backups
- Daily automated backups via AWS RDS
- 7-day retention (configurable)
- Point-in-time recovery enabled

### Manual Backups

```bash
# Create backup
pg_dump -U postgres -d financial_rise_db -F c -b -v -f backup_$(date +%Y%m%d).dump

# Restore backup
pg_restore -U postgres -d financial_rise_db -v backup_20251219.dump
```

## Data Retention

### Retention Periods
- Active assessments: Indefinite
- Archived assessments: 7 years (compliance)
- Activity logs: 1 year
- Refresh tokens: Auto-delete after expiration
- Password reset tokens: Auto-delete after 24 hours

### Data Cleanup

```sql
-- Delete expired refresh tokens
DELETE FROM refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP;

-- Delete expired password reset tokens
DELETE FROM password_reset_tokens WHERE expires_at < CURRENT_TIMESTAMP;

-- Archive old activity logs (after 1 year)
DELETE FROM activity_logs WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 year';
```

## Query Examples

### Get all assessments for a consultant

```sql
SELECT * FROM v_assessment_overview
WHERE consultant_email = 'consultant@example.com'
ORDER BY created_at DESC;
```

### Calculate consultant performance

```sql
SELECT
    u.email,
    COUNT(*) AS total_assessments,
    COUNT(*) FILTER (WHERE a.status = 'completed') AS completed,
    AVG(EXTRACT(EPOCH FROM (a.completed_at - a.started_at))/3600) AS avg_hours
FROM users u
JOIN assessments a ON u.id = a.consultant_id
WHERE u.role = 'consultant'
GROUP BY u.id, u.email;
```

### Find assessments needing follow-up

```sql
SELECT
    a.id,
    a.client_name,
    a.updated_at,
    CURRENT_TIMESTAMP - a.updated_at AS time_since_update
FROM assessments a
WHERE a.status = 'in_progress'
  AND a.updated_at < CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY a.updated_at ASC;
```

## Troubleshooting

### Common Issues

**Issue:** Slow assessment queries
**Solution:** Ensure indexes are created, run `ANALYZE assessments;`

**Issue:** Connection pool exhausted
**Solution:** Increase max connections or optimize slow queries

**Issue:** Disk space full
**Solution:** Archive old activity logs, clean up expired tokens

### Performance Monitoring

```sql
-- Check table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

## References

- [PostgreSQL 14 Documentation](https://www.postgresql.org/docs/14/)
- [TypeORM Documentation](https://typeorm.io/)
- [Database Best Practices](https://wiki.postgresql.org/wiki/Don%27t_Do_This)
