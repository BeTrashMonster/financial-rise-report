# Financial RISE Report - Database Design

**Version:** 1.0
**Date:** 2025-12-19
**Database:** PostgreSQL 14+

## Table of Contents
1. [Overview](#overview)
2. [Entity Relationship Diagram](#entity-relationship-diagram)
3. [Table Definitions](#table-definitions)
4. [Indexes](#indexes)
5. [Constraints](#constraints)
6. [Data Types and Enumerations](#data-types-and-enumerations)

---

## Overview

This document defines the complete database schema for the Financial RISE Report application. The schema supports:
- User authentication and authorization (Consultants, Admins)
- Assessment management with DISC profiling
- Phase determination and scoring
- Report generation and storage
- Action item checklists (Phase 2)
- Scheduler integration (Phase 2)
- Activity logging and audit trails

**Key Design Principles:**
- **Referential Integrity:** All foreign keys properly defined with cascade rules
- **Data Integrity:** Check constraints, unique constraints, and NOT NULL where appropriate
- **Performance:** Indexes on all frequently queried columns
- **Auditability:** Created/updated timestamps on all tables
- **Soft Deletes:** Deleted_at column for soft delete support
- **Scalability:** Normalized structure with appropriate denormalization where needed

---

## Entity Relationship Diagram

```
┌─────────────┐
│   users     │
└──────┬──────┘
       │ 1
       │
       │ N
┌──────┴──────────┐         ┌─────────────────┐
│  assessments    │────────▶│ disc_profiles   │
└──────┬──────────┘   1:1   └─────────────────┘
       │ 1
       │                     ┌─────────────────┐
       │ N                   │ phase_results   │
┌──────┴──────────┐   1:1   └─────────────────┘
│   responses     │◀────────┐
└─────────────────┘          │
                             │
┌─────────────────┐          │
│   questions     │──────────┘
└─────────────────┘   N:1

┌──────────────────┐
│     reports      │
└───────┬──────────┘
        │ N
        │
        │ 1
┌───────┴──────────┐
│   assessments    │
└───────┬──────────┘
        │ 1
        │
        │ N
┌───────┴──────────┐
│  checklist_items │
└──────────────────┘

┌──────────────────┐
│ activity_logs    │
└───────┬──────────┘
        │ N
        │
        │ 1
┌───────┴──────────┐
│     users        │
└──────────────────┘

┌──────────────────────┐
│ consultant_settings  │
└───────┬──────────────┘
        │ 1
        │
        │ 1
┌───────┴──────────┐
│     users        │
└──────────────────┘

┌──────────────────────┐
│ scheduler_links      │
└───────┬──────────────┘
        │ N
        │
        │ 1
┌───────┴──────────┐
│     users        │
└──────────────────┘
```

---

## Table Definitions

### 1. users

Stores consultant and administrator user accounts.

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('consultant', 'admin')),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    account_locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

COMMENT ON TABLE users IS 'Consultant and administrator user accounts';
COMMENT ON COLUMN users.password_hash IS 'bcrypt hash with work factor 12';
COMMENT ON COLUMN users.failed_login_attempts IS 'Count of failed login attempts, reset on successful login';
COMMENT ON COLUMN users.account_locked_until IS 'Account lock expiration timestamp (set after 5 failed attempts)';
COMMENT ON COLUMN users.password_reset_token IS 'Token for password reset flow, expires after 24 hours or first use';
```

### 2. assessments

Stores client assessment records with metadata.

```sql
CREATE TABLE assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consultant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_name VARCHAR(100) NOT NULL,
    client_business_name VARCHAR(200) NOT NULL,
    client_email VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('draft', 'in_progress', 'completed')) DEFAULT 'draft',
    entity_type VARCHAR(100),
    is_s_corp_on_payroll BOOLEAN,
    confidence_before INTEGER CHECK (confidence_before >= 1 AND confidence_before <= 10),
    confidence_after INTEGER CHECK (confidence_after >= 1 AND confidence_after <= 10),
    progress_percentage DECIMAL(5,2) NOT NULL DEFAULT 0.00 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    archived_at TIMESTAMP
);

CREATE INDEX idx_assessments_consultant_id ON assessments(consultant_id);
CREATE INDEX idx_assessments_status ON assessments(status);
CREATE INDEX idx_assessments_client_email ON assessments(client_email);
CREATE INDEX idx_assessments_created_at ON assessments(created_at DESC);

COMMENT ON TABLE assessments IS 'Client assessment records';
COMMENT ON COLUMN assessments.entity_type IS 'Business entity type: Sole Proprietor, LLC, S-Corp, C-Corp, Partnership, etc.';
COMMENT ON COLUMN assessments.is_s_corp_on_payroll IS 'For S-Corp entities, tracks if owner is on payroll (compliance check)';
COMMENT ON COLUMN assessments.confidence_before IS 'Client confidence rating before assessment (1-10 scale)';
COMMENT ON COLUMN assessments.confidence_after IS 'Client confidence rating after assessment (1-10 scale)';
```

### 3. questions

Stores assessment question bank with DISC and phase mapping.

```sql
CREATE TABLE questions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    question_text TEXT NOT NULL,
    question_type VARCHAR(50) NOT NULL CHECK (question_type IN ('single_choice', 'multiple_choice', 'rating', 'text')),
    section VARCHAR(100) NOT NULL CHECK (section IN ('stabilize', 'organize', 'build', 'grow', 'systemic', 'disc', 'metadata')),
    order_index INTEGER NOT NULL,
    is_required BOOLEAN NOT NULL DEFAULT true,
    is_conditional BOOLEAN NOT NULL DEFAULT false,
    conditional_parent_id UUID REFERENCES questions(id),
    conditional_trigger_value TEXT,
    disc_trait_mapping JSONB,
    phase_weight_mapping JSONB,
    answer_options JSONB,
    help_text TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_questions_section ON questions(section);
CREATE INDEX idx_questions_order ON questions(order_index);
CREATE INDEX idx_questions_conditional_parent ON questions(conditional_parent_id);

COMMENT ON TABLE questions IS 'Assessment question bank with DISC and phase mapping';
COMMENT ON COLUMN questions.disc_trait_mapping IS 'JSON mapping of answer options to DISC traits: {"D": 3, "I": 1, "S": 0, "C": 2}';
COMMENT ON COLUMN questions.phase_weight_mapping IS 'JSON mapping of answer options to phase weights: {"stabilize": 2, "organize": 1}';
COMMENT ON COLUMN questions.answer_options IS 'JSON array of answer options for choice-based questions: [{"value": "option1", "label": "Option 1"}]';
COMMENT ON COLUMN questions.conditional_trigger_value IS 'Answer value that triggers conditional child questions';
```

### 4. responses

Stores individual assessment question responses.

```sql
CREATE TABLE responses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    answer_value TEXT,
    answer_numeric INTEGER,
    is_not_applicable BOOLEAN NOT NULL DEFAULT false,
    consultant_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(assessment_id, question_id)
);

CREATE INDEX idx_responses_assessment_id ON responses(assessment_id);
CREATE INDEX idx_responses_question_id ON responses(question_id);

COMMENT ON TABLE responses IS 'Individual assessment question responses';
COMMENT ON COLUMN responses.answer_value IS 'Text response for text questions or selected option value';
COMMENT ON COLUMN responses.answer_numeric IS 'Numeric response for rating questions';
COMMENT ON COLUMN responses.is_not_applicable IS 'Flag for questions marked as N/A';
COMMENT ON COLUMN responses.consultant_notes IS 'Private notes added by consultant for this question';
```

### 5. disc_profiles

Stores calculated DISC personality profiles.

```sql
CREATE TABLE disc_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
    dominance_score DECIMAL(5,2) NOT NULL CHECK (dominance_score >= 0 AND dominance_score <= 100),
    influence_score DECIMAL(5,2) NOT NULL CHECK (influence_score >= 0 AND influence_score <= 100),
    steadiness_score DECIMAL(5,2) NOT NULL CHECK (steadiness_score >= 0 AND steadiness_score <= 100),
    compliance_score DECIMAL(5,2) NOT NULL CHECK (compliance_score >= 0 AND compliance_score <= 100),
    primary_type VARCHAR(20) NOT NULL CHECK (primary_type IN ('D', 'I', 'S', 'C')),
    secondary_type VARCHAR(20) CHECK (secondary_type IN ('D', 'I', 'S', 'C')),
    calculated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_disc_profiles_assessment_id ON disc_profiles(assessment_id);
CREATE INDEX idx_disc_profiles_primary_type ON disc_profiles(primary_type);

COMMENT ON TABLE disc_profiles IS 'Calculated DISC personality profiles for assessments';
COMMENT ON COLUMN disc_profiles.dominance_score IS 'D score (0-100)';
COMMENT ON COLUMN disc_profiles.influence_score IS 'I score (0-100)';
COMMENT ON COLUMN disc_profiles.steadiness_score IS 'S score (0-100)';
COMMENT ON COLUMN disc_profiles.compliance_score IS 'C score (0-100)';
COMMENT ON COLUMN disc_profiles.secondary_type IS 'Secondary DISC type if scores are close (optional)';
```

### 6. phase_results

Stores calculated financial readiness phase results.

```sql
CREATE TABLE phase_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
    stabilize_score DECIMAL(5,2) NOT NULL CHECK (stabilize_score >= 0 AND stabilize_score <= 100),
    organize_score DECIMAL(5,2) NOT NULL CHECK (organize_score >= 0 AND organize_score <= 100),
    build_score DECIMAL(5,2) NOT NULL CHECK (build_score >= 0 AND build_score <= 100),
    grow_score DECIMAL(5,2) NOT NULL CHECK (grow_score >= 0 AND grow_score <= 100),
    systemic_score DECIMAL(5,2) NOT NULL CHECK (systemic_score >= 0 AND systemic_score <= 100),
    primary_phase VARCHAR(50) NOT NULL CHECK (primary_phase IN ('stabilize', 'organize', 'build', 'grow', 'systemic')),
    secondary_phases TEXT[],
    calculated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_phase_results_assessment_id ON phase_results(assessment_id);
CREATE INDEX idx_phase_results_primary_phase ON phase_results(primary_phase);

COMMENT ON TABLE phase_results IS 'Calculated financial readiness phase results';
COMMENT ON COLUMN phase_results.secondary_phases IS 'Array of secondary phases if client is in transition';
```

### 7. reports

Stores generated report metadata and storage links.

```sql
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL CHECK (report_type IN ('consultant', 'client')),
    file_url TEXT NOT NULL,
    file_size_bytes BIGINT,
    page_count INTEGER,
    generated_by UUID NOT NULL REFERENCES users(id),
    is_shared BOOLEAN NOT NULL DEFAULT false,
    share_token VARCHAR(255) UNIQUE,
    share_expires_at TIMESTAMP,
    view_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reports_assessment_id ON reports(assessment_id);
CREATE INDEX idx_reports_type ON reports(report_type);
CREATE INDEX idx_reports_share_token ON reports(share_token);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);

COMMENT ON TABLE reports IS 'Generated report metadata and storage links';
COMMENT ON COLUMN reports.file_url IS 'S3 or cloud storage URL for PDF file';
COMMENT ON COLUMN reports.share_token IS 'Unique token for shareable report links';
COMMENT ON COLUMN reports.view_count IS 'Number of times report has been viewed (for shared links)';
```

### 8. activity_logs

Stores audit trail of user activities and system events.

```sql
CREATE TABLE activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL CHECK (event_category IN ('auth', 'assessment', 'report', 'admin', 'system')),
    description TEXT NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')) DEFAULT 'info',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_activity_logs_user_id ON activity_logs(user_id);
CREATE INDEX idx_activity_logs_event_type ON activity_logs(event_type);
CREATE INDEX idx_activity_logs_event_category ON activity_logs(event_category);
CREATE INDEX idx_activity_logs_severity ON activity_logs(severity);
CREATE INDEX idx_activity_logs_created_at ON activity_logs(created_at DESC);

COMMENT ON TABLE activity_logs IS 'Audit trail of user activities and system events';
COMMENT ON COLUMN activity_logs.metadata IS 'Additional event context in JSON format';
```

### 9. checklist_items (Phase 2)

Stores action item checklists for assessments.

```sql
CREATE TABLE checklist_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    item_text TEXT NOT NULL,
    item_order INTEGER NOT NULL,
    phase_category VARCHAR(50) CHECK (phase_category IN ('stabilize', 'organize', 'build', 'grow', 'systemic')),
    is_completed BOOLEAN NOT NULL DEFAULT false,
    completed_at TIMESTAMP,
    completed_by VARCHAR(50) CHECK (completed_by IN ('consultant', 'client')),
    priority VARCHAR(20) CHECK (priority IN ('low', 'medium', 'high')),
    due_date DATE,
    created_by UUID NOT NULL REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_checklist_items_assessment_id ON checklist_items(assessment_id);
CREATE INDEX idx_checklist_items_phase ON checklist_items(phase_category);
CREATE INDEX idx_checklist_items_completed ON checklist_items(is_completed);

COMMENT ON TABLE checklist_items IS 'Action item checklists for assessments (Phase 2)';
COMMENT ON COLUMN checklist_items.completed_by IS 'Who marked the item complete: consultant or client';
```

### 10. consultant_settings (Phase 2)

Stores consultant-specific settings and branding.

```sql
CREATE TABLE consultant_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consultant_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    company_name VARCHAR(200),
    logo_url TEXT,
    brand_color VARCHAR(7),
    email_signature TEXT,
    email_templates JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_consultant_settings_consultant_id ON consultant_settings(consultant_id);

COMMENT ON TABLE consultant_settings IS 'Consultant-specific settings and branding (Phase 2)';
COMMENT ON COLUMN consultant_settings.brand_color IS 'Hex color code for custom branding (e.g., #4B006E)';
COMMENT ON COLUMN consultant_settings.email_templates IS 'JSON storage for custom email templates';
```

### 11. scheduler_links (Phase 2)

Stores external scheduler integration links.

```sql
CREATE TABLE scheduler_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consultant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    meeting_type_label VARCHAR(100) NOT NULL,
    scheduler_url TEXT NOT NULL,
    duration_minutes INTEGER,
    recommended_for_phases TEXT[],
    is_active BOOLEAN NOT NULL DEFAULT true,
    display_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_scheduler_links_consultant_id ON scheduler_links(consultant_id);
CREATE INDEX idx_scheduler_links_active ON scheduler_links(is_active);

COMMENT ON TABLE scheduler_links IS 'External scheduler integration links (Phase 2)';
COMMENT ON COLUMN scheduler_links.meeting_type_label IS 'Display label: Initial Consultation, Follow-up Session, Deep Dive Review';
COMMENT ON COLUMN scheduler_links.recommended_for_phases IS 'Array of phases this meeting type is recommended for';
```

---

## Indexes

All indexes are documented inline with table definitions above. Key index strategies:

1. **Primary Keys:** UUID with gen_random_uuid() for distributed scalability
2. **Foreign Keys:** Indexed automatically for JOIN performance
3. **Frequently Filtered Columns:** status, created_at, email
4. **Search Columns:** email, client_email with B-tree indexes
5. **Timestamp Columns:** DESC ordering for recent-first queries

---

## Constraints

### Foreign Key Cascade Rules

- **assessments.consultant_id → users.id:** CASCADE DELETE (remove assessments when consultant deleted)
- **responses.assessment_id → assessments.id:** CASCADE DELETE (remove responses with assessment)
- **disc_profiles.assessment_id → assessments.id:** CASCADE DELETE (remove profile with assessment)
- **phase_results.assessment_id → assessments.id:** CASCADE DELETE (remove results with assessment)
- **reports.assessment_id → assessments.id:** CASCADE DELETE (remove reports with assessment)
- **activity_logs.user_id → users.id:** SET NULL (preserve logs even if user deleted)
- **checklist_items.assessment_id → assessments.id:** CASCADE DELETE
- **consultant_settings.consultant_id → users.id:** CASCADE DELETE
- **scheduler_links.consultant_id → users.id:** CASCADE DELETE

### Check Constraints

- **users.role:** Must be 'consultant' or 'admin'
- **assessments.status:** Must be 'draft', 'in_progress', or 'completed'
- **assessments.confidence_before/after:** 1-10 range
- **assessments.progress_percentage:** 0-100 range
- **questions.question_type:** Enumerated question types
- **questions.section:** Valid section names
- **disc_profiles.scores:** 0-100 range for all DISC dimensions
- **disc_profiles.primary_type/secondary_type:** Valid DISC types (D, I, S, C)
- **phase_results.scores:** 0-100 range for all phases
- **phase_results.primary_phase:** Valid phase names
- **reports.report_type:** 'consultant' or 'client'
- **activity_logs.event_category:** Enumerated categories
- **activity_logs.severity:** info, warning, error, critical

### Unique Constraints

- **users.email:** Globally unique
- **assessments + responses:** Unique (assessment_id, question_id) pair
- **disc_profiles.assessment_id:** One profile per assessment
- **phase_results.assessment_id:** One result set per assessment
- **reports.share_token:** Unique shareable tokens
- **consultant_settings.consultant_id:** One settings record per consultant

---

## Data Types and Enumerations

### Custom Types (Optional - can use VARCHARs with CHECK constraints)

```sql
-- User roles
CREATE TYPE user_role AS ENUM ('consultant', 'admin');

-- Assessment status
CREATE TYPE assessment_status AS ENUM ('draft', 'in_progress', 'completed');

-- Question types
CREATE TYPE question_type AS ENUM ('single_choice', 'multiple_choice', 'rating', 'text');

-- Financial phases
CREATE TYPE financial_phase AS ENUM ('stabilize', 'organize', 'build', 'grow', 'systemic');

-- DISC types
CREATE TYPE disc_type AS ENUM ('D', 'I', 'S', 'C');

-- Report types
CREATE TYPE report_type AS ENUM ('consultant', 'client');

-- Event categories
CREATE TYPE event_category AS ENUM ('auth', 'assessment', 'report', 'admin', 'system');

-- Severity levels
CREATE TYPE severity_level AS ENUM ('info', 'warning', 'error', 'critical');

-- Priority levels
CREATE TYPE priority_level AS ENUM ('low', 'medium', 'high');
```

### JSON Schema Examples

**disc_trait_mapping (in questions table):**
```json
{
  "option1": {"D": 3, "I": 1, "S": 0, "C": 2},
  "option2": {"D": 1, "I": 3, "S": 2, "C": 0}
}
```

**phase_weight_mapping (in questions table):**
```json
{
  "option1": {"stabilize": 3, "organize": 1},
  "option2": {"stabilize": 0, "organize": 3, "build": 1}
}
```

**answer_options (in questions table):**
```json
[
  {"value": "option1", "label": "Yes, completely organized"},
  {"value": "option2", "label": "Partially organized"},
  {"value": "option3", "label": "Not organized"}
]
```

**email_templates (in consultant_settings table):**
```json
{
  "default": {
    "subject": "Your Financial Readiness Report",
    "body": "Hi {{client_name}},\n\nAttached is your personalized financial readiness report...",
    "variables": ["client_name", "business_name", "consultant_name"]
  }
}
```

---

## Migration Strategy

1. **Version Control:** All schema changes via numbered migration files
2. **Rollback Support:** Each migration includes up/down scripts
3. **Data Migration:** Separate data migration scripts for seed/test data
4. **Environment Parity:** Identical schema across dev/staging/prod
5. **Zero-Downtime:** Use online schema changes for production (no locks)

---

## Performance Considerations

1. **Connection Pooling:** Min 5, Max 20 connections per app instance
2. **Query Optimization:** All foreign keys indexed, composite indexes where needed
3. **Pagination:** Limit/offset queries with created_at DESC ordering
4. **Caching Strategy:** Redis for session data, database for persistent data
5. **Partitioning:** Consider time-based partitioning for activity_logs if volume exceeds 10M rows

---

## Security Considerations

1. **Password Storage:** bcrypt with work factor 12
2. **Sensitive Data:** Encrypt DISC profiles and assessment responses at rest
3. **Access Control:** Row-level security via consultant_id filtering
4. **Audit Logging:** All data modifications logged to activity_logs
5. **Backup Encryption:** All database backups encrypted at rest

---

**Document Status:** Complete
**Next Steps:**
1. Create TypeORM entities
2. Create migration files
3. Create seed data scripts
