-- ============================================================================
-- Financial RISE Report - Production Database Initialization Script
-- ============================================================================
--
-- PURPOSE:
--   This script creates the complete database schema for the Financial RISE
--   Report application from scratch. It consolidates all TypeORM migrations
--   into a single SQL file for production database initialization.
--
-- WHEN TO USE:
--   - Initial production database setup
--   - Creating new development/staging environments
--   - Database recovery/restoration scenarios
--   - Container initialization scripts
--
-- REQUIREMENTS:
--   - PostgreSQL 14+ (uses gen_random_uuid(), JSONB, ENUM types)
--   - Database must exist (this script does NOT create the database)
--   - Run as a user with CREATE privilege
--
-- IMPORTANT NOTES:
--   - This script is idempotent (safe to run multiple times)
--   - Includes all schema changes from migrations 1703700000001 - 1735500000000
--   - Seeds 14 assessment questions with DISC/Phase scoring data
--   - Does NOT include encryption key setup (must be configured separately)
--   - Review GDPR/privacy fields before production deployment
--
-- EXECUTION:
--   psql -U your_user -d financial_rise_db -f init-production-database.sql
--
-- MAINTENANCE:
--   Generated: 2026-01-03
--   Last Migration: 1735500000000-AddDeviceInfoToRefreshTokens
--   Schema Version: 1.0
--
-- ============================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- SECTION 1: ENUM TYPES
-- ============================================================================
-- Create all ENUM types first (required by tables)
-- Using IF NOT EXISTS for idempotency
-- ============================================================================

DO $$ BEGIN
    CREATE TYPE user_role_enum AS ENUM ('consultant', 'admin');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE user_status_enum AS ENUM ('active', 'inactive', 'locked');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE assessment_status_enum AS ENUM ('draft', 'in_progress', 'completed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE question_type_enum AS ENUM ('single_choice', 'multiple_choice', 'rating', 'text');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE report_type_enum AS ENUM ('consultant', 'client');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE report_status_enum AS ENUM ('generating', 'completed', 'failed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Note: The following ENUMs are created inline by CREATE TABLE statements below
-- They are defined here for documentation purposes but not created separately:
-- - consent_type_enum: ('essential', 'analytics', 'marketing')
-- - objection_type_enum: ('marketing', 'analytics', 'profiling')

-- ============================================================================
-- SECTION 2: CORE TABLES
-- ============================================================================
-- Create all tables in dependency order
-- Tables with no foreign keys first, then dependent tables
-- ============================================================================

-- ----------------------------------------------------------------------------
-- TABLE: users
-- ----------------------------------------------------------------------------
-- Core user accounts for consultants and administrators
-- Includes authentication, security, and GDPR compliance fields
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role_enum NOT NULL DEFAULT 'consultant',
    status user_status_enum NOT NULL DEFAULT 'active',

    -- Security fields
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMP,
    reset_password_token VARCHAR(255),
    reset_password_expires TIMESTAMP,
    reset_password_used_at TIMESTAMP,
    refresh_token VARCHAR(255),

    -- GDPR Article 18: Right to Restriction of Processing
    processing_restricted BOOLEAN NOT NULL DEFAULT false,
    restriction_reason TEXT,

    -- Timestamps
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    last_login_at TIMESTAMP,

    CONSTRAINT UQ_users_email UNIQUE (email)
);

COMMENT ON COLUMN users.processing_restricted IS 'GDPR Article 18: Indicates if user has restricted data processing';
COMMENT ON COLUMN users.restriction_reason IS 'GDPR Article 18: Optional reason provided by user for restricting processing';

-- ----------------------------------------------------------------------------
-- TABLE: refresh_tokens
-- ----------------------------------------------------------------------------
-- Multi-device refresh token support for JWT authentication
-- Includes device tracking for security auditing
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP,
    device_info VARCHAR(50),
    ip_address VARCHAR(45), -- IPv6 support (45 chars)
    created_at TIMESTAMP NOT NULL DEFAULT now(),

    CONSTRAINT UQ_refresh_tokens_token UNIQUE (token),
    CONSTRAINT FK_refresh_tokens_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- TABLE: questions
-- ----------------------------------------------------------------------------
-- Assessment questionnaire with DISC/Phase scoring configuration
-- Contains 14 seeded questions (see SECTION 4)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS questions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    question_key VARCHAR(50) NOT NULL UNIQUE,
    question_text TEXT NOT NULL,
    question_type question_type_enum NOT NULL,
    options JSONB, -- Stores answer options, DISC scores, phase scores
    required BOOLEAN NOT NULL DEFAULT true,
    display_order INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),

    CONSTRAINT UQ_questions_key UNIQUE (question_key)
);

-- ----------------------------------------------------------------------------
-- TABLE: assessments
-- ----------------------------------------------------------------------------
-- Financial readiness assessments conducted by consultants
-- Links to client information and tracks assessment progress
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consultant_id UUID NOT NULL,
    client_name VARCHAR(100) NOT NULL,
    business_name VARCHAR(100) NOT NULL,
    client_email VARCHAR(255) NOT NULL,
    status assessment_status_enum NOT NULL DEFAULT 'draft',
    progress DECIMAL(5,2) NOT NULL DEFAULT 0,
    notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    updated_at TIMESTAMP NOT NULL DEFAULT now(),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    deleted_at TIMESTAMP, -- Soft delete support

    CONSTRAINT FK_assessments_consultant FOREIGN KEY (consultant_id)
        REFERENCES users(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- TABLE: assessment_responses
-- ----------------------------------------------------------------------------
-- Individual question responses for each assessment
-- Answer field stores ENCRYPTED JSONB data (requires DB_ENCRYPTION_KEY)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessment_responses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL,
    question_id VARCHAR(50) NOT NULL,
    answer TEXT NOT NULL, -- ENCRYPTED: Stores AES-256-GCM encrypted JSONB
    not_applicable BOOLEAN NOT NULL DEFAULT false,
    consultant_notes TEXT,
    answered_at TIMESTAMP NOT NULL DEFAULT now(),

    CONSTRAINT FK_assessment_responses_assessment FOREIGN KEY (assessment_id)
        REFERENCES assessments(id) ON DELETE CASCADE,
    CONSTRAINT FK_assessment_responses_question FOREIGN KEY (question_id)
        REFERENCES questions(question_key) ON DELETE RESTRICT
);

COMMENT ON COLUMN assessment_responses.answer IS 'ENCRYPTED: AES-256-GCM encrypted JSONB answer data (CRIT-005)';

-- ----------------------------------------------------------------------------
-- TABLE: disc_profiles
-- ----------------------------------------------------------------------------
-- DISC personality assessment results
-- All scores are ENCRYPTED at rest (requires DB_ENCRYPTION_KEY)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS disc_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL,
    d_score TEXT NOT NULL, -- ENCRYPTED: Dominance score
    i_score TEXT NOT NULL, -- ENCRYPTED: Influence score
    s_score TEXT NOT NULL, -- ENCRYPTED: Steadiness score
    c_score TEXT NOT NULL, -- ENCRYPTED: Compliance score
    primary_type VARCHAR(1) NOT NULL,
    secondary_type VARCHAR(1),
    confidence_level VARCHAR(10) NOT NULL,
    calculated_at TIMESTAMP NOT NULL DEFAULT now(),

    CONSTRAINT FK_disc_profiles_assessment FOREIGN KEY (assessment_id)
        REFERENCES assessments(id) ON DELETE CASCADE
);

COMMENT ON COLUMN disc_profiles.d_score IS 'ENCRYPTED: Dominance score - AES-256-GCM encrypted at rest (CRIT-004)';
COMMENT ON COLUMN disc_profiles.i_score IS 'ENCRYPTED: Influence score - AES-256-GCM encrypted at rest (CRIT-004)';
COMMENT ON COLUMN disc_profiles.s_score IS 'ENCRYPTED: Steadiness score - AES-256-GCM encrypted at rest (CRIT-004)';
COMMENT ON COLUMN disc_profiles.c_score IS 'ENCRYPTED: Compliance score - AES-256-GCM encrypted at rest (CRIT-004)';

-- ----------------------------------------------------------------------------
-- TABLE: phase_results
-- ----------------------------------------------------------------------------
-- Financial readiness phase determination results
-- Maps to 5 phases: Stabilize, Organize, Build, Grow, Systemic
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS phase_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL,
    stabilize_score FLOAT NOT NULL,
    organize_score FLOAT NOT NULL,
    build_score FLOAT NOT NULL,
    grow_score FLOAT NOT NULL,
    systemic_score FLOAT NOT NULL,
    primary_phase VARCHAR(10) NOT NULL,
    secondary_phases TEXT NOT NULL, -- Comma-separated list
    transition_state BOOLEAN NOT NULL DEFAULT false,
    calculated_at TIMESTAMP NOT NULL DEFAULT now(),

    CONSTRAINT FK_phase_results_assessment FOREIGN KEY (assessment_id)
        REFERENCES assessments(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- TABLE: reports
-- ----------------------------------------------------------------------------
-- Generated PDF reports (consultant and client versions)
-- Tracks report status, file location, and ownership
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID NOT NULL,
    consultant_id UUID NOT NULL, -- For IDOR protection
    report_type report_type_enum NOT NULL,
    status report_status_enum NOT NULL DEFAULT 'generating',
    file_url TEXT,
    file_size_bytes INT,
    generated_at TIMESTAMP,
    expires_at TIMESTAMP,
    error TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT now(),

    CONSTRAINT FK_reports_assessment FOREIGN KEY (assessment_id)
        REFERENCES assessments(id) ON DELETE CASCADE,
    CONSTRAINT FK_reports_consultant FOREIGN KEY (consultant_id)
        REFERENCES users(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- TABLE: user_consents
-- ----------------------------------------------------------------------------
-- GDPR consent tracking for data processing
-- Records user consent for essential, analytics, and marketing processing
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_consents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    consent_type VARCHAR(20) NOT NULL CHECK (consent_type IN ('essential', 'analytics', 'marketing')),
    granted BOOLEAN NOT NULL DEFAULT false,
    ip_address VARCHAR(45), -- IPv6 support
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT FK_user_consents_user FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

-- ----------------------------------------------------------------------------
-- TABLE: user_objections
-- ----------------------------------------------------------------------------
-- GDPR Article 21: Right to Object to Processing
-- Stores user objections to specific processing activities
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_objections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL,
    objection_type VARCHAR(20) NOT NULL CHECK (objection_type IN ('marketing', 'analytics', 'profiling')),
    reason TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT FK_USER_OBJECTIONS_USER_ID FOREIGN KEY (user_id)
        REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================================================
-- SECTION 3: INDEXES
-- ============================================================================
-- Create all indexes for query optimization
-- Organized by table for maintainability
-- ============================================================================

-- Users table indexes
CREATE INDEX IF NOT EXISTS IDX_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_processing_restricted ON users (processing_restricted) WHERE processing_restricted = true;

-- Refresh tokens table indexes
CREATE INDEX IF NOT EXISTS IDX_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX IF NOT EXISTS IDX_refresh_tokens_token ON refresh_tokens (token);

-- Questions table indexes
CREATE UNIQUE INDEX IF NOT EXISTS IDX_questions_key ON questions (question_key);
CREATE INDEX IF NOT EXISTS IDX_questions_type ON questions (question_type);
CREATE INDEX IF NOT EXISTS IDX_questions_order ON questions (display_order);

-- Assessments table indexes
CREATE INDEX IF NOT EXISTS IDX_assessments_consultant ON assessments (consultant_id);
CREATE INDEX IF NOT EXISTS IDX_assessments_status ON assessments (status);
CREATE INDEX IF NOT EXISTS IDX_assessments_updated ON assessments (updated_at);
CREATE INDEX IF NOT EXISTS IDX_assessments_email ON assessments (client_email);

-- Assessment responses table indexes
CREATE INDEX IF NOT EXISTS IDX_assessment_responses_assessment ON assessment_responses (assessment_id);
CREATE INDEX IF NOT EXISTS IDX_assessment_responses_question ON assessment_responses (question_id);

-- DISC profiles table indexes
CREATE INDEX IF NOT EXISTS IDX_disc_profiles_assessment ON disc_profiles (assessment_id);

-- Phase results table indexes
CREATE INDEX IF NOT EXISTS IDX_phase_results_assessment ON phase_results (assessment_id);

-- Reports table indexes
CREATE INDEX IF NOT EXISTS IDX_reports_assessment ON reports (assessment_id);
CREATE INDEX IF NOT EXISTS IDX_reports_type ON reports (report_type);
CREATE INDEX IF NOT EXISTS IDX_reports_status ON reports (status);
CREATE INDEX IF NOT EXISTS IDX_reports_consultant_id ON reports (consultant_id);

-- User consents table indexes
CREATE INDEX IF NOT EXISTS IDX_USER_CONSENT_TYPE ON user_consents (user_id, consent_type);
CREATE INDEX IF NOT EXISTS IDX_USER_CONSENTS_CREATED_AT ON user_consents (created_at);

-- User objections table indexes
CREATE UNIQUE INDEX IF NOT EXISTS IDX_USER_OBJECTION_TYPE ON user_objections (user_id, objection_type);
CREATE INDEX IF NOT EXISTS IDX_USER_OBJECTIONS_USER_ID ON user_objections (user_id);

-- ============================================================================
-- SECTION 4: SEED DATA - ASSESSMENT QUESTIONS
-- ============================================================================
-- Insert 14 assessment questions with DISC and Phase scoring configuration
-- Questions cover: Confidence (2), Finance (3), Organization (3),
--                  Build (2), Grow (2), Systemic/Literacy (3)
-- ============================================================================

-- Confidence Assessment (Before)
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'CONF-001',
    'How confident do you feel about your business finances right now?',
    'rating',
    '{"min": 1, "max": 10, "labels": {"1": "Not confident at all", "10": "Extremely confident"}}',
    true,
    1
)
ON CONFLICT (question_key) DO NOTHING;

-- Financial Stability Questions (Stabilize Phase)
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'FIN-001',
    'How frequently do you review your financial statements?',
    'single_choice',
    '{"options": [
        {"value": "weekly", "text": "Weekly", "discScores": {"D": 15, "I": 5, "S": 0, "C": 20}, "phaseScores": {"stabilize": 20, "organize": 15, "build": 10, "grow": 5, "systemic": 15}},
        {"value": "monthly", "text": "Monthly", "discScores": {"D": 10, "I": 10, "S": 10, "C": 15}, "phaseScores": {"stabilize": 15, "organize": 10, "build": 5, "grow": 0, "systemic": 10}},
        {"value": "quarterly", "text": "Quarterly", "discScores": {"D": 5, "I": 15, "S": 15, "C": 5}, "phaseScores": {"stabilize": 10, "organize": 5, "build": 0, "grow": 0, "systemic": 5}},
        {"value": "annually", "text": "Annually or less", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 0, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    2
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'FIN-002',
    'Do you have a current bookkeeping system in place?',
    'single_choice',
    '{"options": [
        {"value": "yes_current", "text": "Yes, and it is up to date", "discScores": {"D": 15, "I": 5, "S": 10, "C": 20}, "phaseScores": {"stabilize": 20, "organize": 15, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "yes_behind", "text": "Yes, but it is behind", "discScores": {"D": 5, "I": 15, "S": 15, "C": 10}, "phaseScores": {"stabilize": 10, "organize": 5, "build": 0, "grow": 0, "systemic": 5}},
        {"value": "no", "text": "No", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 0, "organize": 0, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    3
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'FIN-003',
    'What is your business entity type?',
    'single_choice',
    '{"options": [
        {"value": "sole_proprietor", "text": "Sole Proprietor", "discScores": {"D": 10, "I": 15, "S": 15, "C": 5}, "phaseScores": {"stabilize": 5, "organize": 5, "build": 0, "grow": 0, "systemic": 5}},
        {"value": "llc", "text": "LLC", "discScores": {"D": 15, "I": 10, "S": 10, "C": 15}, "phaseScores": {"stabilize": 15, "organize": 15, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "s_corp", "text": "S-Corp", "discScores": {"D": 20, "I": 5, "S": 5, "C": 20}, "phaseScores": {"stabilize": 20, "organize": 20, "build": 15, "grow": 10, "systemic": 15}},
        {"value": "c_corp", "text": "C-Corp", "discScores": {"D": 20, "I": 0, "S": 0, "C": 20}, "phaseScores": {"stabilize": 20, "organize": 20, "build": 20, "grow": 15, "systemic": 20}}
    ]}',
    true,
    4
)
ON CONFLICT (question_key) DO NOTHING;

-- Financial Organization Questions (Organize Phase)
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'ORG-001',
    'Do you have a documented Chart of Accounts (COA)?',
    'single_choice',
    '{"options": [
        {"value": "yes_customized", "text": "Yes, customized for my business", "discScores": {"D": 15, "I": 5, "S": 10, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 15, "grow": 10, "systemic": 15}},
        {"value": "yes_default", "text": "Yes, using default template", "discScores": {"D": 5, "I": 10, "S": 15, "C": 10}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "no", "text": "No", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 0, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    5
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'ORG-002',
    'Do you have a system for tracking accounts receivable (money owed to you)?',
    'single_choice',
    '{"options": [
        {"value": "yes_automated", "text": "Yes, automated system", "discScores": {"D": 20, "I": 5, "S": 5, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 20, "grow": 15, "systemic": 15}},
        {"value": "yes_manual", "text": "Yes, manual tracking", "discScores": {"D": 10, "I": 10, "S": 15, "C": 15}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "no", "text": "No formal system", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 0, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    6
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'ORG-003',
    'Do you have a system for tracking accounts payable (money you owe)?',
    'single_choice',
    '{"options": [
        {"value": "yes_automated", "text": "Yes, automated system", "discScores": {"D": 20, "I": 5, "S": 5, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 20, "grow": 15, "systemic": 15}},
        {"value": "yes_manual", "text": "Yes, manual tracking", "discScores": {"D": 10, "I": 10, "S": 15, "C": 15}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "no", "text": "No formal system", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 0, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    7
)
ON CONFLICT (question_key) DO NOTHING;

-- Build Phase Questions
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'BUILD-001',
    'Do you have documented Standard Operating Procedures (SOPs) for financial processes?',
    'single_choice',
    '{"options": [
        {"value": "yes_comprehensive", "text": "Yes, comprehensive and up to date", "discScores": {"D": 20, "I": 0, "S": 10, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 20, "grow": 15, "systemic": 15}},
        {"value": "yes_basic", "text": "Yes, but basic or outdated", "discScores": {"D": 10, "I": 10, "S": 15, "C": 15}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 15, "grow": 10, "systemic": 10}},
        {"value": "in_progress", "text": "In progress", "discScores": {"D": 15, "I": 15, "S": 10, "C": 10}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "no", "text": "No", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 5, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    8
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'BUILD-002',
    'Do you have a process for monthly financial close and reconciliation?',
    'single_choice',
    '{"options": [
        {"value": "yes_automated", "text": "Yes, mostly automated", "discScores": {"D": 20, "I": 5, "S": 5, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 20, "grow": 15, "systemic": 15}},
        {"value": "yes_manual", "text": "Yes, manual process", "discScores": {"D": 10, "I": 10, "S": 15, "C": 15}, "phaseScores": {"stabilize": 15, "organize": 15, "build": 15, "grow": 10, "systemic": 10}},
        {"value": "sometimes", "text": "Sometimes", "discScores": {"D": 5, "I": 15, "S": 15, "C": 10}, "phaseScores": {"stabilize": 10, "organize": 10, "build": 5, "grow": 0, "systemic": 5}},
        {"value": "no", "text": "No", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 0, "build": 0, "grow": 0, "systemic": 0}}
    ]}',
    true,
    9
)
ON CONFLICT (question_key) DO NOTHING;

-- Grow Phase Questions
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'GROW-001',
    'Do you have a formal budgeting process?',
    'single_choice',
    '{"options": [
        {"value": "yes_detailed", "text": "Yes, detailed annual budget with monthly reviews", "discScores": {"D": 20, "I": 0, "S": 5, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 20, "grow": 20, "systemic": 20}},
        {"value": "yes_basic", "text": "Yes, basic budget", "discScores": {"D": 15, "I": 10, "S": 10, "C": 15}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 15, "grow": 15, "systemic": 15}},
        {"value": "informal", "text": "Informal planning only", "discScores": {"D": 5, "I": 15, "S": 15, "C": 5}, "phaseScores": {"stabilize": 10, "organize": 10, "build": 10, "grow": 5, "systemic": 10}},
        {"value": "no", "text": "No", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 5, "build": 5, "grow": 0, "systemic": 5}}
    ]}',
    true,
    10
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'GROW-002',
    'Do you regularly create cash flow forecasts for the next 3-12 months?',
    'single_choice',
    '{"options": [
        {"value": "yes_monthly", "text": "Yes, updated monthly", "discScores": {"D": 20, "I": 0, "S": 5, "C": 20}, "phaseScores": {"stabilize": 15, "organize": 20, "build": 20, "grow": 20, "systemic": 20}},
        {"value": "yes_quarterly", "text": "Yes, updated quarterly", "discScores": {"D": 15, "I": 10, "S": 10, "C": 15}, "phaseScores": {"stabilize": 10, "organize": 15, "build": 15, "grow": 15, "systemic": 15}},
        {"value": "occasionally", "text": "Occasionally", "discScores": {"D": 5, "I": 15, "S": 15, "C": 10}, "phaseScores": {"stabilize": 10, "organize": 10, "build": 10, "grow": 10, "systemic": 10}},
        {"value": "no", "text": "No", "discScores": {"D": 0, "I": 20, "S": 20, "C": 0}, "phaseScores": {"stabilize": 5, "organize": 5, "build": 5, "grow": 0, "systemic": 5}}
    ]}',
    true,
    11
)
ON CONFLICT (question_key) DO NOTHING;

-- Systemic (Financial Literacy) Questions
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'SYS-001',
    'How well do you understand your Profit & Loss (Income) Statement?',
    'rating',
    '{"min": 1, "max": 10, "labels": {"1": "Not at all", "10": "Completely understand and use regularly"}, "discScores": {"D": 2, "I": 1, "S": 1, "C": 2}, "phaseScores": {"stabilize": 2, "organize": 2, "build": 2, "grow": 2, "systemic": 4}}',
    true,
    12
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'SYS-002',
    'How well do you understand your Balance Sheet?',
    'rating',
    '{"min": 1, "max": 10, "labels": {"1": "Not at all", "10": "Completely understand and use regularly"}, "discScores": {"D": 2, "I": 1, "S": 1, "C": 2}, "phaseScores": {"stabilize": 2, "organize": 2, "build": 2, "grow": 2, "systemic": 4}}',
    true,
    13
)
ON CONFLICT (question_key) DO NOTHING;

INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'SYS-003',
    'How well do you understand your Cash Flow Statement?',
    'rating',
    '{"min": 1, "max": 10, "labels": {"1": "Not at all", "10": "Completely understand and use regularly"}, "discScores": {"D": 2, "I": 1, "S": 1, "C": 2}, "phaseScores": {"stabilize": 2, "organize": 2, "build": 2, "grow": 2, "systemic": 4}}',
    true,
    14
)
ON CONFLICT (question_key) DO NOTHING;

-- Confidence Assessment (After)
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES (
    'CONF-002',
    'After reviewing these areas, how confident do you feel about working on your business finances?',
    'rating',
    '{"min": 1, "max": 10, "labels": {"1": "Not confident at all", "10": "Extremely confident"}}',
    true,
    42
)
ON CONFLICT (question_key) DO NOTHING;

-- ============================================================================
-- COMPLETION MESSAGE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Financial RISE Report Database Initialization Complete';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'Database Schema Version: 1.0';
    RAISE NOTICE 'Last Migration Applied: 1735500000000-AddDeviceInfoToRefreshTokens';
    RAISE NOTICE '';
    RAISE NOTICE 'Tables Created: 10';
    RAISE NOTICE '  - users, refresh_tokens, questions, assessments';
    RAISE NOTICE '  - assessment_responses, disc_profiles, phase_results, reports';
    RAISE NOTICE '  - user_consents, user_objections';
    RAISE NOTICE '';
    RAISE NOTICE 'Questions Seeded: 14';
    RAISE NOTICE '  - CONF (2), FIN (3), ORG (3), BUILD (2), GROW (2), SYS (3)';
    RAISE NOTICE '';
    RAISE NOTICE 'IMPORTANT NEXT STEPS:';
    RAISE NOTICE '  1. Set DB_ENCRYPTION_KEY environment variable (64 hex chars)';
    RAISE NOTICE '     Generate: node -e "console.log(require(''crypto'').randomBytes(32).toString(''hex''))"';
    RAISE NOTICE '  2. Store encryption key in GCP Secret Manager';
    RAISE NOTICE '  3. Create initial admin user account';
    RAISE NOTICE '  4. Configure GDPR compliance settings';
    RAISE NOTICE '  5. Test assessment flow end-to-end';
    RAISE NOTICE '';
    RAISE NOTICE 'Security Notes:';
    RAISE NOTICE '  - DISC scores encrypted at rest (requires DB_ENCRYPTION_KEY)';
    RAISE NOTICE '  - Assessment responses encrypted at rest (requires DB_ENCRYPTION_KEY)';
    RAISE NOTICE '  - GDPR Article 18 and Article 21 compliance fields included';
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE '';
END $$;
