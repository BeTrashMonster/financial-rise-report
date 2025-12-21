-- Financial RISE Report - Database Schema
-- PostgreSQL 14+
-- Version: 1.0.0
-- Date: 2025-12-19

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto for encryption functions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==============================================
-- USERS AND AUTHENTICATION
-- ==============================================

-- User roles enum
CREATE TYPE user_role AS ENUM ('consultant', 'admin');

-- User status enum
CREATE TYPE user_status AS ENUM ('active', 'inactive', 'locked');

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role user_role NOT NULL DEFAULT 'consultant',
    status user_status NOT NULL DEFAULT 'active',
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(500) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked BOOLEAN DEFAULT FALSE
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- CONSULTANT SETTINGS
-- ==============================================

-- Consultant branding settings
CREATE TABLE consultant_branding (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    company_name VARCHAR(255),
    logo_url TEXT,
    primary_color VARCHAR(7) DEFAULT '#4B006E',
    website_url TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Scheduler integration settings
CREATE TABLE consultant_scheduler_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    initial_consultation_url TEXT,
    follow_up_url TEXT,
    deep_dive_url TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- QUESTIONNAIRE CONTENT
-- ==============================================

-- Financial phases enum
CREATE TYPE financial_phase AS ENUM ('stabilize', 'organize', 'build', 'grow', 'systemic');

-- DISC personality types enum
CREATE TYPE disc_type AS ENUM ('D', 'I', 'S', 'C');

-- Question types enum
CREATE TYPE question_type AS ENUM ('multiple_choice', 'yes_no', 'scale', 'text');

-- Questions table
CREATE TABLE questions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    question_order INTEGER NOT NULL,
    question_text TEXT NOT NULL,
    question_type question_type NOT NULL DEFAULT 'multiple_choice',
    phase financial_phase,
    disc_trait disc_type,
    disc_weight INTEGER DEFAULT 0, -- Weight for DISC calculation (0 if not a DISC question)
    is_disc_hidden BOOLEAN DEFAULT FALSE, -- Hide from client if true
    is_required BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Question options (for multiple choice questions)
CREATE TABLE question_options (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    option_order INTEGER NOT NULL,
    option_text TEXT NOT NULL,
    disc_d_score INTEGER DEFAULT 0,
    disc_i_score INTEGER DEFAULT 0,
    disc_s_score INTEGER DEFAULT 0,
    disc_c_score INTEGER DEFAULT 0,
    phase_stabilize_score INTEGER DEFAULT 0,
    phase_organize_score INTEGER DEFAULT 0,
    phase_build_score INTEGER DEFAULT 0,
    phase_grow_score INTEGER DEFAULT 0,
    phase_systemic_score INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Conditional logic for questions
CREATE TABLE question_conditionals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    trigger_question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    trigger_option_id UUID REFERENCES question_options(id) ON DELETE CASCADE,
    condition_type VARCHAR(50) NOT NULL, -- 'equals', 'not_equals', 'contains', etc.
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- ASSESSMENTS
-- ==============================================

-- Assessment status enum
CREATE TYPE assessment_status AS ENUM ('draft', 'in_progress', 'completed', 'archived');

-- Assessments table
CREATE TABLE assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    consultant_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_name VARCHAR(255) NOT NULL,
    client_email VARCHAR(255),
    client_company VARCHAR(255),
    status assessment_status NOT NULL DEFAULT 'draft',
    progress_percentage INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    archived_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Assessment responses
CREATE TABLE assessment_responses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    question_id UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    selected_option_id UUID REFERENCES question_options(id) ON DELETE SET NULL,
    text_response TEXT,
    numeric_response INTEGER,
    boolean_response BOOLEAN,
    is_not_applicable BOOLEAN DEFAULT FALSE,
    consultant_notes TEXT, -- Private notes visible only to consultant
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(assessment_id, question_id)
);

-- Before/After confidence assessment
CREATE TABLE assessment_confidence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
    before_confidence INTEGER CHECK (before_confidence BETWEEN 1 AND 10),
    after_confidence INTEGER CHECK (after_confidence BETWEEN 1 AND 10),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- DISC AND PHASE RESULTS
-- ==============================================

-- DISC profile results
CREATE TABLE disc_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
    d_score INTEGER NOT NULL DEFAULT 0,
    i_score INTEGER NOT NULL DEFAULT 0,
    s_score INTEGER NOT NULL DEFAULT 0,
    c_score INTEGER NOT NULL DEFAULT 0,
    primary_type disc_type NOT NULL,
    secondary_type disc_type,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Phase determination results
CREATE TABLE phase_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
    stabilize_score INTEGER NOT NULL DEFAULT 0,
    organize_score INTEGER NOT NULL DEFAULT 0,
    build_score INTEGER NOT NULL DEFAULT 0,
    grow_score INTEGER NOT NULL DEFAULT 0,
    systemic_score INTEGER NOT NULL DEFAULT 0,
    primary_phase financial_phase NOT NULL,
    secondary_phase financial_phase,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- REPORTS
-- ==============================================

-- Report types enum
CREATE TYPE report_type AS ENUM ('consultant', 'client');

-- Generated reports
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    report_type report_type NOT NULL,
    s3_key TEXT NOT NULL,
    s3_url TEXT NOT NULL,
    file_size_bytes BIGINT,
    generation_time_ms INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Shareable report links
CREATE TABLE shareable_report_links (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    report_id UUID NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    share_token VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    expires_at TIMESTAMP,
    view_count INTEGER DEFAULT 0,
    max_views INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_accessed_at TIMESTAMP
);

-- ==============================================
-- ACTION CHECKLISTS
-- ==============================================

-- Checklist items
CREATE TABLE checklist_items (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    phase financial_phase NOT NULL,
    item_order INTEGER NOT NULL,
    item_text TEXT NOT NULL,
    is_completed BOOLEAN DEFAULT FALSE,
    completed_at TIMESTAMP,
    completed_by UUID REFERENCES users(id),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- EMAIL TEMPLATES
-- ==============================================

-- Email templates
CREATE TABLE email_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    template_name VARCHAR(255) NOT NULL,
    subject TEXT NOT NULL,
    body_html TEXT NOT NULL,
    body_text TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, template_name)
);

-- ==============================================
-- ACTIVITY LOGGING
-- ==============================================

-- Activity log types enum
CREATE TYPE activity_type AS ENUM (
    'user_login',
    'user_logout',
    'user_created',
    'user_updated',
    'user_deleted',
    'assessment_created',
    'assessment_updated',
    'assessment_completed',
    'report_generated',
    'report_shared',
    'email_sent'
);

-- Activity logs
CREATE TABLE activity_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    activity_type activity_type NOT NULL,
    entity_type VARCHAR(100),
    entity_id UUID,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- ANALYTICS
-- ==============================================

-- System metrics (for admin dashboard)
CREATE TABLE system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value NUMERIC NOT NULL,
    metric_unit VARCHAR(50),
    recorded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ==============================================
-- INDEXES FOR PERFORMANCE
-- ==============================================

-- Users indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);

-- Assessments indexes
CREATE INDEX idx_assessments_consultant_id ON assessments(consultant_id);
CREATE INDEX idx_assessments_status ON assessments(status);
CREATE INDEX idx_assessments_created_at ON assessments(created_at DESC);
CREATE INDEX idx_assessments_client_name ON assessments(client_name);

-- Responses indexes
CREATE INDEX idx_responses_assessment_id ON assessment_responses(assessment_id);
CREATE INDEX idx_responses_question_id ON assessment_responses(question_id);

-- Questions indexes
CREATE INDEX idx_questions_order ON questions(question_order);
CREATE INDEX idx_questions_phase ON questions(phase);
CREATE INDEX idx_questions_disc_trait ON questions(disc_trait);

-- Reports indexes
CREATE INDEX idx_reports_assessment_id ON reports(assessment_id);
CREATE INDEX idx_reports_type ON reports(report_type);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);

-- Activity logs indexes
CREATE INDEX idx_activity_logs_user_id ON activity_logs(user_id);
CREATE INDEX idx_activity_logs_type ON activity_logs(activity_type);
CREATE INDEX idx_activity_logs_created_at ON activity_logs(created_at DESC);
CREATE INDEX idx_activity_logs_entity ON activity_logs(entity_type, entity_id);

-- ==============================================
-- TRIGGERS FOR AUTOMATIC UPDATES
-- ==============================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at trigger to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assessments_updated_at BEFORE UPDATE ON assessments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_responses_updated_at BEFORE UPDATE ON assessment_responses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_disc_profiles_updated_at BEFORE UPDATE ON disc_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_phase_results_updated_at BEFORE UPDATE ON phase_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_branding_updated_at BEFORE UPDATE ON consultant_branding
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scheduler_updated_at BEFORE UPDATE ON consultant_scheduler_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_checklist_updated_at BEFORE UPDATE ON checklist_items
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ==============================================
-- VIEWS FOR COMMON QUERIES
-- ==============================================

-- View for assessment overview with consultant info
CREATE OR REPLACE VIEW v_assessment_overview AS
SELECT
    a.id,
    a.client_name,
    a.client_email,
    a.client_company,
    a.status,
    a.progress_percentage,
    a.created_at,
    a.completed_at,
    u.first_name || ' ' || u.last_name AS consultant_name,
    u.email AS consultant_email,
    COUNT(DISTINCT r.id) AS report_count,
    dp.primary_type AS disc_primary,
    pr.primary_phase AS phase_primary
FROM assessments a
JOIN users u ON a.consultant_id = u.id
LEFT JOIN reports r ON a.id = r.assessment_id
LEFT JOIN disc_profiles dp ON a.id = dp.assessment_id
LEFT JOIN phase_results pr ON a.id = pr.assessment_id
GROUP BY a.id, u.id, dp.primary_type, pr.primary_phase;

-- View for user activity summary
CREATE OR REPLACE VIEW v_user_activity_summary AS
SELECT
    u.id,
    u.email,
    u.first_name || ' ' || u.last_name AS full_name,
    COUNT(DISTINCT a.id) AS total_assessments,
    COUNT(DISTINCT CASE WHEN a.status = 'completed' THEN a.id END) AS completed_assessments,
    COUNT(DISTINCT r.id) AS total_reports,
    u.last_login_at,
    u.created_at AS user_since
FROM users u
LEFT JOIN assessments a ON u.id = a.consultant_id
LEFT JOIN reports r ON a.id = r.assessment_id
GROUP BY u.id;

-- ==============================================
-- COMMENTS
-- ==============================================

COMMENT ON TABLE users IS 'Consultants and administrators of the Financial RISE system';
COMMENT ON TABLE assessments IS 'Client financial readiness assessments';
COMMENT ON TABLE questions IS 'Assessment questionnaire items with DISC and phase mapping';
COMMENT ON TABLE assessment_responses IS 'Client responses to assessment questions';
COMMENT ON TABLE disc_profiles IS 'DISC personality profile results';
COMMENT ON TABLE phase_results IS 'Financial readiness phase determination results';
COMMENT ON TABLE reports IS 'Generated PDF reports (consultant and client versions)';
COMMENT ON TABLE activity_logs IS 'System activity audit trail';
