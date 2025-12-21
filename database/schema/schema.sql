-- Financial RISE Report - Database Schema
-- PostgreSQL 14+
-- Version: 1.0
-- Date: 2025-12-19

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TABLE: users
-- =============================================================================

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

-- =============================================================================
-- TABLE: assessments
-- =============================================================================

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

-- =============================================================================
-- TABLE: questions
-- =============================================================================

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

-- =============================================================================
-- TABLE: responses
-- =============================================================================

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

-- =============================================================================
-- TABLE: disc_profiles
-- =============================================================================

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

-- =============================================================================
-- TABLE: phase_results
-- =============================================================================

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

-- =============================================================================
-- TABLE: reports
-- =============================================================================

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

-- =============================================================================
-- TABLE: activity_logs
-- =============================================================================

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

-- =============================================================================
-- TABLE: checklist_items (Phase 2)
-- =============================================================================

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

-- =============================================================================
-- TABLE: consultant_settings (Phase 2)
-- =============================================================================

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

-- =============================================================================
-- TABLE: scheduler_links (Phase 2)
-- =============================================================================

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

-- =============================================================================
-- TRIGGERS: updated_at timestamp automation
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger to all tables with updated_at column
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_assessments_updated_at BEFORE UPDATE ON assessments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_questions_updated_at BEFORE UPDATE ON questions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_responses_updated_at BEFORE UPDATE ON responses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_disc_profiles_updated_at BEFORE UPDATE ON disc_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_phase_results_updated_at BEFORE UPDATE ON phase_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_reports_updated_at BEFORE UPDATE ON reports
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_checklist_items_updated_at BEFORE UPDATE ON checklist_items
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_consultant_settings_updated_at BEFORE UPDATE ON consultant_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scheduler_links_updated_at BEFORE UPDATE ON scheduler_links
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
