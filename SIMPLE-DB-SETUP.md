# Simplest Database Setup Method

## Run This Single Command in Your GCP Console SSH Terminal:

```bash
docker exec -i financial-rise-backend-prod psql -U financial_rise -d financial_rise_production << 'EOFDB'
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create ENUM types
DO \$\$ BEGIN CREATE TYPE user_role_enum AS ENUM ('consultant', 'admin'); EXCEPTION WHEN duplicate_object THEN null; END \$\$;
DO \$\$ BEGIN CREATE TYPE user_status_enum AS ENUM ('active', 'inactive', 'locked'); EXCEPTION WHEN duplicate_object THEN null; END \$\$;
DO \$\$ BEGIN CREATE TYPE assessment_status_enum AS ENUM ('draft', 'in_progress', 'completed'); EXCEPTION WHEN duplicate_object THEN null; END \$\$;
DO \$\$ BEGIN CREATE TYPE question_type_enum AS ENUM ('single_choice', 'multiple_choice', 'rating', 'text'); EXCEPTION WHEN duplicate_object THEN null; END \$\$;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100) NOT NULL,
  last_name VARCHAR(100) NOT NULL,
  role user_role_enum NOT NULL DEFAULT 'consultant',
  status user_status_enum NOT NULL DEFAULT 'active',
  failed_login_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMP,
  reset_password_token VARCHAR(255),
  reset_password_expires TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now(),
  last_login_at TIMESTAMP,
  gdpr_data_processing_restricted BOOLEAN DEFAULT false,
  gdpr_restriction_requested_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Create refresh_tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token VARCHAR(500) UNIQUE NOT NULL,
  device_name VARCHAR(100),
  device_type VARCHAR(50),
  ip_address VARCHAR(45),
  user_agent TEXT,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  revoked_at TIMESTAMP,
  is_revoked BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);

-- Create questions table
CREATE TABLE IF NOT EXISTS questions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  question_key VARCHAR(50) UNIQUE NOT NULL,
  question_text TEXT NOT NULL,
  question_type question_type_enum NOT NULL,
  options JSONB,
  required BOOLEAN NOT NULL DEFAULT true,
  display_order INT NOT NULL,
  disc_scoring JSONB,
  phase_scoring JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_questions_key ON questions(question_key);
CREATE INDEX IF NOT EXISTS idx_questions_type ON questions(question_type);
CREATE INDEX IF NOT EXISTS idx_questions_order ON questions(display_order);

-- Create assessments table
CREATE TABLE IF NOT EXISTS assessments (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  consultant_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
  deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_assessments_consultant_id ON assessments(consultant_id);
CREATE INDEX IF NOT EXISTS idx_assessments_status ON assessments(status);
CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON assessments(created_at);

-- Create assessment_responses table
CREATE TABLE IF NOT EXISTS assessment_responses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  question_id uuid NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
  answer TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now(),
  UNIQUE(assessment_id, question_id)
);

CREATE INDEX IF NOT EXISTS idx_assessment_responses_assessment_id ON assessment_responses(assessment_id);
CREATE INDEX IF NOT EXISTS idx_assessment_responses_question_id ON assessment_responses(question_id);

-- Create disc_profiles table
CREATE TABLE IF NOT EXISTS disc_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid UNIQUE NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  d_score TEXT NOT NULL,
  i_score TEXT NOT NULL,
  s_score TEXT NOT NULL,
  c_score TEXT NOT NULL,
  primary_style VARCHAR(1) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_disc_profiles_assessment_id ON disc_profiles(assessment_id);
CREATE INDEX IF NOT EXISTS idx_disc_profiles_primary_style ON disc_profiles(primary_style);

-- Create phase_results table
CREATE TABLE IF NOT EXISTS phase_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid UNIQUE NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  stabilize_score DECIMAL(5,2) NOT NULL,
  organize_score DECIMAL(5,2) NOT NULL,
  build_score DECIMAL(5,2) NOT NULL,
  grow_score DECIMAL(5,2) NOT NULL,
  systemic_score DECIMAL(5,2) NOT NULL,
  recommended_phase VARCHAR(50) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_phase_results_assessment_id ON phase_results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_phase_results_recommended_phase ON phase_results(recommended_phase);

-- Create reports table
CREATE TABLE IF NOT EXISTS reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  assessment_id uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  consultant_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  report_type VARCHAR(50) NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  file_size INT,
  generated_at TIMESTAMP NOT NULL DEFAULT now(),
  expires_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reports_assessment_id ON reports(assessment_id);
CREATE INDEX IF NOT EXISTS idx_reports_consultant_id ON reports(consultant_id);
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at);

-- Create user_consents table
CREATE TABLE IF NOT EXISTS user_consents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  consent_type VARCHAR(100) NOT NULL,
  granted BOOLEAN NOT NULL DEFAULT false,
  granted_at TIMESTAMP,
  withdrawn_at TIMESTAMP,
  ip_address VARCHAR(45),
  user_agent TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_consents_user_id ON user_consents(user_id);
CREATE INDEX IF NOT EXISTS idx_user_consents_type ON user_consents(consent_type);

-- Create user_objections table
CREATE TABLE IF NOT EXISTS user_objections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  objection_type VARCHAR(100) NOT NULL,
  reason TEXT,
  status VARCHAR(50) NOT NULL DEFAULT 'pending',
  submitted_at TIMESTAMP NOT NULL DEFAULT now(),
  resolved_at TIMESTAMP,
  resolution_notes TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_objections_user_id ON user_objections(user_id);
CREATE INDEX IF NOT EXISTS idx_user_objections_status ON user_objections(status);

-- Seed questions (basic set - full set in init-production-database.sql)
INSERT INTO questions (question_key, question_text, question_type, options, display_order, disc_scoring, phase_scoring)
VALUES
  ('CONF-001', 'On a scale of 1-10, how confident do you currently feel about your business''s financial health?', 'rating', '{"min": 1, "max": 10}', 1, '{}', '{"stabilize": 2}'),
  ('FIN-001', 'Are you current on all tax filings?', 'single_choice', '{"choices": ["yes", "no", "unsure"]}', 3, '{"yes": {"c": 2}}', '{"yes": {"stabilize": 3}}')
ON CONFLICT (question_key) DO NOTHING;

SELECT 'Database initialized successfully! ✅' as status;
EOFDB
```

This creates all the core tables in one command!

## Then Create Your Account:

After the above command completes, run:

```bash
curl -X POST "http://localhost:4000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "info@thegracefulpenny.com",
    "password": "DemoPass123!",
    "first_name": "Audrey",
    "last_name": "Heesch",
    "role": "consultant"
  }'
```

## Then Log In:

Open your browser: **http://34.72.61.170/login**

Enter:
- **Email:** info@thegracefulpenny.com
- **Password:** DemoPass123!

---

**NOTE:** The command above creates the minimum tables needed. For the full schema with all 14 questions, see `financial-rise-app/backend/init-production-database.sql`
