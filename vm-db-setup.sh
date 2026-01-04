#!/bin/bash
# Run this script in the GCP Console SSH terminal
# It will create the database tables and your account

set -e

echo "========================================="
echo "INSTALLING POSTGRESQL CLIENT"
echo "========================================="

# Install psql on the VM
sudo apt-get update -qq
sudo apt-get install -y postgresql-client

echo ""
echo "========================================="
echo "CREATING DATABASE TABLES"
echo "========================================="

# Database connection details
export PGPASSWORD="ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE="

psql -h 34.134.76.171 -U financial_rise -d financial_rise_production << 'EOFDB'
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create ENUM types
DO $$ BEGIN CREATE TYPE user_role_enum AS ENUM ('consultant', 'admin'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE user_status_enum AS ENUM ('active', 'inactive', 'locked'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE assessment_status_enum AS ENUM ('draft', 'in_progress', 'completed'); EXCEPTION WHEN duplicate_object THEN null; END $$;
DO $$ BEGIN CREATE TYPE question_type_enum AS ENUM ('single_choice', 'multiple_choice', 'rating', 'text'); EXCEPTION WHEN duplicate_object THEN null; END $$;

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

SELECT 'Database initialized ✅' as status;
EOFDB

unset PGPASSWORD

echo ""
echo "✅ Database tables created!"
echo ""
echo "========================================="
echo "CREATING YOUR ACCOUNT"
echo "========================================="

curl -X POST "http://localhost:4000/api/v1/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "info@thegracefulpenny.com",
    "password": "DemoPass123!",
    "first_name": "Audrey",
    "last_name": "Heesch",
    "role": "consultant"
  }'

echo ""
echo ""
echo "========================================="
echo "ALL DONE! 🎉"
echo "========================================="
echo ""
echo "Go to: http://34.72.61.170/login"
echo ""
echo "Sign in with:"
echo "  Email: info@thegracefulpenny.com"
echo "  Password: DemoPass123!"
echo ""
