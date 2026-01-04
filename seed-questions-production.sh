#!/bin/bash
# Seed questions into production database
# This script creates sample questions for the Financial RISE questionnaire

echo "🌱 Seeding questions into production database..."

# Database connection details
export PGPASSWORD='ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE='
DB_HOST='34.134.76.171'
DB_USER='financial_rise'
DB_NAME='financial_rise_production'

# Insert a simple test question to verify the questionnaire works
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" << 'EOSQL'
-- Insert sample questions for testing
INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, section, created_at, updated_at)
VALUES
  -- Getting Started section
  ('START-001', 'What is your business name?', 'text', '{}', true, 1, 'metadata', NOW(), NOW()),
  ('START-002', 'What industry are you in?', 'single_choice', '{"options": [{"value": "retail", "label": "Retail"}, {"value": "services", "label": "Services"}, {"value": "manufacturing", "label": "Manufacturing"}, {"value": "technology", "label": "Technology"}, {"value": "other", "label": "Other"}]}', true, 2, 'metadata', NOW(), NOW()),

  -- Financial Readiness Questions
  ('FIN-001', 'How frequently do you review your financial statements?', 'single_choice', '{"options": [{"value": "weekly", "label": "Weekly"}, {"value": "monthly", "label": "Monthly"}, {"value": "quarterly", "label": "Quarterly"}, {"value": "annually", "label": "Annually or less"}]}', true, 3, 'stabilize', NOW(), NOW()),
  ('FIN-002', 'Do you have a current bookkeeping system in place?', 'single_choice', '{"options": [{"value": "yes_current", "label": "Yes, and it is up to date"}, {"value": "yes_behind", "label": "Yes, but it is behind"}, {"value": "no", "label": "No"}]}', true, 4, 'stabilize', NOW(), NOW()),
  ('FIN-003', 'What is your business entity type?', 'single_choice', '{"options": [{"value": "sole_proprietor", "label": "Sole Proprietor"}, {"value": "llc", "label": "LLC"}, {"value": "s_corp", "label": "S-Corp"}, {"value": "c_corp", "label": "C-Corp"}]}', true, 5, 'stabilize', NOW(), NOW())
ON CONFLICT (question_key) DO NOTHING;

EOSQL

# Check count
COUNT=$(psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -t -c "SELECT COUNT(*) FROM questions;")

echo "✅ Questions seeded successfully!"
echo "📊 Total questions in database: $COUNT"
