#!/bin/bash
# Deploy comprehensive question bank to production database
# This script seeds 66 questions across all phases + DISC profiling

echo "🚀 Deploying comprehensive question bank to production..."

# Database connection details
export PGPASSWORD='ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE='
DB_HOST='34.134.76.171'
DB_USER='financial_rise'
DB_NAME='financial_rise_production'

# Run the comprehensive seed script
echo "📝 Running seed script..."
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" -f seed-comprehensive-questions.sql

# Check the results
echo ""
echo "📊 Verifying question counts..."
psql -h "$DB_HOST" -U "$DB_USER" -d "$DB_NAME" << 'EOSQL'
SELECT
  'Total questions:' as metric,
  COUNT(*)::text as count
FROM questions
UNION ALL
SELECT 'Metadata questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'META-%'
UNION ALL
SELECT 'Stabilize questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'STAB-%'
UNION ALL
SELECT 'Organize questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'ORG-%'
UNION ALL
SELECT 'Build questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'BUILD-%'
UNION ALL
SELECT 'Grow questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'GROW-%'
UNION ALL
SELECT 'Systemic questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'SYS-%'
UNION ALL
SELECT 'DISC questions:', COUNT(*)::text FROM questions WHERE question_key LIKE 'DISC-%';
EOSQL

echo ""
echo "✅ Question deployment complete!"
echo ""
echo "Next steps:"
echo "  1. Test the assessment workflow end-to-end"
echo "  2. Verify all question types render correctly"
echo "  3. Test auto-save functionality"
echo "  4. Test submission and results calculation"
