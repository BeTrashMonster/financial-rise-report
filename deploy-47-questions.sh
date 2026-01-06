#!/bin/bash
# Deploy 47-question structure from assessment-questions.json to production
# This replaces the old 66-question structure with the new unified format

echo "🚀 Deploying 47-question structure to production..."
echo ""
echo "⚠️  WARNING: This will DELETE all existing questions and responses!"
echo "   - All assessment responses will be lost"
echo "   - This is a destructive operation"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
  echo "❌ Deployment cancelled"
  exit 1
fi

# Set database environment variables for production
export DB_HOST='34.134.76.171'
export DB_PORT='5432'
export DB_USERNAME='financial_rise'
export DB_PASSWORD='ENY0j6eAnRNBUjupSduEeMTL3VGnjsvFrifnhBeXIYE='
export DB_NAME='financial_rise_production'
export DB_SSL='true'

# Navigate to backend directory
cd financial-rise-app/backend || exit 1

echo ""
echo "📝 Running seed:questions script..."
npm run seed:questions

# Check the results
echo ""
echo "📊 Verifying question counts..."
PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -U "$DB_USERNAME" -d "$DB_NAME" << 'EOSQL'
SELECT
  'Total questions:' as metric,
  COUNT(*)::text as count
FROM questions
UNION ALL
SELECT 'Phase questions:', COUNT(*)::text FROM questions WHERE question_type = 'phase'
UNION ALL
SELECT 'Phase+DISC questions:', COUNT(*)::text FROM questions WHERE question_type = 'phase_and_disc'
UNION ALL
SELECT 'Multiple choice questions:', COUNT(*)::text FROM questions WHERE question_type = 'multiple_choice'
UNION ALL
SELECT 'Rating questions:', COUNT(*)::text FROM questions WHERE question_type = 'rating'
UNION ALL
SELECT 'Metadata questions:', COUNT(*)::text FROM questions WHERE question_type = 'metadata';
EOSQL

echo ""
echo "✅ 47-question deployment complete!"
echo ""
echo "📋 Next steps:"
echo "  1. Test the assessment workflow end-to-end"
echo "  2. Verify multiple_choice question (BUILD-007) renders correctly"
echo "  3. Verify rating question (SYS-009) renders correctly"
echo "  4. Test auto-save functionality"
echo "  5. Test submission and DISC/phase calculation"
echo ""
