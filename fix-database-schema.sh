#!/bin/bash
# Fix Database Schema - Add Missing answered_at Column
# Run this on the production VM

echo "========================================="
echo "Fixing Database Schema"
echo "========================================="
echo ""

# Step 1: Find the database container
echo "1. Finding database container..."
DB_CONTAINER=$(docker ps --format "{{.Names}}" | grep -i "postgres\|database\|db")

if [ -z "$DB_CONTAINER" ]; then
    echo "❌ ERROR: Could not find database container"
    echo "Available containers:"
    docker ps --format "{{.Names}}"
    exit 1
fi

echo "✅ Found database container: $DB_CONTAINER"
echo ""

# Step 2: Check current schema
echo "2. Checking current assessment_responses schema..."
docker exec -i $DB_CONTAINER psql -U postgres -d financial_rise << 'EOF'
\d assessment_responses
EOF
echo ""

# Step 3: Check if answered_at column exists
echo "3. Checking if answered_at column exists..."
COLUMN_EXISTS=$(docker exec -i $DB_CONTAINER psql -U postgres -d financial_rise -t -c "SELECT column_name FROM information_schema.columns WHERE table_name = 'assessment_responses' AND column_name = 'answered_at';")

if [ -z "$COLUMN_EXISTS" ]; then
    echo "❌ Column 'answered_at' does NOT exist - will add it"

    echo ""
    echo "4. Adding answered_at column..."
    docker exec -i $DB_CONTAINER psql -U postgres -d financial_rise << 'EOF'
ALTER TABLE assessment_responses
ADD COLUMN answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

-- Verify the column was added
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'assessment_responses' AND column_name = 'answered_at';
EOF

    echo ""
    echo "✅ Column added successfully!"
else
    echo "✅ Column 'answered_at' already exists"
fi

echo ""

# Step 5: Check for other potentially missing columns
echo "5. Checking for other common timestamp columns..."
docker exec -i $DB_CONTAINER psql -U postgres -d financial_rise << 'EOF'
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'assessment_responses'
ORDER BY ordinal_position;
EOF
echo ""

# Step 6: Restart backend to clear any cached schema
echo "6. Restarting backend container to apply changes..."
docker restart financial-rise-backend-prod
echo "✅ Backend restarted"
echo ""

echo "========================================="
echo "Database Schema Fix Complete!"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Wait 10 seconds for backend to fully restart"
echo "2. Open browser DevTools (F12)"
echo "3. Clear console"
echo "4. Try to answer an assessment question"
echo "5. Check if auto-save works (no more 500 errors)"
echo ""
