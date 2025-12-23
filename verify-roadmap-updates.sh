#!/bin/bash
# verify-roadmap-updates.sh - Verify roadmap is being updated correctly

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          ROADMAP UPDATE VERIFICATION                       ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check recent roadmap updates
echo "📋 Recent roadmap modifications:"
echo ""
git log --oneline --all --grep="roadmap" -10 || git log --oneline plans/roadmap.md -5
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Show current work stream statuses
echo "📊 Current work stream statuses:"
echo ""
grep -E "^### [⚪🟡✅🔴]" plans/roadmap.md | head -15
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Count completed vs remaining
COMPLETED=$(grep -c "^### ✅" plans/roadmap.md 2>/dev/null || echo "0")
IN_PROGRESS=$(grep -c "^### 🟡" plans/roadmap.md 2>/dev/null || echo "0")
NOT_STARTED=$(grep -c "^### ⚪" plans/roadmap.md 2>/dev/null || echo "0")
BLOCKED=$(grep -c "^### 🔴" plans/roadmap.md 2>/dev/null || echo "0")

# Clean up counts (get first line only)
COMPLETED=$(echo "$COMPLETED" | head -1)
IN_PROGRESS=$(echo "$IN_PROGRESS" | head -1)
NOT_STARTED=$(echo "$NOT_STARTED" | head -1)
BLOCKED=$(echo "$BLOCKED" | head -1)

echo "📈 Work stream summary:"
echo "  ✅ Completed: $COMPLETED"
echo "  🟡 In Progress: $IN_PROGRESS"
echo "  ⚪ Not Started: $NOT_STARTED"
echo "  🔴 Blocked: $BLOCKED"
echo ""
TOTAL_ACTIVE=$((IN_PROGRESS + NOT_STARTED + BLOCKED))
echo "  Total active: $TOTAL_ACTIVE"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check for uncommitted roadmap changes
if git diff plans/roadmap.md | grep -q "^+"; then
    echo "⚠️  WARNING: Uncommitted roadmap changes detected!"
    echo ""
    echo "Changes:"
    git diff plans/roadmap.md | grep "^[+-]" | head -20
    echo ""
    echo "💡 Commit these changes with:"
    echo "   git add plans/roadmap.md"
    echo "   git commit -m 'Update roadmap status'"
else
    echo "✅ Roadmap is up to date with git"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check archive
if [ -f "plans/completed/roadmap-archive.md" ]; then
    ARCHIVED=$(grep -c "^### ✅" plans/completed/roadmap-archive.md 2>/dev/null || echo "0")
    ARCHIVED=$(echo "$ARCHIVED" | head -1)
    echo "📦 Archived work streams: $ARCHIVED"
    echo ""
fi
