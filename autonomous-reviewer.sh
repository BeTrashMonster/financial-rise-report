#!/bin/bash
# autonomous-reviewer.sh - Autonomous architectural and code quality reviewer
#
# This script launches Claude Code to:
# 1. Scan the codebase for anti-patterns using the checklist
# 2. Document findings in a detailed review report
# 3. Update the anti-patterns checklist with new discoveries
# 4. Escalate critical/high issues to project manager for roadmap
# 5. Track review history and trends

set -e  # Exit on error

# Create reviews directory if it doesn't exist
REVIEWS_DIR="reviews"
mkdir -p "$REVIEWS_DIR"

# Create logs directory
LOGS_DIR="agent-logs"
mkdir -p "$LOGS_DIR"

# Generate timestamped files
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOGS_DIR/reviewer-$TIMESTAMP.log"
REVIEW_FILE="$REVIEWS_DIR/review-$TIMESTAMP.md"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║          AUTONOMOUS REVIEWER - ARCHITECTURE SCAN           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Logging to: $LOG_FILE"
echo "📋 Review report will be: $REVIEW_FILE"
echo ""

# Step 1: Launch Claude Code to perform architectural review
echo "🔍 Launching reviewer agent to scan codebase for anti-patterns..."
echo ""

claude \
  --dangerously-skip-permissions \
  --print \
  "$(cat <<'EOF'
Perform an autonomous architectural and code quality review of the codebase.

CRITICAL REQUIREMENTS:

1. Read the Anti-Patterns Checklist:
   - Read reviews/anti-patterns-checklist.md completely
   - Understand all current anti-patterns being tracked
   - Note priority levels and search criteria

2. Scan the Codebase Systematically:
   - Focus on financial-rise-app/backend and financial-rise-app/frontend
   - Check each anti-pattern category in order of priority:
     a) Security (HIGHEST PRIORITY)
     b) Architecture
     c) Testing gaps
     d) Performance
     e) Error handling
     f) Code quality
     g) API design
     h) Dependencies

   - Use Grep, Glob, and Read tools efficiently
   - Document specific file:line references for all findings

3. Create Review Report (MANDATORY):
   - Create reviews/review-YYYYMMDD-HHMMSS.md (use current timestamp)
   - Follow the exact format from the agent prompt
   - Include:
     * Executive summary with counts by severity
     * All findings with file:line references
     * Code snippets showing the issue
     * Recommended fixes
     * New anti-patterns discovered
     * Positive observations
     * Roadmap escalations

4. Update Anti-Patterns Checklist:
   - If you discover new anti-patterns, add them to reviews/anti-patterns-checklist.md
   - Follow the established format (ID, description, impact, check-for, correct approach, priority, discovered date)
   - Increment version number (e.g., 1.0 → 1.1)
   - Update "Last Updated" date
   - Add entry to "Review History" section

5. Escalate Critical/High Issues:
   - Compile summary of all 🔴 CRITICAL and 🟠 HIGH issues
   - Include in review report with roadmap item recommendations
   - Note: Project manager will be notified to add to roadmap

6. Provide Summary:
   - How many issues found (by severity)
   - New anti-patterns added to checklist
   - Critical/high issues requiring escalation
   - Trends vs previous reviews (if applicable)
   - Confirm review report created

SCOPE:
- Primary: financial-rise-app/backend/** (Node.js/Express backend)
- Primary: financial-rise-app/frontend/** (React frontend)
- Secondary: plans/**, scripts/**, config files
- Exclude: node_modules/**, *.log, agent-logs/**, .git/**

EFFICIENCY:
- Use targeted Grep searches based on checklist patterns
- Don't read every file - use search tools to identify issues first
- Focus on high-impact areas: auth, database, API endpoints, user input
- Batch similar searches together
- Complete review in < 30 minutes

Be thorough but efficient. Focus on objective, verifiable issues with significant impact.
EOF
)" \
  2>&1 | tee -a "$LOG_FILE"

CLAUDE_EXIT_CODE=${PIPESTATUS[0]}

# Check if reviewer execution was successful
if [ $CLAUDE_EXIT_CODE -ne 0 ]; then
  echo "❌ Reviewer execution failed with exit code $CLAUDE_EXIT_CODE"
  echo "   Check logs at: $LOG_FILE"
  exit 1
fi

echo ""
echo "════════════════════════════════════════════════════════════" | tee -a "$LOG_FILE"
echo "📊 Review Summary" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Show summary from review report if it exists
LATEST_REVIEW=$(ls -t "$REVIEWS_DIR"/review-*.md 2>/dev/null | head -1)
if [ -n "$LATEST_REVIEW" ]; then
  echo "✓ Review report created: $(basename "$LATEST_REVIEW")" | tee -a "$LOG_FILE"

  # Extract executive summary if present
  if grep -q "## Executive Summary" "$LATEST_REVIEW"; then
    echo "" | tee -a "$LOG_FILE"
    echo "Executive Summary:" | tee -a "$LOG_FILE"
    sed -n '/## Executive Summary/,/## /p' "$LATEST_REVIEW" | head -n -1 | tail -n +2 | tee -a "$LOG_FILE"
  fi
else
  echo "⚠️  No review report found. Check logs for errors." | tee -a "$LOG_FILE"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
echo "║           AUTONOMOUS REVIEWER COMPLETE                     ║" | tee -a "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "📋 Full execution log: $LOG_FILE"
echo "📄 Review report: $LATEST_REVIEW"
echo ""
echo "Next steps:"
echo "  1. Review the report: cat $LATEST_REVIEW"
echo "  2. Check for critical issues that need immediate attention"
echo "  3. Project manager will add high-priority items to roadmap"
echo ""
