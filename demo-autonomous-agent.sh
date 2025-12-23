#!/bin/bash
# demo-autonomous-agent.sh - Demo of autonomous agent completing one task
#
# This demonstrates the autonomous agent by completing one specific task
# from the roadmap to show the system works end-to-end

set -e

# Create logs directory
LOGS_DIR="agent-logs"
mkdir -p "$LOGS_DIR"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOGS_DIR/demo-$TIMESTAMP.log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         DEMO: AUTONOMOUS AGENT - SINGLE TASK TEST          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Logging to: $LOG_FILE"
echo ""
echo "🎯 This demo will complete ONE task from Work Stream 10 to demonstrate"
echo "   the autonomous agent system works end-to-end."
echo ""

# Complete one specific task as a demo
echo "🤖 Executing demo task..."
echo ""

claude \
  --dangerously-skip-permissions \
  --print \
  --max-budget-usd 2.00 \
  "$(cat <<'EOF'
Review plans/roadmap.md and find Work Stream 10: Report Template Design.

Your task: Complete the FIRST unchecked task in Work Stream 10:
- Design consultant report template (PDF layout) with executive summary section

Create a simple HTML/CSS template file for the consultant report at:
financial-rise-backend/src/templates/consultant-report.html

The template should include:
1. Basic HTML structure
2. Executive summary section with placeholders
3. CSS styling matching brand colors (Purple #4B006E, gold accents)
4. Placeholder variables for dynamic content (e.g., {{clientName}}, {{assessmentDate}})

After creating the file:
1. Update plans/roadmap.md to check off the executive summary task: [x]
2. Report what you created

Keep it simple - this is a demo to show the system works.
EOF
)" 2>&1 | tee "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}

if [ $EXIT_CODE -eq 0 ]; then
  echo ""
  echo "════════════════════════════════════════════════════════════"
  echo "📝 Checking for changes to commit..."
  echo ""

  if [[ -n $(git status --porcelain) ]]; then
    echo "✓ Changes found. Creating commit..."
    echo ""

    claude \
      --dangerously-skip-permissions \
      --print \
      --max-budget-usd 0.50 \
      "Create a git commit for the autonomous agent demo. Check git status and git diff, then commit with an appropriate message describing what task was completed." \
      2>&1 | tee -a "$LOG_FILE"

    echo ""
    echo "✅ DEMO COMPLETE - Task completed and committed!"
  else
    echo "ℹ️  No file changes detected"
    echo "✅ DEMO COMPLETE - Task finished!"
  fi

  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║                  DEMO SUCCESSFUL!                          ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""
  echo "📋 Full log: $LOG_FILE"
  echo ""
  echo "Next steps:"
  echo "  - Run ./autonomous-agent.sh to complete full work streams"
  echo "  - Run ./run-tdd-agent.sh for TDD-driven work stream execution"
else
  echo ""
  echo "❌ Demo failed with exit code $EXIT_CODE"
  echo "📋 Check log: $LOG_FILE"
  exit 1
fi
