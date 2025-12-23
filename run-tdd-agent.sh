#!/bin/bash
# run-tdd-agent.sh - Run TDD agent on next roadmap work stream
#
# This script executes a single TDD work stream with proper logging

set -e  # Exit on error

# Create logs directory
LOGS_DIR="agent-logs"
mkdir -p "$LOGS_DIR"

# Generate timestamped log file
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOGS_DIR/tdd-agent-$TIMESTAMP.log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║            TDD AGENT - WORK STREAM EXECUTOR                ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Logging to: $LOG_FILE"
echo ""

# Execute TDD work stream
echo "🤖 Launching TDD agent..."
echo ""

claude \
  --dangerously-skip-permissions \
  --print \
  "$(cat <<'EOF'
Review plans/roadmap.md to find work streams.

If Work Stream 10 is marked 'In Progress' by tdd-work-stream-executor from today:
  - Continue working on it and complete the remaining tasks
  - This is a design work stream, so create the report templates as HTML/CSS files
  - Check off tasks as you complete them
  - Update status to Complete when done

Otherwise:
  - Find the next unclaimed work stream with all dependencies satisfied
  - Mark it as In Progress
  - Execute it following TDD principles
  - Complete all tasks and deliverables
  - Update status to Complete

After completing the work stream, provide a summary of what was accomplished.
EOF
)" 2>&1 | tee "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}

echo ""
if [ $EXIT_CODE -eq 0 ]; then
  echo "════════════════════════════════════════════════════════════"
  echo "📝 Checking for uncommitted changes..."
  echo ""

  if [[ -n $(git status --porcelain) ]]; then
    echo "✓ Changes detected. Creating commit..."

    claude \
      --dangerously-skip-permissions \
      --print \
      "Create a git commit for the TDD work stream that was just completed. Review git status and git diff, then create an appropriate commit following standard git workflow." \
      2>&1 | tee -a "$LOG_FILE"

    echo ""
    echo "✅ Work complete and committed"
  else
    echo "ℹ️  No changes to commit"
  fi

  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║                    SUCCESS                                 ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""
  echo "📋 Full log: $LOG_FILE"
else
  echo ""
  echo "❌ TDD agent failed with exit code $EXIT_CODE"
  echo "📋 Check log: $LOG_FILE"
  exit 1
fi
