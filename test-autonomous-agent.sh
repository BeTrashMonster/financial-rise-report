#!/bin/bash
# test-autonomous-agent.sh - Quick test of autonomous agent script mechanics
#
# This is a quick test that verifies the script can launch Claude and identify
# the next work stream, without actually executing it.

set -e  # Exit on error

# Create logs directory
LOGS_DIR="agent-logs"
mkdir -p "$LOGS_DIR"

# Generate timestamped log file
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOGS_DIR/test-agent-$TIMESTAMP.log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           TEST AUTONOMOUS AGENT - QUICK TEST               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Logging to: $LOG_FILE"
echo ""

# Quick test: Just identify next work stream without executing
echo "🤖 Testing: Identifying next roadmap work stream..."
echo ""

claude \
  --dangerously-skip-permissions \
  --print \
  --max-budget-usd 0.50 \
  "Review plans/roadmap.md and identify the next unclaimed work stream that has all dependencies satisfied. List the work stream number, title, and status. DO NOT execute it - just identify it and explain why it's the next one to work on." \
  2>&1 | tee -a "$LOG_FILE"

CLAUDE_EXIT_CODE=${PIPESTATUS[0]}

echo ""
if [ $CLAUDE_EXIT_CODE -eq 0 ]; then
  echo "✅ Test successful! Script mechanics work correctly." | tee -a "$LOG_FILE"
else
  echo "❌ Test failed with exit code $CLAUDE_EXIT_CODE" | tee -a "$LOG_FILE"
  exit 1
fi

echo ""
echo "📋 Full test log saved to: $LOG_FILE"
echo ""
