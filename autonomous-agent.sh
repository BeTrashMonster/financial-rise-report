#!/bin/bash
# autonomous-agent.sh - Autonomous TDD work stream executor
#
# This script launches Claude Code to:
# 1. Identify the next available work stream from the roadmap
# 2. Execute it using the TDD work stream executor agent
# 3. Auto-commit any changes when complete

set -e  # Exit on error

# Create logs directory
LOGS_DIR="agent-logs"
mkdir -p "$LOGS_DIR"

# Generate timestamped log file
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOGS_DIR/autonomous-agent-$TIMESTAMP.log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        AUTONOMOUS AGENT - TDD WORK STREAM EXECUTOR         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📝 Logging to: $LOG_FILE"
echo ""

# Step 1: Launch Claude Code to execute next roadmap work stream
echo "🤖 Launching TDD agent to execute next roadmap work stream..."
echo ""

claude \
  --dangerously-skip-permissions \
  --print \
  "$(cat <<'EOF'
Review plans/roadmap.md and complete the next work stream.

CRITICAL REQUIREMENTS:

1. Find Next Work Stream:
   - Look for work streams marked 🟡 In Progress (continue those first)
   - Otherwise, find ⚪ Not Started with all dependencies satisfied
   - Identify which work stream you'll work on

2. Complete All Tasks:
   - Check off each task as [x] when completed
   - Create all deliverables listed
   - Write tests following TDD principles
   - Ensure production-ready code quality

3. UPDATE ROADMAP (MANDATORY):
   After completing work, you MUST update plans/roadmap.md:
   - Check off ALL completed tasks: [ ] → [x]
   - Update status: ⚪ → 🟡 → ✅ Complete
   - Set completion date: **Completed:** YYYY-MM-DD
   - Move to plans/completed/roadmap-archive.md if appropriate

   THIS IS CRITICAL - The roadmap must reflect current progress!

4. Provide Summary:
   - What work stream was completed
   - What files were created/modified
   - What was committed to git
   - Confirm roadmap was updated

Follow TDD: Write tests first, implement code, refactor.
Create production-ready, well-tested code.
EOF
)" \
  2>&1 | tee -a "$LOG_FILE"

CLAUDE_EXIT_CODE=${PIPESTATUS[0]}

# Check if TDD agent execution was successful
if [ $CLAUDE_EXIT_CODE -ne 0 ]; then
  echo "❌ TDD agent execution failed with exit code $CLAUDE_EXIT_CODE"
  echo "   Check logs at: $LOG_FILE"
  exit 1
fi

# Step 2: Check if working tree is dirty and commit if needed
echo ""
echo "════════════════════════════════════════════════════════════" | tee -a "$LOG_FILE"
echo "📝 Checking for uncommitted changes..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

if [[ -n $(git status --porcelain) ]]; then
  echo "✓ Working tree has changes. Spawning Claude to create commit..." | tee -a "$LOG_FILE"
  echo "" | tee -a "$LOG_FILE"

  # Spawn another Claude instance to generate a proper commit message
  claude \
    --dangerously-skip-permissions \
    --print \
    "The autonomous TDD agent has completed work on a roadmap task.

CRITICAL: Make sure to include plans/roadmap.md in your commit if it was modified!

Review all changes (git status, git diff) and create an appropriate git commit following the standard git commit workflow. The commit message should:
1. Clearly describe what work stream was completed
2. List key deliverables created
3. Mention roadmap updates if applicable
4. Follow the repository's commit message format

Use 'git add' to stage all relevant files INCLUDING plans/roadmap.md if it changed." \
    2>&1 | tee -a "$LOG_FILE"

  echo "" | tee -a "$LOG_FILE"
  echo "✓ Changes committed successfully" | tee -a "$LOG_FILE"
else
  echo "✓ Working tree is clean. No commit needed." | tee -a "$LOG_FILE"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
echo "║              AUTONOMOUS AGENT COMPLETE                     ║" | tee -a "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "📋 Full execution log saved to: $LOG_FILE"
echo ""
