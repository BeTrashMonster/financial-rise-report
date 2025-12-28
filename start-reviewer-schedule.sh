#!/bin/bash
# start-reviewer-schedule.sh - Start autonomous reviewer loop in background
#
# Runs the autonomous reviewer every hour for 24 hours in the background

LOOP_SCRIPT="./run-reviewer-loop.sh"
PID_FILE="reviewer-loop.pid"
LOG_FILE="reviewer-loop-$(date +%Y%m%d-%H%M%S).log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     STARTING AUTONOMOUS REVIEWER SCHEDULED LOOP            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "⚠️  Reviewer loop is already running (PID: $OLD_PID)"
        echo ""
        echo "Stop it with: kill $OLD_PID"
        echo "Or use: ./stop-reviewer-schedule.sh"
        exit 1
    else
        echo "⚠️  Removing stale PID file"
        rm "$PID_FILE"
    fi
fi

# Start the loop in background
echo "🚀 Starting autonomous reviewer loop in background..."
echo "   Interval: Every 60 minutes (1 hour)"
echo "   Duration: 24 hours (24 runs)"
echo "   Log file: $LOG_FILE"
echo ""

nohup "$LOOP_SCRIPT" > "$LOG_FILE" 2>&1 &
PID=$!

# Save PID
echo "$PID" > "$PID_FILE"

echo "✅ Reviewer loop started!"
echo ""
echo "  PID: $PID"
echo "  PID file: $PID_FILE"
echo "  Log file: $LOG_FILE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Management commands:"
echo ""
echo "  Monitor progress:"
echo "    tail -f $LOG_FILE"
echo "    or: autonomous-reviewer-schedule-monitor"
echo ""
echo "  Check if running:"
echo "    ps -p $PID"
echo ""
echo "  Stop the loop:"
echo "    ./stop-reviewer-schedule.sh"
echo "    or: autonomous-reviewer-schedule-stop"
echo "    or: kill $PID"
echo ""
echo "  View all review reports:"
echo "    ls -lht reviews/review-*.md"
echo "    or: reviewer-list"
echo ""
echo "  View latest review:"
echo "    reviewer-latest"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
