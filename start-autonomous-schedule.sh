#!/bin/bash
# start-autonomous-schedule.sh - Start autonomous agent loop in background
#
# Runs the autonomous agent every 30 minutes for 12 hours in the background

LOOP_SCRIPT="./run-autonomous-loop.sh"
PID_FILE="autonomous-loop.pid"
LOG_FILE="autonomous-loop-$(date +%Y%m%d-%H%M%S).log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     STARTING AUTONOMOUS AGENT SCHEDULED LOOP               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "⚠️  Autonomous loop is already running (PID: $OLD_PID)"
        echo ""
        echo "Stop it with: kill $OLD_PID"
        echo "Or use: ./stop-autonomous-schedule.sh"
        exit 1
    else
        echo "⚠️  Removing stale PID file"
        rm "$PID_FILE"
    fi
fi

# Start the loop in background
echo "🚀 Starting autonomous agent loop in background..."
echo "   Interval: Every 30 minutes"
echo "   Duration: 12 hours (24 runs)"
echo "   Log file: $LOG_FILE"
echo ""

nohup "$LOOP_SCRIPT" > "$LOG_FILE" 2>&1 &
PID=$!

# Save PID
echo "$PID" > "$PID_FILE"

echo "✅ Autonomous loop started!"
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
echo ""
echo "  Check if running:"
echo "    ps -p $PID"
echo ""
echo "  Stop the loop:"
echo "    ./stop-autonomous-schedule.sh"
echo "    or: kill $PID"
echo ""
echo "  View all agent logs:"
echo "    ls -lht agent-logs/"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
