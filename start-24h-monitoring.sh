#!/bin/bash
# start-24h-monitoring.sh - Start 24-hour agent monitoring in background

MONITOR_SCRIPT="./monitor-agents-24h.sh"
PID_FILE="monitoring-24h.pid"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
LOG_FILE="dev-logs/24h-monitoring-$TIMESTAMP.log"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     STARTING 24-HOUR AGENT MONITORING                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "⚠️  24-hour monitoring is already running (PID: $OLD_PID)"
        echo ""
        echo "Stop it with: kill $OLD_PID"
        echo "Or use: ./stop-24h-monitoring.sh"
        exit 1
    else
        echo "⚠️  Removing stale PID file"
        rm "$PID_FILE"
    fi
fi

# Create dev-logs directory if needed
mkdir -p dev-logs

# Start monitoring in background
echo "🚀 Starting 24-hour monitoring in background..."
echo "   Interval: Every 60 minutes (hourly)"
echo "   Duration: 24 hours"
echo "   Log file: $LOG_FILE"
echo "   Output: dev-logs/hourly-update-*.md"
echo ""

nohup "$MONITOR_SCRIPT" > "$LOG_FILE" 2>&1 &
PID=$!

# Save PID
echo "$PID" > "$PID_FILE"

echo "✅ 24-hour monitoring started!"
echo ""
echo "  PID: $PID"
echo "  PID file: $PID_FILE"
echo "  Master log: $LOG_FILE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Management commands:"
echo ""
echo "  Monitor progress:"
echo "    tail -f $LOG_FILE"
echo ""
echo "  View latest hourly update:"
echo "    cat \$(ls -t dev-logs/hourly-update-*.md | head -1)"
echo ""
echo "  List all hourly updates:"
echo "    ls -lht dev-logs/hourly-update-*.md"
echo ""
echo "  Check if running:"
echo "    ps -p $PID"
echo ""
echo "  Stop monitoring:"
echo "    ./stop-24h-monitoring.sh"
echo "    or: kill $PID"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 First hourly update will be generated immediately"
echo "⏰ Subsequent updates every hour for the next 24 hours"
echo ""
