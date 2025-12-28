#!/bin/bash
# stop-reviewer-schedule.sh - Stop the autonomous reviewer scheduled loop

PID_FILE="reviewer-loop.pid"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     STOPPING AUTONOMOUS REVIEWER SCHEDULED LOOP            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if [ ! -f "$PID_FILE" ]; then
    echo "⚠️  No PID file found. Reviewer loop may not be running."
    echo ""
    echo "Checking for reviewer loop processes..."
    PROCS=$(ps aux | grep "run-reviewer-loop.sh" | grep -v grep)
    if [ -n "$PROCS" ]; then
        echo "Found running processes:"
        echo "$PROCS"
        echo ""
        echo "Kill manually with: kill <PID>"
    else
        echo "No reviewer loop processes found."
    fi
    exit 1
fi

PID=$(cat "$PID_FILE")

if ps -p "$PID" > /dev/null 2>&1; then
    echo "🛑 Stopping reviewer loop (PID: $PID)..."
    kill "$PID"

    # Wait a moment
    sleep 2

    # Check if it stopped
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "⚠️  Process still running, force killing..."
        kill -9 "$PID"
    fi

    echo "✅ Reviewer loop stopped"
    rm "$PID_FILE"
else
    echo "⚠️  Process $PID not found (may have already stopped)"
    rm "$PID_FILE"
fi

echo ""
echo "📊 Review reports saved in: reviews/"
echo "📁 Logs saved in: agent-logs/"
echo ""
