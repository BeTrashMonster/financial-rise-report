#!/bin/bash
# stop-autonomous-schedule.sh - Stop the autonomous agent scheduled loop

PID_FILE="autonomous-loop.pid"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     STOPPING AUTONOMOUS AGENT SCHEDULED LOOP               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if [ ! -f "$PID_FILE" ]; then
    echo "⚠️  No PID file found. Loop may not be running."
    echo ""
    echo "Checking for autonomous loop processes..."
    PROCS=$(ps aux | grep "run-autonomous-loop.sh" | grep -v grep)
    if [ -n "$PROCS" ]; then
        echo "Found running processes:"
        echo "$PROCS"
        echo ""
        echo "Kill manually with: kill <PID>"
    else
        echo "No autonomous loop processes found."
    fi
    exit 1
fi

PID=$(cat "$PID_FILE")

if ps -p "$PID" > /dev/null 2>&1; then
    echo "🛑 Stopping autonomous loop (PID: $PID)..."
    kill "$PID"

    # Wait a moment
    sleep 2

    # Check if it stopped
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "⚠️  Process still running, force killing..."
        kill -9 "$PID"
    fi

    echo "✅ Autonomous loop stopped"
    rm "$PID_FILE"
else
    echo "⚠️  Process $PID not found (may have already stopped)"
    rm "$PID_FILE"
fi

echo ""
echo "📊 Final agent logs saved in: agent-logs/"
echo ""
