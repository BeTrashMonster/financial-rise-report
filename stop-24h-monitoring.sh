#!/bin/bash
# stop-24h-monitoring.sh - Stop the 24-hour agent monitoring

PID_FILE="monitoring-24h.pid"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     STOPPING 24-HOUR AGENT MONITORING                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if [ ! -f "$PID_FILE" ]; then
    echo "⚠️  No PID file found. Monitoring may not be running."
    echo ""
    echo "Checking for monitoring processes..."
    PROCS=$(ps aux | grep "monitor-agents-24h.sh" | grep -v grep)
    if [ -n "$PROCS" ]; then
        echo "Found running processes:"
        echo "$PROCS"
        echo ""
        echo "Kill manually with: kill <PID>"
    else
        echo "No monitoring processes found."
    fi
    exit 1
fi

PID=$(cat "$PID_FILE")

if ps -p "$PID" > /dev/null 2>&1; then
    echo "🛑 Stopping 24-hour monitoring (PID: $PID)..."
    kill "$PID"

    # Wait a moment
    sleep 2

    # Check if it stopped
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "⚠️  Process still running, force killing..."
        kill -9 "$PID"
    fi

    echo "✅ Monitoring stopped"
    rm "$PID_FILE"
else
    echo "⚠️  Process $PID not found (may have already stopped)"
    rm "$PID_FILE"
fi

echo ""
echo "📊 Hourly reports saved in: dev-logs/hourly-update-*.md"
echo "📋 Master logs saved in: dev-logs/24h-monitoring-*.log"
echo ""
