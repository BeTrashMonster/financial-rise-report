#!/bin/bash
# .autonomous-agent-env.sh - Source this file to enable autonomous agent commands
#
# Usage: source .autonomous-agent-env.sh
#        or add to your ~/.bashrc: source /c/Users/Admin/src/.autonomous-agent-env.sh

# Get the directory where this script is located
AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function: Run autonomous agent to complete next work stream
autonomous-agent() {
    echo "🤖 Starting Autonomous Agent from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./autonomous-agent.sh "$@")
}

# Function: Run demo autonomous agent
autonomous-agent-demo() {
    echo "🎯 Running Autonomous Agent Demo from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./demo-autonomous-agent.sh "$@")
}

# Function: Test autonomous agent (identify next work stream)
autonomous-agent-test() {
    echo "🔍 Testing Autonomous Agent from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./test-autonomous-agent.sh "$@")
}

# Function: Run TDD agent
tdd-agent() {
    echo "🧪 Starting TDD Agent from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./run-tdd-agent.sh "$@")
}

# Function: View latest agent log
agent-logs() {
    local LATEST_LOG=$(ls -t "$AGENT_DIR/agent-logs"/*.log 2>/dev/null | head -1)
    if [ -n "$LATEST_LOG" ]; then
        echo "📋 Latest log: $(basename "$LATEST_LOG")"
        echo ""
        cat "$LATEST_LOG"
    else
        echo "No agent logs found in $AGENT_DIR/agent-logs/"
    fi
}

# Function: List all agent logs
agent-logs-list() {
    echo "📁 Agent logs in $AGENT_DIR/agent-logs/:"
    echo ""
    ls -lht "$AGENT_DIR/agent-logs"/*.log 2>/dev/null | head -20 || echo "No logs found"
}

# Function: Start scheduled autonomous loop (every 30 min for 12 hours)
autonomous-agent-schedule-start() {
    echo "🚀 Starting scheduled autonomous agent loop from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./start-autonomous-schedule.sh "$@")
}

# Function: Stop scheduled autonomous loop
autonomous-agent-schedule-stop() {
    echo "🛑 Stopping scheduled autonomous agent loop from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./stop-autonomous-schedule.sh "$@")
}

# Function: Monitor scheduled loop progress
autonomous-agent-schedule-monitor() {
    local LOG_FILE=$(ls -t "$AGENT_DIR"/autonomous-loop-*.log 2>/dev/null | head -1)
    if [ -n "$LOG_FILE" ]; then
        echo "📊 Monitoring: $(basename "$LOG_FILE")"
        echo "   Press Ctrl+C to stop monitoring"
        echo ""
        tail -f "$LOG_FILE"
    else
        echo "⚠️  No loop log file found. Schedule may not be running."
    fi
}

# Function: Verify roadmap updates
verify-roadmap() {
    echo "📋 Verifying roadmap updates from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./verify-roadmap-updates.sh "$@")
}

# Export functions
export -f autonomous-agent
export -f autonomous-agent-demo
export -f autonomous-agent-test
export -f tdd-agent
export -f agent-logs
export -f agent-logs-list
export -f autonomous-agent-schedule-start
export -f autonomous-agent-schedule-stop
export -f autonomous-agent-schedule-monitor
export -f verify-roadmap

# Print help
echo "╔════════════════════════════════════════════════════════════╗"
echo "║        AUTONOMOUS AGENT COMMANDS LOADED ✅                  ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "🤖 Execution Commands:"
echo "  autonomous-agent               - Complete next work stream"
echo "  autonomous-agent-demo          - Quick demo (one task)"
echo "  autonomous-agent-test          - Identify next work stream"
echo "  tdd-agent                      - TDD-focused execution"
echo ""
echo "📅 Scheduling Commands:"
echo "  autonomous-agent-schedule-start   - Start 12-hour scheduled loop"
echo "  autonomous-agent-schedule-stop    - Stop scheduled loop"
echo "  autonomous-agent-schedule-monitor - Monitor loop progress"
echo ""
echo "📋 Logging & Verification:"
echo "  agent-logs                     - View latest log"
echo "  agent-logs-list                - List all logs"
echo "  verify-roadmap                 - Check roadmap updates"
echo ""
echo "Agent directory: $AGENT_DIR"
echo ""
