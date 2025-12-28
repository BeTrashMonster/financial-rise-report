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

# Function: Run autonomous reviewer
autonomous-reviewer() {
    echo "🔍 Starting Autonomous Reviewer from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./autonomous-reviewer.sh "$@")
}

# Function: Start scheduled reviewer loop (every hour)
autonomous-reviewer-schedule-start() {
    echo "🚀 Starting scheduled reviewer loop from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./start-reviewer-schedule.sh "$@")
}

# Function: Stop scheduled reviewer loop
autonomous-reviewer-schedule-stop() {
    echo "🛑 Stopping scheduled reviewer loop from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./stop-reviewer-schedule.sh "$@")
}

# Function: Monitor reviewer loop progress
autonomous-reviewer-schedule-monitor() {
    local LOG_FILE=$(ls -t "$AGENT_DIR"/reviewer-loop-*.log 2>/dev/null | head -1)
    if [ -n "$LOG_FILE" ]; then
        echo "📊 Monitoring: $(basename "$LOG_FILE")"
        echo "   Press Ctrl+C to stop monitoring"
        echo ""
        tail -f "$LOG_FILE"
    else
        echo "⚠️  No reviewer loop log file found. Schedule may not be running."
    fi
}

# Function: View latest review report
reviewer-latest() {
    local LATEST_REVIEW=$(ls -t "$AGENT_DIR/reviews"/review-*.md 2>/dev/null | head -1)
    if [ -n "$LATEST_REVIEW" ]; then
        echo "📋 Latest review: $(basename "$LATEST_REVIEW")"
        echo ""
        cat "$LATEST_REVIEW"
    else
        echo "No review reports found in $AGENT_DIR/reviews/"
    fi
}

# Function: List all review reports
reviewer-list() {
    echo "📁 Review reports in $AGENT_DIR/reviews/:"
    echo ""
    ls -lht "$AGENT_DIR/reviews"/review-*.md 2>/dev/null | head -20 || echo "No reviews found"
}

# Function: View anti-patterns checklist
reviewer-checklist() {
    if [ -f "$AGENT_DIR/reviews/anti-patterns-checklist.md" ]; then
        echo "📋 Anti-Patterns Checklist:"
        echo ""
        cat "$AGENT_DIR/reviews/anti-patterns-checklist.md"
    else
        echo "⚠️  Checklist not found at $AGENT_DIR/reviews/anti-patterns-checklist.md"
    fi
}

# Function: Start 24-hour monitoring
start-24h-monitoring() {
    echo "🚀 Starting 24-hour agent monitoring from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./start-24h-monitoring.sh "$@")
}

# Function: Stop 24-hour monitoring
stop-24h-monitoring() {
    echo "🛑 Stopping 24-hour monitoring from: $AGENT_DIR"
    (cd "$AGENT_DIR" && ./stop-24h-monitoring.sh "$@")
}

# Function: View latest hourly update
dev-logs-latest() {
    local LATEST_UPDATE=$(ls -t "$AGENT_DIR/dev-logs"/hourly-update-*.md 2>/dev/null | head -1)
    if [ -n "$LATEST_UPDATE" ]; then
        echo "📋 Latest hourly update: $(basename "$LATEST_UPDATE")"
        echo ""
        cat "$LATEST_UPDATE"
    else
        echo "No hourly updates found in $AGENT_DIR/dev-logs/"
    fi
}

# Function: List all dev logs
dev-logs-list() {
    echo "📁 Hourly updates in $AGENT_DIR/dev-logs/:"
    echo ""
    ls -lht "$AGENT_DIR/dev-logs"/hourly-update-*.md 2>/dev/null | head -20 || echo "No hourly updates found"
}

# Function: Monitor 24h progress
monitor-24h-progress() {
    local LOG_FILE=$(ls -t "$AGENT_DIR"/dev-logs/24h-monitoring-*.log 2>/dev/null | head -1)
    if [ -n "$LOG_FILE" ]; then
        echo "📊 Monitoring: $(basename "$LOG_FILE")"
        echo "   Press Ctrl+C to stop monitoring"
        echo ""
        tail -f "$LOG_FILE"
    else
        echo "⚠️  No monitoring log file found. 24h monitoring may not be running."
        echo "   Start with: start-24h-monitoring"
    fi
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
export -f autonomous-reviewer
export -f autonomous-reviewer-schedule-start
export -f autonomous-reviewer-schedule-stop
export -f autonomous-reviewer-schedule-monitor
export -f reviewer-latest
export -f reviewer-list
export -f reviewer-checklist
export -f start-24h-monitoring
export -f stop-24h-monitoring
export -f dev-logs-latest
export -f dev-logs-list
export -f monitor-24h-progress
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
echo "🔍 Reviewer Commands:"
echo "  autonomous-reviewer            - Run architectural review"
echo "  reviewer-latest                - View latest review report"
echo "  reviewer-list                  - List all reviews"
echo "  reviewer-checklist             - View anti-patterns checklist"
echo ""
echo "📊 24-Hour Monitoring Commands:"
echo "  start-24h-monitoring           - Start hourly tracking (24h)"
echo "  stop-24h-monitoring            - Stop monitoring"
echo "  monitor-24h-progress           - Watch monitoring in real-time"
echo "  dev-logs-latest                - View latest hourly update"
echo "  dev-logs-list                  - List all hourly updates"
echo ""
echo "📅 Scheduling Commands:"
echo "  autonomous-agent-schedule-start      - Start 12-hour work loop"
echo "  autonomous-agent-schedule-stop       - Stop work loop"
echo "  autonomous-agent-schedule-monitor    - Monitor work loop"
echo "  autonomous-reviewer-schedule-start   - Start hourly review loop"
echo "  autonomous-reviewer-schedule-stop    - Stop review loop"
echo "  autonomous-reviewer-schedule-monitor - Monitor review loop"
echo ""
echo "📋 Logging & Verification:"
echo "  agent-logs                     - View latest log"
echo "  agent-logs-list                - List all logs"
echo "  verify-roadmap                 - Check roadmap updates"
echo ""
echo "Agent directory: $AGENT_DIR"
echo ""
