#!/bin/bash
# run-autonomous-loop.sh - Run autonomous agent every 30 minutes for 12 hours
#
# This is an alternative to Windows Task Scheduler that doesn't require admin rights

INTERVAL_MINUTES=30
DURATION_HOURS=12
TOTAL_RUNS=$((DURATION_HOURS * 60 / INTERVAL_MINUTES))

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AUTONOMOUS AGENT - CONTINUOUS EXECUTION LOOP           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Configuration:"
echo "  Interval: Every $INTERVAL_MINUTES minutes"
echo "  Duration: $DURATION_HOURS hours"
echo "  Total runs: $TOTAL_RUNS"
echo "  Start time: $(date +'%Y-%m-%d %H:%M:%S')"
echo "  End time: ~$(date -d "+$DURATION_HOURS hours" +'%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v+${DURATION_HOURS}H +'%Y-%m-%d %H:%M:%S' 2>/dev/null || echo 'calculated dynamically')"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Track execution
RUN_COUNT=0
SUCCESS_COUNT=0
FAIL_COUNT=0

# Main loop
for i in $(seq 1 $TOTAL_RUNS); do
    RUN_COUNT=$i
    CURRENT_TIME=$(date +'%Y-%m-%d %H:%M:%S')

    echo ""
    echo "╭────────────────────────────────────────────────────────────╮"
    echo "│ Run #$i of $TOTAL_RUNS - $CURRENT_TIME"
    echo "╰────────────────────────────────────────────────────────────╯"
    echo ""

    # Run autonomous agent
    if ./autonomous-agent.sh; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo ""
        echo "✅ Run #$i completed successfully"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo ""
        echo "❌ Run #$i failed (continuing...)"
    fi

    # Display stats
    echo ""
    echo "📊 Progress: $RUN_COUNT/$TOTAL_RUNS runs | ✅ $SUCCESS_COUNT success | ❌ $FAIL_COUNT failed"
    echo ""

    # Sleep until next run (unless it's the last one)
    if [ $i -lt $TOTAL_RUNS ]; then
        SLEEP_SECONDS=$((INTERVAL_MINUTES * 60))
        NEXT_RUN=$(date -d "+$INTERVAL_MINUTES minutes" +'%H:%M:%S' 2>/dev/null || date -v+${INTERVAL_MINUTES}M +'%H:%M:%S' 2>/dev/null || echo "in $INTERVAL_MINUTES minutes")

        echo "⏰ Waiting $INTERVAL_MINUTES minutes until next run at $NEXT_RUN..."
        echo "   (Press Ctrl+C to stop)"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        sleep $SLEEP_SECONDS
    fi
done

# Final summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              AUTONOMOUS LOOP COMPLETE                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Final Statistics:"
echo "  Total runs: $RUN_COUNT"
echo "  Successful: $SUCCESS_COUNT"
echo "  Failed: $FAIL_COUNT"
echo "  Success rate: $(awk "BEGIN {printf \"%.1f\", ($SUCCESS_COUNT/$RUN_COUNT)*100}")%"
echo ""
echo "  Duration: $DURATION_HOURS hours"
echo "  Start: $(date +'%Y-%m-%d %H:%M:%S')"
echo "  End: $(date +'%Y-%m-%d %H:%M:%S')"
echo ""
echo "📁 All logs saved to: agent-logs/"
echo ""
