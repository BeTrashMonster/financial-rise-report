#!/bin/bash
# run-reviewer-loop.sh - Run autonomous reviewer every hour for 24 hours
#
# This runs the architectural reviewer on a regular schedule without requiring admin rights

INTERVAL_MINUTES=60
DURATION_HOURS=24
TOTAL_RUNS=$((DURATION_HOURS * 60 / INTERVAL_MINUTES))

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     AUTONOMOUS REVIEWER - CONTINUOUS EXECUTION LOOP        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Configuration:"
echo "  Interval: Every $INTERVAL_MINUTES minutes (1 hour)"
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
START_TIME=$(date +%s)

# Main loop
for i in $(seq 1 $TOTAL_RUNS); do
    RUN_COUNT=$i
    CURRENT_TIME=$(date +'%Y-%m-%d %H:%M:%S')

    echo ""
    echo "╭────────────────────────────────────────────────────────────╮"
    echo "│ Review Run #$i of $TOTAL_RUNS - $CURRENT_TIME"
    echo "╰────────────────────────────────────────────────────────────╯"
    echo ""

    # Run autonomous reviewer
    if ./autonomous-reviewer.sh; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo ""
        echo "✅ Review run #$i completed successfully"
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo ""
        echo "❌ Review run #$i failed (continuing...)"
    fi

    # Display stats
    echo ""
    echo "📊 Progress: $RUN_COUNT/$TOTAL_RUNS runs | ✅ $SUCCESS_COUNT success | ❌ $FAIL_COUNT failed"
    echo ""

    # Sleep until next run (unless it's the last one)
    if [ $i -lt $TOTAL_RUNS ]; then
        SLEEP_SECONDS=$((INTERVAL_MINUTES * 60))
        NEXT_RUN=$(date -d "+$INTERVAL_MINUTES minutes" +'%H:%M:%S' 2>/dev/null || date -v+${INTERVAL_MINUTES}M +'%H:%M:%S' 2>/dev/null || echo "in $INTERVAL_MINUTES minutes")

        echo "⏰ Waiting $INTERVAL_MINUTES minutes until next review at $NEXT_RUN..."
        echo "   (Press Ctrl+C to stop)"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        sleep $SLEEP_SECONDS
    fi
done

# Final summary
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
HOURS=$((ELAPSED / 3600))
MINUTES=$(((ELAPSED % 3600) / 60))

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║            AUTONOMOUS REVIEWER LOOP COMPLETE               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Final Statistics:"
echo "  Total runs: $RUN_COUNT"
echo "  Successful: $SUCCESS_COUNT"
echo "  Failed: $FAIL_COUNT"
echo "  Success rate: $(awk "BEGIN {printf \"%.1f\", ($SUCCESS_COUNT/$RUN_COUNT)*100}")%"
echo ""
echo "  Actual duration: ${HOURS}h ${MINUTES}m"
echo "  Reviews per hour: $(awk "BEGIN {printf \"%.1f\", $RUN_COUNT/$HOURS}")"
echo ""
echo "📁 All review reports saved to: reviews/"
echo "📁 All logs saved to: agent-logs/"
echo ""
