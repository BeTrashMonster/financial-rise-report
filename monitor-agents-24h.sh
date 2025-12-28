#!/bin/bash
# monitor-agents-24h.sh - Monitor autonomous agent progress for 24 hours
#
# This script runs every hour for 24 hours to:
# - Check autonomous agent activity
# - Review team structure rollout progress
# - Track roadmap updates
# - Generate hourly status reports in dev-logs/

set -e

# Configuration
DURATION_HOURS=24
INTERVAL_MINUTES=60
TOTAL_RUNS=$((DURATION_HOURS * 60 / INTERVAL_MINUTES))
DEV_LOGS_DIR="dev-logs"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
MASTER_LOG="$DEV_LOGS_DIR/24h-monitoring-$TIMESTAMP.log"

mkdir -p "$DEV_LOGS_DIR"

echo "╔════════════════════════════════════════════════════════════╗" | tee -a "$MASTER_LOG"
echo "║     24-HOUR AGENT PROGRESS MONITORING                      ║" | tee -a "$MASTER_LOG"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo "Start Time: $(date)" | tee -a "$MASTER_LOG"
echo "Duration: $DURATION_HOURS hours" | tee -a "$MASTER_LOG"
echo "Interval: Every $INTERVAL_MINUTES minutes" | tee -a "$MASTER_LOG"
echo "Total Checks: $TOTAL_RUNS" | tee -a "$MASTER_LOG"
echo "Output Directory: $DEV_LOGS_DIR" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

# Track stats
SUCCESS_COUNT=0
FAIL_COUNT=0

# Main monitoring loop
for i in $(seq 1 $TOTAL_RUNS); do
    CURRENT_TIME=$(date +'%Y-%m-%d %H:%M:%S')
    HOUR_TIMESTAMP=$(date +'%Y%m%d-%H%M')
    HOUR_LOG="$DEV_LOGS_DIR/hourly-update-$HOUR_TIMESTAMP.md"

    echo "" | tee -a "$MASTER_LOG"
    echo "╭────────────────────────────────────────────────────────────╮" | tee -a "$MASTER_LOG"
    echo "│ Hour $i of $TOTAL_RUNS - $CURRENT_TIME" | tee -a "$MASTER_LOG"
    echo "╰────────────────────────────────────────────────────────────╯" | tee -a "$MASTER_LOG"
    echo "" | tee -a "$MASTER_LOG"

    # Generate hourly status report using Claude
    echo "📊 Generating hourly status report..." | tee -a "$MASTER_LOG"

    if claude \
        --dangerously-skip-permissions \
        --print \
        "$(cat <<'EOF'
Generate an hourly status update for autonomous agent monitoring.

CRITICAL REQUIREMENTS:

1. Check Current Agent Activity:
   - Read agent-logs/ for recent autonomous agent runs
   - Check reviews/ for recent review reports
   - Look at plans/roadmap.md for progress
   - Check git log for commits in the last hour

2. Review Team Structures:
   - Check plans/ directory for any team structure documents
   - Look for agent assignments and coordination
   - Review any new work streams or phases

3. Track Progress Metrics:
   - Autonomous developer: runs in last hour, success/fail
   - Autonomous reviewer: reviews completed, issues found
   - Roadmap: work streams completed, % progress
   - Git: commits, files changed, lines added/removed

4. Identify Issues:
   - Any failed runs or errors
   - Critical issues from reviews
   - Blockers or dependencies
   - Resource concerns (disk space, etc.)

5. Create Hourly Report:
   Write to dev-logs/hourly-update-YYYYMMDD-HHMM.md in this format:

# Hourly Status Update - [Hour X/24]

**Time:** YYYY-MM-DD HH:MM:SS
**Monitoring Period:** Last 60 minutes

---

## 📊 Activity Summary

### Autonomous Developer
- **Runs This Hour:** X successful, Y failed
- **Work Completed:** [List work streams or "No activity"]
- **Files Changed:** X files, Y lines
- **Test Results:** [Pass/Fail counts if applicable]

### Autonomous Reviewer
- **Reviews This Hour:** X
- **Issues Found:** 🔴 X critical, 🟠 Y high, 🟡 Z medium
- **New Anti-Patterns:** X added to checklist
- **Trend:** [Improving/Stable/Declining]

### Roadmap Progress
- **Overall Completion:** XX%
- **Work Streams Completed This Hour:** X
- **Active Work Streams:** [List]
- **Blocked Items:** [List or "None"]

---

## 🎯 Key Accomplishments

[3-5 bullet points of what was achieved this hour]

---

## ⚠️ Issues & Concerns

[List any errors, failures, or concerns, or "None"]

---

## 📁 Recent Activity

### Git Commits (Last Hour)
```
[Git log output]
```

### Files Modified
- `path/to/file.ext` - [brief description]
- ...

---

## 🔮 Next Hour Focus

[What's expected to happen in the next hour]

---

## 🤖 Team Structure Status

[If team structures are being launched, track their status here]

---

*Generated: YYYY-MM-DD HH:MM:SS*

IMPORTANT:
- Focus on the LAST HOUR of activity only
- Be specific with file paths and metrics
- Highlight critical issues prominently
- Keep it concise but informative
EOF
)" > "$HOUR_LOG" 2>&1; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "   ✅ Hourly report generated: $HOUR_LOG" | tee -a "$MASTER_LOG"

        # Show summary from report
        if [ -f "$HOUR_LOG" ]; then
            echo "" | tee -a "$MASTER_LOG"
            echo "   Summary:" | tee -a "$MASTER_LOG"
            grep -A 5 "## 📊 Activity Summary" "$HOUR_LOG" | head -10 | sed 's/^/   /' | tee -a "$MASTER_LOG"
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo "   ❌ Failed to generate hourly report" | tee -a "$MASTER_LOG"
        echo "Check failed, continuing..." >> "$HOUR_LOG"
    fi

    echo "" | tee -a "$MASTER_LOG"
    echo "📊 Progress: $i/$TOTAL_RUNS checks | ✅ $SUCCESS_COUNT success | ❌ $FAIL_COUNT failed" | tee -a "$MASTER_LOG"
    echo "" | tee -a "$MASTER_LOG"

    # Wait until next hour (unless it's the last run)
    if [ $i -lt $TOTAL_RUNS ]; then
        SLEEP_SECONDS=$((INTERVAL_MINUTES * 60))
        NEXT_CHECK=$(date -d "+$INTERVAL_MINUTES minutes" +'%H:%M:%S' 2>/dev/null || date -v+${INTERVAL_MINUTES}M +'%H:%M:%S' 2>/dev/null || echo "in $INTERVAL_MINUTES minutes")

        echo "⏰ Next check at $NEXT_CHECK..." | tee -a "$MASTER_LOG"
        echo "   (Press Ctrl+C to stop)" | tee -a "$MASTER_LOG"
        echo "" | tee -a "$MASTER_LOG"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" | tee -a "$MASTER_LOG"

        sleep $SLEEP_SECONDS
    fi
done

# Final summary
echo "" | tee -a "$MASTER_LOG"
echo "╔════════════════════════════════════════════════════════════╗" | tee -a "$MASTER_LOG"
echo "║          24-HOUR MONITORING COMPLETE                       ║" | tee -a "$MASTER_LOG"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo "📊 Final Statistics:" | tee -a "$MASTER_LOG"
echo "  Total Checks: $TOTAL_RUNS" | tee -a "$MASTER_LOG"
echo "  Successful: $SUCCESS_COUNT" | tee -a "$MASTER_LOG"
echo "  Failed: $FAIL_COUNT" | tee -a "$MASTER_LOG"
echo "  Success Rate: $(awk "BEGIN {printf \"%.1f\", ($SUCCESS_COUNT/$TOTAL_RUNS)*100}")%" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo "  Duration: $DURATION_HOURS hours" | tee -a "$MASTER_LOG"
echo "  Start: $(date)" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo "📁 All hourly reports saved to: $DEV_LOGS_DIR/hourly-update-*.md" | tee -a "$MASTER_LOG"
echo "📋 Master log: $MASTER_LOG" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

# Generate final summary report
FINAL_REPORT="$DEV_LOGS_DIR/24h-final-summary-$(date +%Y%m%d-%H%M%S).md"
echo "📄 Generating final 24-hour summary..." | tee -a "$MASTER_LOG"

claude \
    --dangerously-skip-permissions \
    --print \
    "Analyze all hourly reports in dev-logs/hourly-update-*.md and create a comprehensive 24-hour summary.

Include:
- Overall progress and accomplishments
- Total work streams completed
- Total issues found and resolved
- Trends over the 24 hours (improving/declining)
- Team structure rollout status
- Recommendations for next steps

Write to: $FINAL_REPORT" > "$FINAL_REPORT" 2>&1 || echo "Failed to generate final summary" | tee -a "$MASTER_LOG"

echo "✅ Final summary: $FINAL_REPORT" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
