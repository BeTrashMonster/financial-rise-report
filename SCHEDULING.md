# Autonomous Agent Scheduling Guide

## Overview

The autonomous agent can run on a schedule to continuously complete work streams from your roadmap over an extended period.

## Quick Start

```bash
# Start 12-hour scheduled execution (every 30 minutes)
autonomous-agent-schedule-start

# Monitor progress
autonomous-agent-schedule-monitor

# Stop the schedule
autonomous-agent-schedule-stop
```

---

## Scheduling Options

### Option 1: Bash Loop (No Admin Required) ✅ ACTIVE

**Current Setup:** Running in background with PID 1287

- **Interval:** Every 30 minutes
- **Duration:** 12 hours (24 total runs)
- **Start:** 2025-12-22 17:04:24
- **End:** ~2025-12-23 05:04:24

**Advantages:**
- No administrator privileges needed
- Works immediately
- Full control over execution
- Easy to monitor and stop

**Commands:**
```bash
autonomous-agent-schedule-start   # Start
autonomous-agent-schedule-stop    # Stop
autonomous-agent-schedule-monitor # Watch progress
```

### Option 2: Windows Task Scheduler (Requires Admin)

For production environments where you want the task to survive reboots.

**Setup:**
1. Open PowerShell as Administrator
2. Run: `powershell -ExecutionPolicy Bypass -File setup-schedule.ps1`

**Advantages:**
- Survives system reboots
- Integrated with Windows
- Can run when not logged in

**Disadvantages:**
- Requires administrator privileges
- More complex to debug

---

## Files and Scripts

### Main Scripts

| Script | Purpose |
|--------|---------|
| `run-autonomous-loop.sh` | Core loop - runs agent every 30 min |
| `start-autonomous-schedule.sh` | Start loop in background |
| `stop-autonomous-schedule.sh` | Stop running loop |
| `setup-schedule.ps1` | Windows Task Scheduler setup (admin) |
| `manage-autonomous-schedule.ps1` | Manage Windows tasks |

### Generated Files

| File | Purpose |
|------|---------|
| `autonomous-loop.pid` | Process ID of running loop |
| `autonomous-loop-{timestamp}.log` | Main schedule log |
| `agent-logs/autonomous-agent-{timestamp}.log` | Individual run logs |

---

## Monitoring

### Real-time Monitoring

```bash
# Watch the main schedule log
tail -f autonomous-loop-20251222-170423.log

# Or use the helper command
autonomous-agent-schedule-monitor
```

### Check Status

```bash
# Check if loop is running
cat autonomous-loop.pid
ps -p $(cat autonomous-loop.pid)

# View recent work
agent-logs-list

# Check git commits
git log --oneline -10
```

### View Progress

The schedule log shows:
- Current run number (e.g., "Run #3 of 24")
- Timestamp of each execution
- Success/failure status
- Overall statistics

---

## Customization

### Change Interval or Duration

Edit `run-autonomous-loop.sh`:

```bash
INTERVAL_MINUTES=30    # Change to 15, 60, etc.
DURATION_HOURS=12      # Change to 6, 24, etc.
```

Then restart the schedule.

### Modify What Runs

The loop executes `./autonomous-agent.sh` by default.

To use a different command, edit `run-autonomous-loop.sh` around line 43:

```bash
# Current:
if ./autonomous-agent.sh; then

# Change to:
if ./tdd-agent.sh; then
# or
if ./autonomous-agent-demo.sh; then
```

---

## Troubleshooting

### Loop Not Starting

```bash
# Check for existing PID file
ls -la autonomous-loop.pid

# Remove if stale
rm autonomous-loop.pid

# Try starting again
autonomous-agent-schedule-start
```

### Loop Stopped Unexpectedly

```bash
# Check the schedule log for errors
tail -100 autonomous-loop-*.log

# Look for:
# - Failed runs
# - Error messages
# - Exit codes
```

### Out of Disk Space

Agent logs can accumulate. Clean up old logs:

```bash
# Remove logs older than 7 days
find agent-logs -name "*.log" -mtime +7 -delete

# Or keep only last 50 logs
ls -t agent-logs/*.log | tail -n +51 | xargs rm
```

### Process Won't Stop

```bash
# Get PID
PID=$(cat autonomous-loop.pid)

# Force kill
kill -9 $PID

# Clean up
rm autonomous-loop.pid
```

---

## Best Practices

### 1. Monitor Initially

When first starting a scheduled run, monitor it for the first few executions to ensure it's working correctly:

```bash
autonomous-agent-schedule-start
sleep 5
autonomous-agent-schedule-monitor
```

### 2. Check Logs Periodically

```bash
# Every few hours, check:
agent-logs-list              # See what's been completed
git log --oneline -20        # View commits
```

### 3. Plan for Long Runs

For 12+ hour runs:
- Ensure adequate disk space (500MB+ recommended)
- Keep system plugged in (laptops)
- Disable sleep mode
- Consider running in tmux/screen

### 4. Git Repository Health

```bash
# Before starting long run:
git status                   # Ensure clean state
git pull                     # Get latest

# During run:
git log --graph --oneline -10  # Monitor progress

# After run:
git push                     # Push completed work
```

---

## Example Use Cases

### Overnight Development

```bash
# Start before bed (8-hour run)
# Edit run-autonomous-loop.sh: DURATION_HOURS=8
autonomous-agent-schedule-start

# Check in the morning
git log --since="yesterday" --oneline
```

### Weekend Sprint

```bash
# Start Friday evening (48-hour run)
# Edit run-autonomous-loop.sh: DURATION_HOURS=48
autonomous-agent-schedule-start

# Monitor Sunday
autonomous-agent-schedule-monitor
```

### Hourly Execution

```bash
# Edit run-autonomous-loop.sh:
# INTERVAL_MINUTES=60
# DURATION_HOURS=12

autonomous-agent-schedule-start
```

---

## Safety Features

The autonomous agent loop includes:

1. **Error Tolerance**: Continues even if individual runs fail
2. **Progress Tracking**: Logs success/failure rates
3. **Clean Shutdown**: Stops cleanly after duration expires
4. **PID Management**: Prevents multiple instances
5. **Individual Logs**: Each run logged separately

---

## Stopping Early

If you need to stop before the 12 hours complete:

```bash
# Graceful stop
autonomous-agent-schedule-stop

# Force stop
kill $(cat autonomous-loop.pid)
rm autonomous-loop.pid
```

The loop will finish the current work stream before stopping (may take 5-10 minutes).

---

## Advanced: Running Multiple Schedules

You can run multiple instances with different configurations:

```bash
# Create custom loop script
cp run-autonomous-loop.sh run-custom-loop.sh

# Edit configuration
vim run-custom-loop.sh

# Start with custom PID file
sed -i 's/autonomous-loop.pid/custom-loop.pid/g' start-autonomous-schedule.sh
./start-autonomous-schedule.sh
```

---

## Scheduled Execution Log Example

```
╔════════════════════════════════════════════════════════════╗
║     AUTONOMOUS AGENT - CONTINUOUS EXECUTION LOOP           ║
╚════════════════════════════════════════════════════════════╝

Run #1 of 24 - 2025-12-22 17:04:24
✅ Work Stream 12 completed successfully

Run #2 of 24 - 2025-12-22 17:34:24
✅ Work Stream 13 completed successfully

Run #3 of 24 - 2025-12-22 18:04:24
✅ Work Stream 14 completed successfully

📊 Progress: 3/24 runs | ✅ 3 success | ❌ 0 failed
```

---

## Summary

The autonomous agent scheduling system enables **hands-off development** over extended periods:

✅ Set it and forget it
✅ Works overnight/weekend
✅ Continuous progress on roadmap
✅ Auto-commits all work
✅ Full logging and monitoring
✅ Safe error handling
✅ Easy to stop/start

Perfect for making steady progress on large projects!
