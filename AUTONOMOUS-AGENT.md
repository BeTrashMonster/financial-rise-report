# Autonomous Agent Commands

## Quick Start

The autonomous agent commands are now available globally in your shell!

### Setup (Already Done ✅)

The following files have been configured:
- `~/.bashrc` - Loads autonomous agent commands on shell startup
- `~/.bash_profile` - Created automatically to load .bashrc
- `.autonomous-agent-env.sh` - Defines all agent commands

**The commands are ready to use immediately after sourcing your profile:**

```bash
source ~/.bashrc
```

Or simply **open a new terminal** and the commands will be available automatically.

---

## Available Commands

### 🤖 `autonomous-agent`

Complete the next work stream from the roadmap autonomously.

```bash
# Run from anywhere
autonomous-agent
```

**What it does:**
1. Reads `plans/roadmap.md`
2. Identifies next unclaimed work stream with satisfied dependencies
3. Completes all tasks and deliverables
4. Auto-commits changes with proper git messages
5. Logs execution to `agent-logs/autonomous-agent-{timestamp}.log`

**Use case:** Continuous autonomous development

---

### 🎯 `autonomous-agent-demo`

Quick demo that completes a single task (fast, for testing).

```bash
autonomous-agent-demo
```

**What it does:**
- Completes one specific task from the roadmap
- Creates files and commits changes
- Demonstrates end-to-end autonomous workflow
- Finishes in ~2-5 minutes

**Use case:** Testing the autonomous agent system

---

### 🔍 `autonomous-agent-test`

Identify the next work stream without executing it.

```bash
autonomous-agent-test
```

**What it does:**
- Analyzes the roadmap
- Reports which work stream is next
- Explains why it's ready (dependencies satisfied)
- Does NOT execute the work stream

**Use case:** Planning and roadmap review

---

### 🧪 `tdd-agent`

Run TDD-focused work stream execution.

```bash
tdd-agent
```

**What it does:**
- Executes work streams with strict Test-Driven Development
- Writes tests first (RED phase)
- Implements code to pass tests (GREEN phase)
- Refactors for quality (REFACTOR phase)
- Ensures 100% test coverage for business logic

**Use case:** Quality-focused development with TDD discipline

---

### 📋 `agent-logs`

View the most recent agent execution log.

```bash
agent-logs
```

**What it does:**
- Finds the latest log file
- Displays full log content
- Shows what the agent did, created, and committed

**Use case:** Review what the autonomous agent just completed

---

### 📁 `agent-logs-list`

List all agent execution logs.

```bash
agent-logs-list
```

**What it does:**
- Lists all log files in chronological order
- Shows file sizes and timestamps
- Helps you find specific execution logs

**Use case:** Browse historical agent executions

---

## Examples

### Complete multiple work streams in sequence

```bash
# Run in a loop to complete several work streams
for i in {1..3}; do
  echo "=== Iteration $i ==="
  autonomous-agent
  echo ""
done
```

### Check what's next before running

```bash
# See what will be worked on
autonomous-agent-test

# If you like it, execute it
autonomous-agent
```

### Review recent work

```bash
# List all logs
agent-logs-list

# View latest execution details
agent-logs
```

---

## How It Works

All commands are bash functions that:

1. **Navigate to project directory:** `/c/Users/Admin/src`
2. **Execute the appropriate script:** `./autonomous-agent.sh`, etc.
3. **Return to your original directory** when done

You can run them from **anywhere** in your filesystem - they always operate on the Financial RISE project.

---

## Logs

All execution logs are saved to:

```
/c/Users/Admin/src/agent-logs/
```

Log files are named:
- `autonomous-agent-{timestamp}.log`
- `demo-{timestamp}.log`
- `tdd-agent-{timestamp}.log`
- `test-agent-{timestamp}.log`

Logs contain:
- Full agent output
- Files created
- Git commits made
- Errors (if any)

---

## Customization

To modify the autonomous agent behavior, edit:

```bash
cd /c/Users/Admin/src
vim autonomous-agent.sh
```

To add new commands, edit:

```bash
vim .autonomous-agent-env.sh
source ~/.bashrc  # Reload
```

---

## Troubleshooting

### Commands not found

```bash
# Reload shell configuration
source ~/.bashrc
```

### View command definitions

```bash
type autonomous-agent
type agent-logs
```

### Check agent directory

```bash
echo $AGENT_DIR
```

Should output: `/c/Users/Admin/src`

---

## Uninstall

To remove the autonomous agent commands:

1. Edit `~/.bashrc` and remove the source line
2. Reload shell: `source ~/.bashrc`

Or keep them - they're useful! 🚀
