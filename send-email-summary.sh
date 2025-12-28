#!/bin/bash
# send-email-summary.sh - Generate and send email summary of autonomous activity
#
# This script:
# 1. Uses Claude to generate a summary of the last 4 hours of activity
# 2. Sends the summary via SendGrid or SMTP
# 3. Logs the activity

set -e

# Configuration from environment
EMAIL_TO="${EMAIL_TO:-}"
EMAIL_FROM="${EMAIL_FROM:-autonomous-dev@localhost}"
SENDGRID_API_KEY="${SENDGRID_API_KEY:-}"
CUSTOM_SUBJECT="${1:-}"  # Optional custom subject passed as argument

# Directories
LOGS_DIR="logs"
SUMMARY_DIR="email-summaries"
mkdir -p "$LOGS_DIR" "$SUMMARY_DIR"

# Generate timestamp
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
SUMMARY_FILE="$SUMMARY_DIR/summary-$TIMESTAMP.json"
LOG_FILE="$LOGS_DIR/email-summary-$TIMESTAMP.log"

echo "╔════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
echo "║        EMAIL SUMMARY GENERATION                            ║" | tee -a "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Timestamp: $(date)" | tee -a "$LOG_FILE"
echo "Email To: ${EMAIL_TO:-[Not configured]}" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Validation
if [ -z "$EMAIL_TO" ]; then
    echo "⚠️  EMAIL_TO not set. Cannot send email." | tee -a "$LOG_FILE"
    echo "   Set with: export EMAIL_TO=your-email@example.com" | tee -a "$LOG_FILE"
    exit 1
fi

# Step 1: Generate summary using Claude
echo "🤖 Generating summary using Claude..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

CLAUDE_OUTPUT=$(claude \
  --dangerously-skip-permissions \
  --print \
  "$(cat <<'EOF'
Generate an email summary of autonomous development activity from the last 4 hours.

CRITICAL REQUIREMENTS:

1. Review Recent Activity:
   - Check logs/autonomous-agent.log for developer activity
   - Check logs/autonomous-reviewer.log for review activity
   - Read latest reviews/review-*.md reports (last 4 hours)
   - Check plans/roadmap.md for progress
   - Run: git log --since="4 hours ago" --pretty=format:"%h - %s" --stat

2. Gather Metrics:
   - How many autonomous developer runs (success/failed)?
   - How many work streams completed?
   - How many review runs?
   - How many issues found (by severity)?
   - What files were changed?
   - Were there any errors?

3. Generate Summary:
   - Keep it brief and scannable (< 500 words)
   - Highlight critical issues prominently
   - Include specific metrics and file names
   - Note any failures or errors
   - Track roadmap progress

4. Return as JSON:
   Must return ONLY valid JSON in this exact format:

{
  "subject": "✅ Autonomous Dev Summary - X work streams, Y issues",
  "priority": "normal",
  "body_html": "<h1>Summary</h1><p>Content...</p>",
  "body_text": "Plain text version...",
  "metrics": {
    "developer_runs_success": 0,
    "developer_runs_failed": 0,
    "work_streams_completed": 0,
    "reviewer_runs": 0,
    "critical_issues": 0,
    "high_issues": 0
  }
}

Priority levels: "critical", "high", or "normal"

IMPORTANT:
- Return ONLY the JSON object, no other text
- Ensure the JSON is valid and properly escaped
- If no activity in last 4 hours, still return JSON with zeros
- Check actual log files, don't make up data

Focus on actionable information. What was accomplished? What needs attention?
EOF
)" 2>&1) || {
    echo "❌ Claude execution failed" | tee -a "$LOG_FILE"
    echo "$CLAUDE_OUTPUT" | tee -a "$LOG_FILE"
    exit 1
}

# Save raw Claude output for debugging
echo "$CLAUDE_OUTPUT" > "$SUMMARY_FILE.raw"

# Extract JSON from Claude output (it may include other text)
JSON_OUTPUT=$(echo "$CLAUDE_OUTPUT" | grep -Pzo '(?s)\{.*\}' | tr -d '\0' || echo "$CLAUDE_OUTPUT")

# Validate JSON
if ! echo "$JSON_OUTPUT" | python3 -m json.tool > "$SUMMARY_FILE" 2>/dev/null; then
    echo "❌ Invalid JSON output from Claude" | tee -a "$LOG_FILE"
    echo "Raw output:" | tee -a "$LOG_FILE"
    echo "$CLAUDE_OUTPUT" | tee -a "$LOG_FILE"
    exit 1
fi

echo "✅ Summary generated successfully" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Extract fields from JSON
SUBJECT=$(python3 -c "import json; print(json.load(open('$SUMMARY_FILE'))['subject'])" 2>/dev/null || echo "Autonomous Dev Summary")
PRIORITY=$(python3 -c "import json; print(json.load(open('$SUMMARY_FILE'))['priority'])" 2>/dev/null || echo "normal")
BODY_HTML=$(python3 -c "import json; print(json.load(open('$SUMMARY_FILE'))['body_html'])" 2>/dev/null || echo "")
BODY_TEXT=$(python3 -c "import json; print(json.load(open('$SUMMARY_FILE'))['body_text'])" 2>/dev/null || echo "")

# Use custom subject if provided
if [ -n "$CUSTOM_SUBJECT" ]; then
    SUBJECT="$CUSTOM_SUBJECT"
fi

echo "Subject: $SUBJECT" | tee -a "$LOG_FILE"
echo "Priority: $PRIORITY" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Step 2: Send email
echo "📧 Sending email..." | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Method 1: SendGrid (preferred)
if [ -n "$SENDGRID_API_KEY" ]; then
    echo "Using SendGrid..." | tee -a "$LOG_FILE"

    # Create SendGrid request
    python3 << PYTHON_EOF
import json
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content

# Load summary
with open('$SUMMARY_FILE') as f:
    summary = json.load(f)

# Create email
message = Mail(
    from_email=Email('$EMAIL_FROM'),
    to_emails=To('$EMAIL_TO'),
    subject='$SUBJECT',
    html_content=Content("text/html", summary['body_html']),
    plain_text_content=Content("text/plain", summary['body_text'])
)

# Send via SendGrid
try:
    sg = SendGridAPIClient(os.environ['SENDGRID_API_KEY'])
    response = sg.send(message)
    print(f"✅ Email sent successfully (status: {response.status_code})")
except Exception as e:
    print(f"❌ SendGrid error: {e}")
    exit(1)
PYTHON_EOF

    if [ $? -eq 0 ]; then
        echo "✅ Email sent via SendGrid" | tee -a "$LOG_FILE"
    else
        echo "❌ SendGrid failed, trying fallback..." | tee -a "$LOG_FILE"
        SENDGRID_API_KEY=""  # Fall back to sendmail
    fi
fi

# Method 2: Sendmail fallback
if [ -z "$SENDGRID_API_KEY" ]; then
    echo "Using sendmail..." | tee -a "$LOG_FILE"

    # Create email file
    EMAIL_FILE="/tmp/email-$TIMESTAMP.txt"
    cat > "$EMAIL_FILE" << EMAIL_EOF
To: $EMAIL_TO
From: $EMAIL_FROM
Subject: $SUBJECT
Content-Type: text/html; charset=UTF-8

$BODY_HTML
EMAIL_EOF

    # Send via sendmail
    if command -v sendmail &> /dev/null; then
        sendmail -t < "$EMAIL_FILE"
        if [ $? -eq 0 ]; then
            echo "✅ Email sent via sendmail" | tee -a "$LOG_FILE"
        else
            echo "❌ Sendmail failed" | tee -a "$LOG_FILE"
        fi
    else
        echo "❌ sendmail not available" | tee -a "$LOG_FILE"
        echo "   Install with: sudo apt-get install sendmail" | tee -a "$LOG_FILE"
    fi

    rm -f "$EMAIL_FILE"
fi

echo "" | tee -a "$LOG_FILE"
echo "╔════════════════════════════════════════════════════════════╗" | tee -a "$LOG_FILE"
echo "║              EMAIL SUMMARY COMPLETE                        ║" | tee -a "$LOG_FILE"
echo "╚════════════════════════════════════════════════════════════╝" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Summary saved to: $SUMMARY_FILE" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
