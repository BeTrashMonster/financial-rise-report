#!/bin/bash
# vm-startup-script.sh - GCP VM startup script for autonomous development
#
# This script runs automatically when the VM starts and sets up:
# - System dependencies
# - Node.js, Git, Claude Code CLI
# - Repository clone
# - Cron jobs for autonomous agents
# - Email notifications

set -e

LOGFILE="/var/log/autonomous-dev-setup.log"

# Redirect all output to log file
exec > >(tee -a "$LOGFILE")
exec 2>&1

echo "════════════════════════════════════════════════════════════"
echo "AUTONOMOUS DEVELOPMENT VM STARTUP"
echo "Started: $(date)"
echo "════════════════════════════════════════════════════════════"
echo ""

# Get metadata
REPO_URL=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/repo-url" -H "Metadata-Flavor: Google" || echo "")
REPO_BRANCH=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/repo-branch" -H "Metadata-Flavor: Google" || echo "main")
EMAIL_TO=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/email-to" -H "Metadata-Flavor: Google" || echo "")
EMAIL_FROM=$(curl -s "http://metadata.google.internal/computeMetadata/v1/instance/attributes/email-from" -H "Metadata-Flavor: Google" || echo "")

# Get secrets from Google Secret Manager (if available)
ANTHROPIC_API_KEY=$(gcloud secrets versions access latest --secret="anthropic-api-key" 2>/dev/null || echo "")
SENDGRID_API_KEY=$(gcloud secrets versions access latest --secret="sendgrid-api-key" 2>/dev/null || echo "")

echo "Configuration:"
echo "  Repository: $REPO_URL"
echo "  Branch: $REPO_BRANCH"
echo "  Email To: ${EMAIL_TO:-Not configured}"
echo "  Anthropic API Key: ${ANTHROPIC_API_KEY:+[Set]}${ANTHROPIC_API_KEY:-[Not set]}"
echo ""

# Create autonomous user
if ! id -u autonomous &>/dev/null; then
    echo "📝 Creating autonomous user..."
    useradd -m -s /bin/bash autonomous
    usermod -aG sudo autonomous
    echo "autonomous ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/autonomous
fi

# Switch to autonomous user for remaining setup
cat > /home/autonomous/setup.sh << 'SETUP_EOF'
#!/bin/bash
set -e

echo "════════════════════════════════════════════════════════════"
echo "STEP 1: Installing System Dependencies"
echo "════════════════════════════════════════════════════════════"
sudo apt-get update
sudo apt-get install -y \
    curl \
    git \
    build-essential \
    ca-certificates \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    sendmail \
    mailutils

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 2: Installing Node.js"
echo "════════════════════════════════════════════════════════════"
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version
npm --version

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 3: Installing Claude Code CLI"
echo "════════════════════════════════════════════════════════════"
npm install -g @anthropic-ai/claude-code
claude --version

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 4: Configuring Claude Code"
echo "════════════════════════════════════════════════════════════"

# Create Claude config directory
mkdir -p ~/.config/claude

# Set API key if available
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "Setting Anthropic API key..."
    cat > ~/.config/claude/config.json << CONFIG_EOF
{
  "apiKey": "$ANTHROPIC_API_KEY"
}
CONFIG_EOF
    chmod 600 ~/.config/claude/config.json
else
    echo "⚠️  WARNING: ANTHROPIC_API_KEY not set!"
    echo "   Autonomous agents will not work without it."
    echo ""
    echo "To set the API key after VM creation:"
    echo "  1. Create secret: gcloud secrets create anthropic-api-key --data-file=- <<< 'your-key'"
    echo "  2. Restart VM or run: claude config set apiKey YOUR_KEY"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 5: Cloning Repository"
echo "════════════════════════════════════════════════════════════"

cd /home/autonomous

if [ -z "$REPO_URL" ]; then
    echo "⚠️  WARNING: repo-url metadata not set!"
    echo "   Skipping repository clone."
else
    if [ -d "src" ]; then
        echo "Repository already exists, pulling latest..."
        cd src
        git pull origin "$REPO_BRANCH"
    else
        echo "Cloning $REPO_URL (branch: $REPO_BRANCH)..."
        git clone -b "$REPO_BRANCH" "$REPO_URL" src
        cd src
    fi

    # Install repository dependencies if they exist
    if [ -f "package.json" ]; then
        echo "Installing repository dependencies..."
        npm install
    fi

    # Make scripts executable
    chmod +x *.sh 2>/dev/null || true
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 6: Setting Up Environment"
echo "════════════════════════════════════════════════════════════"

# Create environment file
cat > /home/autonomous/.autonomous-env << ENV_EOF
# Autonomous Development Environment
export ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY"
export SENDGRID_API_KEY="$SENDGRID_API_KEY"
export EMAIL_TO="$EMAIL_TO"
export EMAIL_FROM="${EMAIL_FROM:-autonomous-dev@localhost}"
export REPO_URL="$REPO_URL"
export REPO_BRANCH="$REPO_BRANCH"
ENV_EOF

chmod 600 /home/autonomous/.autonomous-env

# Add to .bashrc
if ! grep -q "source ~/.autonomous-env" ~/.bashrc; then
    echo "source ~/.autonomous-env" >> ~/.bashrc
fi

# Source it now
source /home/autonomous/.autonomous-env

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 7: Setting Up Cron Jobs"
echo "════════════════════════════════════════════════════════════"

# Create crontab configuration
CRON_FILE="/tmp/autonomous-crontab"
cat > "$CRON_FILE" << 'CRON_EOF'
# Autonomous Development Cron Jobs
SHELL=/bin/bash
PATH=/usr/local/bin:/usr/bin:/bin
MAILTO=""

# Load environment
@reboot sleep 60 && source ~/.autonomous-env && cd ~/src && ./autonomous-agent.sh >> ~/logs/startup-agent.log 2>&1

# Run autonomous developer every 30 minutes
*/30 * * * * source ~/.autonomous-env && cd ~/src && ./autonomous-agent.sh >> ~/logs/autonomous-agent.log 2>&1

# Run autonomous reviewer every hour at :15 past the hour
15 * * * * source ~/.autonomous-env && cd ~/src && ./autonomous-reviewer.sh >> ~/logs/autonomous-reviewer.log 2>&1

# Send email summary every 4 hours
0 */4 * * * source ~/.autonomous-env && cd ~/src && ./send-email-summary.sh >> ~/logs/email-summary.log 2>&1

# Daily cleanup of old logs (keep 7 days)
0 2 * * * find ~/logs -name "*.log" -mtime +7 -delete
CRON_EOF

# Install crontab
crontab "$CRON_FILE"
rm "$CRON_FILE"

echo "Cron jobs installed:"
crontab -l

# Create logs directory
mkdir -p /home/autonomous/logs

echo ""
echo "════════════════════════════════════════════════════════════"
echo "STEP 8: Setting Up Email Configuration"
echo "════════════════════════════════════════════════════════════"

if [ -n "$SENDGRID_API_KEY" ]; then
    echo "SendGrid API key configured"
    # Install SendGrid Python client
    pip3 install sendgrid
else
    echo "⚠️  SendGrid API key not configured"
    echo "   Email notifications will use local sendmail (may not work)"
    echo ""
    echo "To configure SendGrid:"
    echo "  gcloud secrets create sendgrid-api-key --data-file=- <<< 'your-key'"
fi

echo ""
echo "════════════════════════════════════════════════════════════"
echo "SETUP COMPLETE"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "✅ All dependencies installed"
echo "✅ Repository cloned"
echo "✅ Cron jobs configured"
echo "✅ Environment configured"
echo ""
echo "Autonomous agents will run on schedule:"
echo "  - Developer: Every 30 minutes"
echo "  - Reviewer: Every hour at :15"
echo "  - Email summary: Every 4 hours"
echo ""
echo "Logs location: /home/autonomous/logs/"
echo ""

# Send initial notification
if [ -n "$EMAIL_TO" ]; then
    echo "Sending startup notification to $EMAIL_TO..."
    cd ~/src
    ./send-email-summary.sh "Autonomous Development VM Started" || echo "⚠️  Email notification failed"
fi

SETUP_EOF

# Make setup script executable and run as autonomous user
chmod +x /home/autonomous/setup.sh
chown autonomous:autonomous /home/autonomous/setup.sh

# Export variables for the setup script
export REPO_URL REPO_BRANCH EMAIL_TO EMAIL_FROM ANTHROPIC_API_KEY SENDGRID_API_KEY

# Run setup as autonomous user
su - autonomous -c "/home/autonomous/setup.sh"

echo ""
echo "════════════════════════════════════════════════════════════"
echo "VM STARTUP COMPLETE"
echo "Finished: $(date)"
echo "════════════════════════════════════════════════════════════"
