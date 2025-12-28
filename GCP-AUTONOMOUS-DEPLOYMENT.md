# Autonomous Development System - GCP Deployment Guide

**Version:** 1.0
**Last Updated:** 2025-12-27
**VM Type:** E2-small (2 vCPU, 2 GB memory)
**Estimated Cost:** ~$15/month

---

## Overview

This guide walks you through deploying the complete autonomous development system to Google Cloud Platform. The system runs three autonomous agents on a scheduled basis:

- **Autonomous Developer** - Executes roadmap work streams every 30 minutes
- **Autonomous Reviewer** - Performs architectural reviews every hour
- **Email Summary Agent** - Sends status updates every 4 hours

All agents run on a single E2-small VM instance, keeping costs low while providing continuous development and quality monitoring.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Detailed Setup](#detailed-setup)
4. [Configuration](#configuration)
5. [Monitoring & Management](#monitoring--management)
6. [Troubleshooting](#troubleshooting)
7. [Cost Management](#cost-management)
8. [Security Considerations](#security-considerations)

---

## Prerequisites

### Required Accounts & Tools

1. **Google Cloud Platform Account**
   - Active GCP project
   - Billing enabled
   - Compute Engine API enabled

2. **Google Cloud SDK (gcloud CLI)**
   ```bash
   # Install gcloud CLI
   # macOS
   brew install google-cloud-sdk

   # Windows
   # Download from: https://cloud.google.com/sdk/docs/install

   # Linux
   curl https://sdk.cloud.google.com | bash

   # Authenticate
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   ```

3. **Anthropic API Key**
   - Sign up at: https://console.anthropic.com
   - Create API key
   - Keep it secure (you'll add it to GCP Secret Manager)

4. **SendGrid API Key (Optional but Recommended)**
   - Sign up at: https://sendgrid.com
   - Create API key with Mail Send permissions
   - Free tier: 100 emails/day (sufficient for this use case)

### Required GCP APIs

Enable these APIs in your project:

```bash
gcloud services enable compute.googleapis.com
gcloud services enable secretmanager.googleapis.com
```

---

## Quick Start

### 1. Store Secrets in GCP Secret Manager

```bash
# Store Anthropic API key
echo -n "YOUR_ANTHROPIC_API_KEY" | gcloud secrets create anthropic-api-key --data-file=-

# Store SendGrid API key (optional)
echo -n "YOUR_SENDGRID_API_KEY" | gcloud secrets create sendgrid-api-key --data-file=-

# Verify secrets
gcloud secrets list
```

### 2. Set Environment Variables

```bash
# Required
export GCP_PROJECT_ID="your-project-id"
export EMAIL_TO="your-email@example.com"

# Optional
export GCP_ZONE="us-central1-a"              # Default zone
export VM_NAME="autonomous-dev-vm"           # Default VM name
export EMAIL_FROM="autonomous-dev@yourapp.com"
export REPO_URL="https://github.com/yourusername/financial-rise.git"
export REPO_BRANCH="main"
```

### 3. Provision the VM

```bash
cd gcp-vm
./provision-autonomous-vm.sh
```

This will:
- Create an E2-small VM instance
- Install all dependencies (Node.js, Git, Claude Code)
- Clone your repository
- Set up cron jobs
- Start autonomous agents

**Provisioning takes ~10 minutes**

### 4. Verify Deployment

```bash
# Check VM status
gcloud compute instances describe autonomous-dev-vm --zone=us-central1-a

# SSH into VM
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# Inside VM, check logs
tail -f /var/log/autonomous-dev-setup.log
tail -f ~/logs/autonomous-agent.log
tail -f ~/logs/autonomous-reviewer.log
```

---

## Detailed Setup

### Step 1: Project Setup

1. **Create or select GCP project:**
   ```bash
   # Create new project
   gcloud projects create autonomous-dev-project --name="Autonomous Development"

   # Or list existing projects
   gcloud projects list

   # Set active project
   gcloud config set project YOUR_PROJECT_ID
   ```

2. **Enable billing:**
   - Go to: https://console.cloud.google.com/billing
   - Link a billing account to your project

3. **Enable required APIs:**
   ```bash
   gcloud services enable compute.googleapis.com
   gcloud services enable secretmanager.googleapis.com
   ```

### Step 2: Configure Secrets

**Anthropic API Key (Required):**
```bash
# Interactive
gcloud secrets create anthropic-api-key
# Paste your key when prompted

# Or from file
echo -n "sk-ant-..." > /tmp/api-key.txt
gcloud secrets create anthropic-api-key --data-file=/tmp/api-key.txt
rm /tmp/api-key.txt
```

**SendGrid API Key (Recommended):**
```bash
echo -n "SG...." | gcloud secrets create sendgrid-api-key --data-file=-
```

**Verify secrets exist:**
```bash
gcloud secrets list
```

### Step 3: Prepare Repository

1. **Push your code to Git:**
   ```bash
   # If not already in git
   git init
   git add .
   git commit -m "Initial commit"

   # Push to GitHub/GitLab
   git remote add origin https://github.com/yourusername/yourrepo.git
   git push -u origin main
   ```

2. **Ensure repository is accessible:**
   - Public repository: No additional setup needed
   - Private repository: Set up SSH keys or deploy tokens

### Step 4: Deploy VM

1. **Set environment variables:**
   ```bash
   export GCP_PROJECT_ID="your-project-id"
   export EMAIL_TO="you@example.com"
   export REPO_URL="https://github.com/yourusername/yourrepo.git"
   export REPO_BRANCH="main"
   ```

2. **Run provisioning script:**
   ```bash
   cd gcp-vm
   chmod +x provision-autonomous-vm.sh
   ./provision-autonomous-vm.sh
   ```

3. **Monitor startup:**
   ```bash
   # Watch startup logs in real-time
   gcloud compute instances get-serial-port-output autonomous-dev-vm \
     --zone=us-central1-a \
     --start=0
   ```

---

## Configuration

### VM Metadata

The VM reads configuration from metadata:

| Metadata Key | Description | Required |
|--------------|-------------|----------|
| `repo-url` | Git repository URL | Yes |
| `repo-branch` | Git branch to use | No (default: main) |
| `email-to` | Email address for summaries | Yes |
| `email-from` | From email address | No (default: autonomous-dev@localhost) |

**Update metadata after deployment:**
```bash
gcloud compute instances add-metadata autonomous-dev-vm \
  --zone=us-central1-a \
  --metadata=email-to=newemail@example.com
```

### Cron Schedule

The system runs on this schedule:

| Agent | Frequency | Cron Expression | Purpose |
|-------|-----------|-----------------|---------|
| Autonomous Developer | Every 30 min | `*/30 * * * *` | Execute roadmap work streams |
| Autonomous Reviewer | Every hour | `15 * * * *` | Scan code for anti-patterns |
| Email Summary | Every 4 hours | `0 */4 * * *` | Send status updates |

**View cron jobs:**
```bash
# SSH into VM
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# View crontab
crontab -l
```

**Modify cron schedule:**
```bash
# Edit crontab
crontab -e

# Example: Change developer to every 15 minutes
# */15 * * * * source ~/.autonomous-env && cd ~/src && ./autonomous-agent.sh >> ~/logs/autonomous-agent.log 2>&1
```

### Environment Variables

The VM uses `~/.autonomous-env` for configuration:

```bash
# On the VM
cat ~/.autonomous-env

# Contents:
export ANTHROPIC_API_KEY="sk-ant-..."
export SENDGRID_API_KEY="SG...."
export EMAIL_TO="you@example.com"
export EMAIL_FROM="autonomous-dev@yourapp.com"
export REPO_URL="https://github.com/..."
export REPO_BRANCH="main"
```

**Update environment:**
```bash
# SSH into VM
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# Edit environment file
vi ~/.autonomous-env

# Source changes
source ~/.autonomous-env
```

---

## Monitoring & Management

### View Logs

**From local machine:**
```bash
# SSH and tail logs
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a \
  --command="tail -f ~/logs/autonomous-agent.log"
```

**On the VM:**
```bash
# All logs
ls -lht ~/logs/

# Autonomous developer
tail -f ~/logs/autonomous-agent.log

# Autonomous reviewer
tail -f ~/logs/autonomous-reviewer.log

# Email summaries
tail -f ~/logs/email-summary.log

# Specific agent run
cat ~/src/agent-logs/autonomous-agent-20251227-153000.log
```

### Check Agent Status

**Verify cron is running:**
```bash
# Check cron service
sudo systemctl status cron

# View recent cron logs
sudo grep CRON /var/log/syslog | tail -20
```

**Check for errors:**
```bash
# Recent errors in autonomous agent
grep -i error ~/logs/autonomous-agent.log | tail -20

# Recent errors in reviewer
grep -i error ~/logs/autonomous-reviewer.log | tail -20
```

### View Review Reports

```bash
# List all reviews
ls -lht ~/src/reviews/review-*.md

# View latest review
cat $(ls -t ~/src/reviews/review-*.md | head -1)

# Check anti-patterns checklist
cat ~/src/reviews/anti-patterns-checklist.md
```

### Check Roadmap Progress

```bash
# View current roadmap
cat ~/src/plans/roadmap.md

# View completed work
cat ~/src/plans/completed/roadmap-archive.md

# Check git commits
cd ~/src
git log --oneline --since="1 day ago"
```

### Email Summaries

**View sent summaries:**
```bash
ls -lht ~/src/email-summaries/summary-*.json

# View latest summary
cat $(ls -t ~/src/email-summaries/summary-*.json | head -1) | python3 -m json.tool
```

**Manually trigger summary:**
```bash
cd ~/src
./send-email-summary.sh
```

### VM Operations

**Stop VM (saves costs):**
```bash
gcloud compute instances stop autonomous-dev-vm --zone=us-central1-a
```

**Start VM:**
```bash
gcloud compute instances start autonomous-dev-vm --zone=us-central1-a
```

**Restart VM:**
```bash
gcloud compute instances reset autonomous-dev-vm --zone=us-central1-a
```

**Delete VM:**
```bash
gcloud compute instances delete autonomous-dev-vm --zone=us-central1-a
```

---

## Troubleshooting

### Common Issues

#### 1. No emails received

**Check SendGrid API key:**
```bash
# SSH into VM
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# Verify environment
echo $SENDGRID_API_KEY
echo $EMAIL_TO

# Test email manually
cd ~/src
./send-email-summary.sh "Test Email"
```

**Check email logs:**
```bash
tail -f ~/logs/email-summary.log
grep -i error ~/logs/email-summary.log
```

**Verify SendGrid setup:**
- Go to SendGrid dashboard
- Check API key permissions (Mail Send required)
- Verify sender authentication

#### 2. Agents not running

**Check cron:**
```bash
# View crontab
crontab -l

# Check cron is enabled
sudo systemctl status cron

# Check syslog for cron execution
sudo grep CRON /var/log/syslog | tail -20
```

**Check for errors:**
```bash
# Recent agent logs
tail -50 ~/logs/autonomous-agent.log
tail -50 ~/logs/autonomous-reviewer.log
```

**Manually run agent:**
```bash
cd ~/src
./autonomous-agent.sh
```

#### 3. Claude API errors

**Verify API key:**
```bash
# Check key is set
echo $ANTHROPIC_API_KEY

# Test Claude CLI
claude --version
```

**Check for rate limiting:**
```bash
grep -i "rate limit" ~/logs/*.log
```

**Verify secret in GCP:**
```bash
gcloud secrets versions access latest --secret=anthropic-api-key
```

#### 4. Git push failures

**Check git credentials:**
```bash
cd ~/src
git status
git remote -v
```

**For private repos, set up SSH:**
```bash
# Generate SSH key on VM
ssh-keygen -t ed25519 -C "autonomous-dev@vm"

# Add to GitHub/GitLab
cat ~/.ssh/id_ed25519.pub
# Copy and add to your Git provider's deploy keys
```

#### 5. Out of disk space

**Check disk usage:**
```bash
df -h
du -sh ~/src/*
du -sh ~/logs/*
```

**Clean up old logs:**
```bash
# Delete logs older than 7 days
find ~/logs -name "*.log" -mtime +7 -delete

# Delete old agent logs
find ~/src/agent-logs -name "*.log" -mtime +7 -delete
```

### Debug Mode

**Enable verbose logging:**
```bash
# Edit agent scripts
vi ~/src/autonomous-agent.sh

# Add debug flags
set -x  # Print commands
set -v  # Print input lines

# Run manually
cd ~/src
bash -x ./autonomous-agent.sh
```

### Getting Help

**View startup logs:**
```bash
sudo cat /var/log/autonomous-dev-setup.log
```

**Check VM serial console:**
```bash
gcloud compute instances get-serial-port-output autonomous-dev-vm --zone=us-central1-a
```

---

## Cost Management

### Current Costs (E2-small)

**VM Costs (us-central1):**
- E2-small: $0.0201/hour = ~$14.67/month (24/7)
- Boot disk (30GB standard): $1.20/month
- **Total: ~$15.87/month**

**Other Costs:**
- Egress (email/git): <$1/month
- Secret Manager: Free (< 6 secrets)
- **Grand Total: ~$17/month**

### Cost Optimization

**1. Use Preemptible VM (70% discount):**
```bash
# Add --preemptible flag to provision script
gcloud compute instances create autonomous-dev-vm \
  --preemptible \
  ...
```
**Savings:** ~$11/month
**Tradeoff:** VM may be terminated (rarely affects 24-hour workloads)

**2. Stop VM when not needed:**
```bash
# Stop VM nights/weekends
gcloud compute instances stop autonomous-dev-vm --zone=us-central1-a
```
**Savings:** ~$10/month (if running 12 hours/day)

**3. Use committed use discounts:**
- 1-year commitment: 25% discount
- 3-year commitment: 52% discount

**4. Use smaller regions:**
Some regions are cheaper than us-central1

### Budget Alerts

**Set up billing alerts:**
```bash
# Via gcloud
gcloud billing budgets create \
  --billing-account=BILLING_ACCOUNT_ID \
  --display-name="Autonomous Dev Budget" \
  --budget-amount=20USD \
  --threshold-rule=percent=50 \
  --threshold-rule=percent=90 \
  --threshold-rule=percent=100
```

---

## Security Considerations

### API Key Security

**✅ DO:**
- Store API keys in GCP Secret Manager
- Use IAM roles to restrict access
- Rotate keys periodically
- Use separate keys for dev/prod

**❌ DON'T:**
- Commit API keys to git
- Share keys via email/Slack
- Use production keys in development

### VM Security

**Firewall:**
```bash
# VM has no ingress by default (SSH only)
# Verify firewall rules
gcloud compute firewall-rules list
```

**Service Account:**
```bash
# Use custom service account with minimal permissions
gcloud iam service-accounts create autonomous-dev-sa \
  --display-name="Autonomous Development SA"

# Grant only required permissions
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:autonomous-dev-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

**SSH Access:**
```bash
# Limit SSH to specific users
gcloud compute instances add-metadata autonomous-dev-vm \
  --zone=us-central1-a \
  --metadata=enable-oslogin=TRUE
```

### Code Security

**Review automated changes:**
- Check email summaries regularly
- Review git commits periodically
- Monitor for unexpected behavior

**Repository access:**
- Use deploy keys for private repos
- Grant read-only access where possible
- Use separate branch for autonomous work

---

## Next Steps

After deployment:

1. **Monitor first 24 hours:**
   - Check email summaries (every 4 hours)
   - Review agent logs for errors
   - Verify roadmap progress

2. **Tune scheduling:**
   - Adjust cron intervals if needed
   - Balance velocity vs cost

3. **Configure alerts:**
   - Set up GCP monitoring alerts
   - Configure budget notifications
   - Monitor Secret Manager access logs

4. **Backup strategy:**
   - Snapshot VM disk periodically
   - Ensure git repo is backed up
   - Export important logs to GCS

5. **Scale as needed:**
   - Upgrade to E2-medium if performance is slow
   - Add more VMs for parallel work
   - Consider Cloud Build for heavier workloads

---

## Support & Resources

- **GCP Documentation:** https://cloud.google.com/docs
- **Claude Code Docs:** https://docs.anthropic.com/claude-code
- **SendGrid Docs:** https://docs.sendgrid.com

For issues with this deployment, check:
1. Logs: `~/logs/*.log` and `~/src/agent-logs/*.log`
2. Email summaries for error notifications
3. GCP Console for VM health and costs
