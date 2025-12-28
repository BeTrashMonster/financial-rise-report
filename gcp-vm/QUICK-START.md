# Quick Start - Autonomous Development on GCP

**Goal:** Deploy the autonomous development system to Google Cloud in < 15 minutes

---

## Prerequisites Checklist

- [ ] Google Cloud account with billing enabled
- [ ] `gcloud` CLI installed and authenticated
- [ ] Anthropic API key from https://console.anthropic.com
- [ ] SendGrid API key from https://sendgrid.com (optional)
- [ ] Code repository on GitHub/GitLab

---

## 5-Step Deployment

### Step 1: Install gcloud CLI (if needed)

```bash
# macOS
brew install google-cloud-sdk

# Windows
# Download from: https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login
```

### Step 2: Set Your Project

```bash
# List projects
gcloud projects list

# Set active project
gcloud config set project YOUR_PROJECT_ID

# Enable APIs
gcloud services enable compute.googleapis.com secretmanager.googleapis.com
```

### Step 3: Store Secrets

```bash
# Store Anthropic API key (REQUIRED)
echo -n "sk-ant-YOUR_KEY_HERE" | gcloud secrets create anthropic-api-key --data-file=-

# Store SendGrid API key (OPTIONAL - for email notifications)
echo -n "SG.YOUR_KEY_HERE" | gcloud secrets create sendgrid-api-key --data-file=-
```

### Step 4: Configure & Deploy

```bash
# Set required environment variables
export GCP_PROJECT_ID="your-project-id"
export EMAIL_TO="your-email@example.com"
export REPO_URL="https://github.com/yourusername/yourrepo.git"
export REPO_BRANCH="main"  # Optional, defaults to main

# Deploy!
cd gcp-vm
./provision-autonomous-vm.sh
```

**Wait ~10 minutes for VM setup to complete**

### Step 5: Verify It's Working

```bash
# Monitor startup progress
gcloud compute instances get-serial-port-output autonomous-dev-vm --zone=us-central1-a | tail -50

# SSH into VM
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# Inside VM, check logs
tail -f ~/logs/autonomous-agent.log
```

---

## What Happens Next?

The VM is now running with these scheduled tasks:

| Agent | Schedule | What It Does |
|-------|----------|--------------|
| **Autonomous Developer** | Every 30 min | Executes roadmap work streams, writes code, runs tests |
| **Autonomous Reviewer** | Every hour at :15 | Scans code for bugs, security issues, anti-patterns |
| **Email Summary** | Every 4 hours | Sends you progress updates via email |

**You'll receive your first email summary within 4 hours.**

---

## Quick Commands

**View logs:**
```bash
# SSH into VM
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# View autonomous developer log
tail -f ~/logs/autonomous-agent.log

# View reviewer log
tail -f ~/logs/autonomous-reviewer.log

# View email summary log
tail -f ~/logs/email-summary.log

# View latest review report
cat $(ls -t ~/src/reviews/review-*.md | head -1)

# Check roadmap progress
cat ~/src/plans/roadmap.md
```

**Manage VM:**
```bash
# Stop VM (to save costs)
gcloud compute instances stop autonomous-dev-vm --zone=us-central1-a

# Start VM
gcloud compute instances start autonomous-dev-vm --zone=us-central1-a

# Delete VM (when done)
gcloud compute instances delete autonomous-dev-vm --zone=us-central1-a
```

**Manually trigger agents:**
```bash
# SSH into VM first
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a

# Run developer agent manually
cd ~/src
./autonomous-agent.sh

# Run reviewer manually
./autonomous-reviewer.sh

# Send email summary manually
./send-email-summary.sh
```

---

## Cost

**E2-small VM in us-central1:**
- **~$15/month** running 24/7
- **~$7.50/month** if you stop it nights/weekends

**Tips to reduce cost:**
- Stop VM when not needed: `gcloud compute instances stop autonomous-dev-vm --zone=us-central1-a`
- Use preemptible instance (add `--preemptible` to provision script): **~$5/month**
- Set up budget alerts in GCP Console

---

## Troubleshooting

**Not receiving emails?**
```bash
# Check SendGrid key is set
gcloud compute ssh autonomous-dev-vm --zone=us-central1-a
echo $SENDGRID_API_KEY

# Test email manually
cd ~/src
./send-email-summary.sh "Test Email"

# Check email logs
tail ~/logs/email-summary.log
```

**Agents not running?**
```bash
# Verify cron is set up
crontab -l

# Check for errors
grep -i error ~/logs/*.log

# Manually run agent to see errors
cd ~/src
./autonomous-agent.sh
```

**Claude API errors?**
```bash
# Verify API key
echo $ANTHROPIC_API_KEY

# Test Claude CLI
claude --version

# Check rate limits
grep -i "rate limit" ~/logs/*.log
```

---

## Next Steps

1. **Wait for first email summary** (within 4 hours)
2. **Review the roadmap progress** via email or on VM
3. **Check review reports** for code quality issues
4. **Monitor costs** in GCP Console
5. **Adjust scheduling** if needed (edit crontab on VM)

For detailed documentation, see: `GCP-AUTONOMOUS-DEPLOYMENT.md`

---

## Support

**Issues?**
- Check `~/logs/*.log` on the VM
- Review email summaries for error notifications
- See `GCP-AUTONOMOUS-DEPLOYMENT.md` for detailed troubleshooting

**Want to modify the system?**
- Cron schedule: `crontab -e` on VM
- Email frequency: Edit crontab
- Agent behavior: Edit `.claude/agents/*.md` prompts
- VM size: Stop VM, resize with `gcloud compute instances set-machine-type`
