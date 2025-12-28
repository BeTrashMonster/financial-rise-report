#!/bin/bash
# provision-autonomous-vm.sh - Provision Google Cloud VM for autonomous development
#
# This script creates an E2-small VM instance configured to run:
# - Autonomous developer (every 30 minutes)
# - Autonomous reviewer (every hour)
# - Email summary agent (every 4 hours)

set -e

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-}"
ZONE="${GCP_ZONE:-us-central1-a}"
VM_NAME="${VM_NAME:-autonomous-dev-vm}"
MACHINE_TYPE="e2-small"
BOOT_DISK_SIZE="30GB"
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
SERVICE_ACCOUNT="${GCP_SERVICE_ACCOUNT:-}"

# Repository configuration
REPO_URL="${REPO_URL:-https://github.com/yourusername/financial-rise.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"

# Email configuration (will be set via metadata)
EMAIL_TO="${EMAIL_TO:-}"
EMAIL_FROM="${EMAIL_FROM:-}"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     PROVISIONING AUTONOMOUS DEVELOPMENT VM ON GCP          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Validation
if [ -z "$PROJECT_ID" ]; then
    echo "❌ Error: GCP_PROJECT_ID not set"
    echo ""
    echo "Please set your GCP project ID:"
    echo "  export GCP_PROJECT_ID=your-project-id"
    exit 1
fi

if [ -z "$EMAIL_TO" ]; then
    echo "⚠️  Warning: EMAIL_TO not set. Email notifications will not work."
    echo "   Set with: export EMAIL_TO=your-email@example.com"
fi

# Confirm configuration
echo "📋 Configuration:"
echo "  Project ID:       $PROJECT_ID"
echo "  Zone:             $ZONE"
echo "  VM Name:          $VM_NAME"
echo "  Machine Type:     $MACHINE_TYPE"
echo "  Boot Disk:        $BOOT_DISK_SIZE"
echo "  Repository:       $REPO_URL"
echo "  Branch:           $REPO_BRANCH"
echo "  Email To:         ${EMAIL_TO:-Not configured}"
echo "  Email From:       ${EMAIL_FROM:-Not configured}"
echo ""

read -p "Continue with VM provisioning? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Cancelled"
    exit 1
fi

# Set active project
echo ""
echo "🔧 Setting active GCP project..."
gcloud config set project "$PROJECT_ID"

# Check if VM already exists
if gcloud compute instances describe "$VM_NAME" --zone="$ZONE" &>/dev/null; then
    echo ""
    echo "⚠️  VM '$VM_NAME' already exists in zone $ZONE"
    read -p "Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🗑️  Deleting existing VM..."
        gcloud compute instances delete "$VM_NAME" --zone="$ZONE" --quiet
    else
        echo "❌ Cancelled"
        exit 1
    fi
fi

# Build metadata with secrets
METADATA="repo-url=$REPO_URL,repo-branch=$REPO_BRANCH"
if [ -n "$EMAIL_TO" ]; then
    METADATA="$METADATA,email-to=$EMAIL_TO"
fi
if [ -n "$EMAIL_FROM" ]; then
    METADATA="$METADATA,email-from=$EMAIL_FROM"
fi

# Create the VM
echo ""
echo "🚀 Creating VM instance '$VM_NAME'..."
echo ""

STARTUP_SCRIPT_PATH="$(dirname "$0")/vm-startup-script.sh"

gcloud compute instances create "$VM_NAME" \
    --zone="$ZONE" \
    --machine-type="$MACHINE_TYPE" \
    --boot-disk-size="$BOOT_DISK_SIZE" \
    --boot-disk-type=pd-standard \
    --image-family="$IMAGE_FAMILY" \
    --image-project="$IMAGE_PROJECT" \
    --metadata-from-file=startup-script="$STARTUP_SCRIPT_PATH" \
    --metadata="$METADATA" \
    --scopes=cloud-platform \
    --tags=autonomous-dev \
    $([ -n "$SERVICE_ACCOUNT" ] && echo "--service-account=$SERVICE_ACCOUNT")

echo ""
echo "✅ VM created successfully!"
echo ""

# Get instance details
EXTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
INTERNAL_IP=$(gcloud compute instances describe "$VM_NAME" --zone="$ZONE" --format='get(networkInterfaces[0].networkIP)')

echo "╔════════════════════════════════════════════════════════════╗"
echo "║              VM PROVISIONING COMPLETE                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Instance Details:"
echo "  Name:           $VM_NAME"
echo "  Zone:           $ZONE"
echo "  External IP:    $EXTERNAL_IP"
echo "  Internal IP:    $INTERNAL_IP"
echo "  Machine Type:   $MACHINE_TYPE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔍 Monitor startup progress:"
echo "  gcloud compute instances get-serial-port-output $VM_NAME --zone=$ZONE"
echo ""
echo "🔐 SSH into the VM:"
echo "  gcloud compute ssh $VM_NAME --zone=$ZONE"
echo ""
echo "📊 View logs:"
echo "  gcloud compute ssh $VM_NAME --zone=$ZONE --command='tail -f /var/log/autonomous-dev-setup.log'"
echo ""
echo "🛑 Stop the VM:"
echo "  gcloud compute instances stop $VM_NAME --zone=$ZONE"
echo ""
echo "🗑️  Delete the VM:"
echo "  gcloud compute instances delete $VM_NAME --zone=$ZONE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "⏱️  The VM is now bootstrapping (takes ~10 minutes):"
echo "   1. Installing system dependencies"
echo "   2. Installing Node.js and Git"
echo "   3. Installing Claude Code CLI"
echo "   4. Cloning repository"
echo "   5. Setting up cron jobs"
echo "   6. Starting autonomous agents"
echo ""
echo "📧 You will receive email updates every 4 hours at: ${EMAIL_TO:-[not configured]}"
echo ""
