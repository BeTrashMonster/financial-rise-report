#!/bin/bash
# Production Infrastructure Setup - Phase 2: Standard Production VM
# Estimated Time: 10 minutes
# Prerequisites: Phase 1 complete (Cloud SQL running)

set -e

PROJECT_ID="financial-rise-prod"
REGION="us-central1"
ZONE="us-central1-a"
VPC_NAME="financial-rise-vpc"
VM_NAME="financial-rise-production-vm"
STATIC_IP_NAME="financial-rise-production-ip"

echo "========================================="
echo "PHASE 2: Standard Production VM Setup"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Zone: $ZONE"
echo "VM: $VM_NAME"
echo ""

# Step 2.1: Reserve Static IP
echo "Step 1/4: Reserving static IP address..."
gcloud compute addresses create $STATIC_IP_NAME \
  --region=$REGION \
  --project=$PROJECT_ID

echo "✅ Static IP reserved"
echo ""

# Step 2.2: Get Reserved IP
echo "Step 2/4: Getting reserved IP address..."
PROD_IP=$(gcloud compute addresses describe $STATIC_IP_NAME \
  --region=$REGION \
  --format="value(address)" \
  --project=$PROJECT_ID)

echo "✅ Production IP: $PROD_IP"
echo ""

# Save for later phases
echo "$PROD_IP" > /tmp/prod-vm-ip.txt
chmod 600 /tmp/prod-vm-ip.txt
echo "IP saved to: /tmp/prod-vm-ip.txt"
echo ""

# Step 2.3: Create Standard Production VM
echo "Step 3/4: Creating production VM (this takes 2-3 minutes)..."
echo "Machine type: e2-standard-2 (2 vCPU, 8GB RAM)"
echo "Disk: 50GB SSD"
echo "Network: $VPC_NAME"
echo ""

gcloud compute instances create $VM_NAME \
  --zone=$ZONE \
  --machine-type=e2-standard-2 \
  --network-interface=network-tier=PREMIUM,address=$PROD_IP,network=$VPC_NAME,subnet=$VPC_NAME \
  --maintenance-policy=MIGRATE \
  --provisioning-model=STANDARD \
  --tags=http-server,https-server,allow-ssh \
  --create-disk=auto-delete=yes,boot=yes,device-name=$VM_NAME,image=projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20241211,mode=rw,size=50,type=pd-balanced \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --project=$PROJECT_ID

echo "✅ VM created successfully"
echo ""

# Step 2.4: Install Docker on Production VM
echo "Step 4/4: Installing Docker and Docker Compose..."
echo "This may take 3-5 minutes..."
echo ""

gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="
    set -e

    echo '=== Updating system packages ==='
    sudo apt-get update -qq

    echo '=== Installing prerequisites ==='
    sudo apt-get install -y -qq ca-certificates curl gnupg

    echo '=== Adding Docker GPG key ==='
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    echo '=== Adding Docker repository ==='
    echo \
      \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      \$(. /etc/os-release && echo \\\"\$VERSION_CODENAME\\\") stable\" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    echo '=== Installing Docker ==='
    sudo apt-get update -qq
    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

    echo '=== Configuring Docker permissions ==='
    sudo usermod -aG docker \$USER
    sudo chmod 666 /var/run/docker.sock

    echo '=== Verifying installation ==='
    docker --version
    docker compose version

    echo '✅ Docker installation complete'
  "

echo "✅ Docker and Docker Compose installed"
echo ""

# Verification
echo "========================================="
echo "VERIFICATION"
echo "========================================="
echo ""

echo "VM Details:"
gcloud compute instances describe $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --format="table(name,status,machineType,networkInterfaces[0].accessConfigs[0].natIP)"

echo ""
echo "Docker Version:"
gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="docker --version && docker compose version"

echo ""

# Summary
echo "========================================="
echo "PHASE 2 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
echo "  ✅ VM Name: $VM_NAME"
echo "  ✅ Machine Type: e2-standard-2 (2 vCPU, 8GB RAM)"
echo "  ✅ Disk: 50GB SSD"
echo "  ✅ Public IP: $PROD_IP"
echo "  ✅ Provisioning: STANDARD (non-preemptible)"
echo "  ✅ Network: $VPC_NAME (Private IP access to Cloud SQL)"
echo "  ✅ Docker: Installed and ready"
echo ""
echo "VM IP saved to: /tmp/prod-vm-ip.txt"
echo ""
echo "⚠️  NOTE: VM can now access Cloud SQL via private IP!"
echo "Cloud SQL is accessible from this VM at the private IP from Phase 1"
echo ""
echo "Next: Run Phase 4 (Production Secret Manager)"
echo "  ./setup-production-phase4-secrets.sh"
echo ""
echo "Or run Phase 3 first if you have a domain name ready for SSL"
echo "  ./setup-production-phase3-ssl.sh"
echo ""
