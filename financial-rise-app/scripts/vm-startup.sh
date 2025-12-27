#!/bin/bash
set -e

echo "=== Financial RISE VM Startup Script ==="
echo "Starting VM initialization..."

# Update system packages
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install Docker
echo "Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
rm get-docker.sh

# Add current user to docker group
usermod -aG docker $(whoami)

# Install Docker Compose V2
echo "Installing Docker Compose V2..."
mkdir -p /usr/local/lib/docker/cli-plugins
curl -SL https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-linux-x86_64 \
  -o /usr/local/lib/docker/cli-plugins/docker-compose
chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

# Verify Docker Compose installation
/usr/local/lib/docker/cli-plugins/docker-compose version

# Install Google Cloud Ops Agent for logging and monitoring
echo "Installing Google Cloud Ops Agent..."
curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
bash add-google-cloud-ops-agent-repo.sh --also-install
rm add-google-cloud-ops-agent-repo.sh

# Create application directory structure
echo "Creating application directories..."
mkdir -p /opt/financial-rise
mkdir -p /opt/financial-rise/scripts
mkdir -p /opt/financial-rise/logs
chown -R $(whoami):$(whoami) /opt/financial-rise

# Enable and start Docker service
echo "Enabling Docker service..."
systemctl enable docker
systemctl start docker

# Install useful utilities
echo "Installing utilities..."
apt-get install -y \
  curl \
  wget \
  vim \
  htop \
  net-tools \
  git \
  unzip

# Configure log rotation for application logs
echo "Configuring log rotation..."
cat > /etc/logrotate.d/financial-rise <<EOF
/opt/financial-rise/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 root root
}
EOF

echo "=== VM Startup Complete ==="
echo "Docker version: $(docker --version)"
echo "Docker Compose version: $(/usr/local/lib/docker/cli-plugins/docker-compose version)"
echo "Application directory: /opt/financial-rise"
echo "Next step: Deploy application via GitHub Actions or manual deployment"
