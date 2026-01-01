#!/bin/bash
# Production Infrastructure Setup - Phase 3: SSL/HTTPS Certificates
# Estimated Time: 30 minutes
# Prerequisites: Phase 2 complete (VM running), Domain name configured

set -e

PROJECT_ID="financial-rise-prod"
ZONE="us-central1-a"
VM_NAME="financial-rise-production-vm"

echo "========================================="
echo "PHASE 3: SSL/HTTPS Certificates Setup"
echo "========================================="
echo ""
echo "Project: $PROJECT_ID"
echo "VM: $VM_NAME"
echo ""

# Get VM IP
if [ -f /tmp/prod-vm-ip.txt ]; then
  PROD_IP=$(cat /tmp/prod-vm-ip.txt)
else
  PROD_IP=$(gcloud compute instances describe $VM_NAME \
    --zone=$ZONE \
    --format="value(networkInterfaces[0].accessConfigs[0].natIP)" \
    --project=$PROJECT_ID)
  echo "$PROD_IP" > /tmp/prod-vm-ip.txt
fi

echo "Production IP: $PROD_IP"
echo ""

# Ask about domain
echo "========================================="
echo "DOMAIN CONFIGURATION"
echo "========================================="
echo ""
echo "SSL/HTTPS requires a domain name."
echo ""
echo "Options:"
echo "  1. I have a domain name (e.g., financialrise.com)"
echo "  2. Use self-signed certificate (testing only - browser warning)"
echo "  3. Skip SSL setup for now"
echo ""
read -p "Choose option (1/2/3): " DOMAIN_OPTION

case $DOMAIN_OPTION in
  1)
    echo ""
    read -p "Enter your domain name (e.g., financialrise.com): " DOMAIN_NAME

    if [ -z "$DOMAIN_NAME" ]; then
      echo "❌ Domain name required"
      exit 1
    fi

    echo ""
    echo "⚠️  IMPORTANT: Before continuing, ensure:"
    echo "   1. Domain DNS A record points to: $PROD_IP"
    echo "   2. DNS has propagated (check: nslookup $DOMAIN_NAME)"
    echo ""
    read -p "Is DNS configured and propagated? (yes/no): " DNS_READY

    if [ "$DNS_READY" != "yes" ]; then
      echo "❌ Please configure DNS first, then run this script again"
      echo ""
      echo "DNS Configuration:"
      echo "  Type: A"
      echo "  Name: @ (or $DOMAIN_NAME)"
      echo "  Value: $PROD_IP"
      echo "  TTL: 3600"
      echo ""
      echo "Optional www subdomain:"
      echo "  Type: CNAME"
      echo "  Name: www"
      echo "  Value: $DOMAIN_NAME"
      echo ""
      exit 1
    fi

    USE_LETSENCRYPT=true
    ;;
  2)
    echo "Using self-signed certificate (testing only)"
    DOMAIN_NAME="$PROD_IP"
    USE_LETSENCRYPT=false
    ;;
  3)
    echo "Skipping SSL setup"
    exit 0
    ;;
  *)
    echo "Invalid option"
    exit 1
    ;;
esac

echo ""
echo "SSL Configuration:"
echo "  Domain: $DOMAIN_NAME"
echo "  Type: $([ "$USE_LETSENCRYPT" = true ] && echo "Let's Encrypt" || echo "Self-signed")"
echo ""

# Step 3.1: Install Certbot on Production VM
echo "Step 1/5: Installing Certbot on production VM..."

gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="
    sudo apt-get update -qq
    sudo apt-get install -y -qq certbot python3-certbot-nginx
    certbot --version
  "

echo "✅ Certbot installed"
echo ""

# Step 3.2: Get SSL Certificate
if [ "$USE_LETSENCRYPT" = true ]; then
  # Let's Encrypt Real Certificate
  echo "Step 2/5: Obtaining Let's Encrypt certificate..."
  echo "Domain: $DOMAIN_NAME"
  echo ""

  read -p "Enter email for certificate notifications: " CERT_EMAIL

  if [ -z "$CERT_EMAIL" ]; then
    echo "❌ Email required for Let's Encrypt"
    exit 1
  fi

  gcloud compute ssh $VM_NAME \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --command="
      # Stop nginx if running (certbot needs port 80)
      sudo docker stop financial-rise-frontend-prod 2>/dev/null || true

      # Get certificate
      sudo certbot certonly --standalone \
        -d $DOMAIN_NAME \
        -d www.$DOMAIN_NAME \
        --email $CERT_EMAIL \
        --agree-tos \
        --non-interactive \
        --preferred-challenges http

      echo ''
      echo 'Certificate files:'
      sudo ls -lh /etc/letsencrypt/live/$DOMAIN_NAME/
    "

  CERT_PATH="/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem"
  KEY_PATH="/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem"

  echo "✅ Let's Encrypt certificate obtained"
  echo ""

else
  # Self-Signed Certificate
  echo "Step 2/5: Creating self-signed certificate..."

  gcloud compute ssh $VM_NAME \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --command="
      sudo mkdir -p /etc/ssl/certs /etc/ssl/private

      sudo openssl req -x509 -nodes -days 365 \
        -newkey rsa:2048 \
        -keyout /etc/ssl/private/financial-rise.key \
        -out /etc/ssl/certs/financial-rise.crt \
        -subj \"/C=US/ST=State/L=City/O=Financial RISE/CN=$DOMAIN_NAME\"

      echo ''
      echo 'Certificate files:'
      sudo ls -lh /etc/ssl/certs/financial-rise.crt /etc/ssl/private/financial-rise.key
    "

  CERT_PATH="/etc/ssl/certs/financial-rise.crt"
  KEY_PATH="/etc/ssl/private/financial-rise.key"

  echo "✅ Self-signed certificate created"
  echo "⚠️  Browsers will show security warning (self-signed)"
  echo ""
fi

# Step 3.3: Update Nginx Configuration
echo "Step 3/5: Updating frontend nginx configuration for HTTPS..."

# Read current nginx.conf
NGINX_CONFIG_PATH="financial-rise-app/frontend/nginx.conf"

if [ ! -f "$NGINX_CONFIG_PATH" ]; then
  echo "❌ nginx.conf not found at $NGINX_CONFIG_PATH"
  exit 1
fi

# Backup original
cp "$NGINX_CONFIG_PATH" "${NGINX_CONFIG_PATH}.backup"

# Create new SSL-enabled nginx config
cat > "$NGINX_CONFIG_PATH" << 'NGINX_EOF'
# HTTP server - redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name _;

    # Redirect all HTTP to HTTPS
    return 301 https://$host$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name _;

    # SSL Configuration
    ssl_certificate SSL_CERT_PATH;
    ssl_certificate_key SSL_KEY_PATH;

    # SSL Security Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    root /usr/share/nginx/html;
    index index.html;

    # API proxy to backend
    location /api {
        proxy_pass http://backend:4000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 90;
    }

    # Frontend - React Router
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
NGINX_EOF

# Replace placeholders
sed -i "s|SSL_CERT_PATH|$CERT_PATH|g" "$NGINX_CONFIG_PATH"
sed -i "s|SSL_KEY_PATH|$KEY_PATH|g" "$NGINX_CONFIG_PATH"

echo "✅ Nginx configuration updated"
echo "   Backup saved to: ${NGINX_CONFIG_PATH}.backup"
echo ""

# Step 3.4: Update docker-compose.prod.yml to mount certificates
echo "Step 4/5: Updating docker-compose.prod.yml to mount SSL certificates..."

COMPOSE_FILE="financial-rise-app/docker-compose.prod.yml"

# Check if volumes already exist
if grep -q "letsencrypt:" "$COMPOSE_FILE"; then
  echo "⚠️  Certificate volumes already configured"
else
  # Add volume mounts to frontend service
  # This is complex - create a backup and manual instructions
  cp "$COMPOSE_FILE" "${COMPOSE_FILE}.backup"

  echo ""
  echo "⚠️  MANUAL STEP REQUIRED:"
  echo "   Edit $COMPOSE_FILE"
  echo "   Add under frontend service → volumes:"
  if [ "$USE_LETSENCRYPT" = true ]; then
    echo "     - /etc/letsencrypt:/etc/letsencrypt:ro"
  else
    echo "     - /etc/ssl:/etc/ssl:ro"
  fi
  echo ""
  echo "   Example:"
  echo "   frontend:"
  echo "     volumes:"
  if [ "$USE_LETSENCRYPT" = true ]; then
    echo "       - /etc/letsencrypt:/etc/letsencrypt:ro"
  else
    echo "       - /etc/ssl:/etc/ssl:ro"
  fi
  echo ""
  read -p "Press ENTER after editing docker-compose.prod.yml..."
fi

echo "✅ docker-compose.prod.yml ready"
echo ""

# Step 3.5: Set up auto-renewal (Let's Encrypt only)
if [ "$USE_LETSENCRYPT" = true ]; then
  echo "Step 5/5: Setting up SSL certificate auto-renewal..."

  gcloud compute ssh $VM_NAME \
    --zone=$ZONE \
    --project=$PROJECT_ID \
    --command="
      # Test renewal
      sudo certbot renew --dry-run

      # Remove existing cron job if present
      crontab -l 2>/dev/null | grep -v 'certbot renew' | crontab - || true

      # Add new cron job: Daily at 3 AM, restart nginx if cert renewed
      (crontab -l 2>/dev/null; echo '0 3 * * * sudo certbot renew --quiet --post-hook \"docker restart financial-rise-frontend-prod 2>/dev/null || true\"') | crontab -

      echo 'Cron job scheduled for auto-renewal'
      crontab -l | grep certbot
    "

  echo "✅ Auto-renewal configured (daily check at 3 AM)"
else
  echo "Step 5/5: Skipping auto-renewal (self-signed certificate)"
fi

echo ""

# Verification
echo "========================================="
echo "VERIFICATION"
echo "========================================="
echo ""

echo "Certificate files on VM:"
gcloud compute ssh $VM_NAME \
  --zone=$ZONE \
  --project=$PROJECT_ID \
  --command="
    if [ -f $CERT_PATH ]; then
      echo '✅ Certificate: $CERT_PATH'
      sudo openssl x509 -in $CERT_PATH -noout -subject -dates
    else
      echo '❌ Certificate not found'
    fi

    if [ -f $KEY_PATH ]; then
      echo '✅ Private key: $KEY_PATH'
    else
      echo '❌ Private key not found'
    fi
  "

echo ""

# Summary
echo "========================================="
echo "PHASE 3 COMPLETE ✅"
echo "========================================="
echo ""
echo "Summary:"
if [ "$USE_LETSENCRYPT" = true ]; then
  echo "  ✅ SSL Type: Let's Encrypt"
  echo "  ✅ Domain: $DOMAIN_NAME"
  echo "  ✅ Certificate: $CERT_PATH"
  echo "  ✅ Auto-renewal: Enabled (daily check)"
  echo "  ✅ Certificate validity: 90 days (auto-renewed)"
else
  echo "  ✅ SSL Type: Self-signed"
  echo "  ✅ Certificate: $CERT_PATH"
  echo "  ⚠️  Certificate validity: 365 days (manual renewal)"
  echo "  ⚠️  Browsers will show security warning"
fi
echo "  ✅ Nginx: HTTP → HTTPS redirect enabled"
echo "  ✅ Security headers: Configured"
echo "  ✅ TLS versions: 1.2, 1.3"
echo ""
echo "Configuration files updated:"
echo "  - $NGINX_CONFIG_PATH (backup: ${NGINX_CONFIG_PATH}.backup)"
echo "  - $COMPOSE_FILE (backup: ${COMPOSE_FILE}.backup)"
echo ""
echo "⚠️  IMPORTANT: Rebuild and redeploy frontend container"
echo "   The nginx config changes require container rebuild"
echo ""
echo "Next steps:"
echo "1. Commit nginx config changes:"
echo "   git add $NGINX_CONFIG_PATH"
echo "   git commit -m 'Add HTTPS support with SSL certificates'"
echo ""
echo "2. Push to trigger deployment:"
echo "   git push origin main"
echo ""
echo "3. After deployment, test HTTPS:"
if [ "$USE_LETSENCRYPT" = true ]; then
  echo "   curl https://$DOMAIN_NAME/api/v1/health"
  echo "   Visit: https://$DOMAIN_NAME"
else
  echo "   curl -k https://$PROD_IP/api/v1/health"
  echo "   Visit: https://$PROD_IP (accept security warning)"
fi
echo ""
if [ "$USE_LETSENCRYPT" = true ]; then
  echo "4. Update FRONTEND_URL in Secret Manager:"
  echo "   Change from http:// to https://$DOMAIN_NAME"
  echo "   Run Phase 4 again to update secrets"
fi
echo ""
