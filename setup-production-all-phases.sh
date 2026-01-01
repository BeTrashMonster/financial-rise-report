#!/bin/bash
# Production Infrastructure Setup - ALL PHASES
# Master script to execute all phases in recommended order
# Estimated Total Time: 2-3 hours

set -e

echo "========================================="
echo "PRODUCTION INFRASTRUCTURE SETUP"
echo "Financial RISE - Full Production Deployment"
echo "========================================="
echo ""
echo "This script will execute all 7 phases:"
echo "  Phase 1: Cloud SQL with Private IP       [15-20 min]"
echo "  Phase 2: Standard Production VM          [10 min]"
echo "  Phase 4: Production Secret Manager       [15 min]"
echo "  Phase 5: Monitoring & Alerting           [30 min]"
echo "  Phase 6: Database Backup Strategy        [20 min]"
echo "  Phase 7: GitHub Secrets Configuration    [10 min]"
echo "  Phase 3: SSL/HTTPS (Optional)            [30 min]"
echo ""
echo "Total Estimated Time: 2-3 hours"
echo "Estimated Monthly Cost: ~$146"
echo ""
echo "========================================="
echo ""

# Confirmation
read -p "Continue with full production setup? (yes/no): " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
  echo "Setup cancelled"
  exit 0
fi

echo ""
echo "Starting production infrastructure setup..."
echo ""

# Track start time
START_TIME=$(date +%s)

# Create log directory
mkdir -p /tmp/production-setup-logs
LOG_DIR="/tmp/production-setup-logs"
MASTER_LOG="$LOG_DIR/master-$(date +%Y%m%d-%H%M%S).log"

echo "Logs will be saved to: $LOG_DIR"
echo "Master log: $MASTER_LOG"
echo ""

# Function to run phase and log
run_phase() {
  PHASE_NUM=$1
  PHASE_SCRIPT=$2
  PHASE_NAME=$3

  echo "========================================="
  echo "STARTING PHASE $PHASE_NUM: $PHASE_NAME"
  echo "========================================="
  echo ""

  PHASE_LOG="$LOG_DIR/phase$PHASE_NUM-$(date +%Y%m%d-%H%M%S).log"

  if bash "$PHASE_SCRIPT" 2>&1 | tee "$PHASE_LOG"; then
    echo ""
    echo "✅ PHASE $PHASE_NUM COMPLETE: $PHASE_NAME"
    echo "   Log: $PHASE_LOG"
    echo ""
    return 0
  else
    echo ""
    echo "❌ PHASE $PHASE_NUM FAILED: $PHASE_NAME"
    echo "   Check log: $PHASE_LOG"
    echo ""
    return 1
  fi
}

# Execute phases in recommended order

# Phase 1: Cloud SQL with Private IP
if ! run_phase 1 "./setup-production-phase1-cloudsql.sh" "Cloud SQL with Private IP"; then
  echo "❌ Setup failed at Phase 1. Aborting."
  exit 1
fi

# Phase 2: Standard Production VM
if ! run_phase 2 "./setup-production-phase2-vm.sh" "Standard Production VM"; then
  echo "❌ Setup failed at Phase 2. Aborting."
  exit 1
fi

# Phase 4: Production Secret Manager
if ! run_phase 4 "./setup-production-phase4-secrets.sh" "Production Secret Manager"; then
  echo "❌ Setup failed at Phase 4. Aborting."
  exit 1
fi

# Phase 5: Monitoring & Alerting
if ! run_phase 5 "./setup-production-phase5-monitoring.sh" "Monitoring & Alerting"; then
  echo "❌ Setup failed at Phase 5. Aborting."
  exit 1
fi

# Phase 6: Database Backup Strategy
if ! run_phase 6 "./setup-production-phase6-backups.sh" "Database Backup Strategy"; then
  echo "❌ Setup failed at Phase 6. Aborting."
  exit 1
fi

# Phase 7: GitHub Secrets Configuration
if ! run_phase 7 "./setup-production-phase7-github.sh" "GitHub Secrets Configuration"; then
  echo "❌ Setup failed at Phase 7. Aborting."
  exit 1
fi

# Phase 3: SSL/HTTPS (Optional)
echo ""
echo "========================================="
echo "OPTIONAL: SSL/HTTPS SETUP"
echo "========================================="
echo ""
echo "Phase 3 (SSL/HTTPS) requires a domain name."
echo "If you have a domain name ready, you can run this now."
echo "Otherwise, you can skip and run it later when ready."
echo ""
read -p "Do you want to set up SSL/HTTPS now? (yes/no): " SSL_CONFIRM

if [ "$SSL_CONFIRM" = "yes" ]; then
  if run_phase 3 "./setup-production-phase3-ssl.sh" "SSL/HTTPS Certificates"; then
    echo "✅ SSL/HTTPS setup complete"
  else
    echo "⚠️  SSL/HTTPS setup failed (non-critical - can retry later)"
  fi
else
  echo "⏭️  Skipping SSL/HTTPS setup"
  echo "   Run ./setup-production-phase3-ssl.sh later when ready"
fi

# Calculate total time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

# Summary
echo ""
echo "========================================="
echo "PRODUCTION INFRASTRUCTURE SETUP COMPLETE!"
echo "========================================="
echo ""
echo "Time Taken: ${MINUTES}m ${SECONDS}s"
echo ""
echo "Completed Phases:"
echo "  ✅ Phase 1: Cloud SQL with Private IP"
echo "  ✅ Phase 2: Standard Production VM"
echo "  ✅ Phase 4: Production Secret Manager"
echo "  ✅ Phase 5: Monitoring & Alerting"
echo "  ✅ Phase 6: Database Backup Strategy"
echo "  ✅ Phase 7: GitHub Secrets Configuration"
if [ "$SSL_CONFIRM" = "yes" ]; then
  echo "  ✅ Phase 3: SSL/HTTPS Certificates"
else
  echo "  ⏭️  Phase 3: SSL/HTTPS (Skipped - run later)"
fi
echo ""
echo "All logs saved to: $LOG_DIR"
echo "Master log: $MASTER_LOG"
echo ""

# Load saved values
PROD_DB_HOST=$(cat /tmp/prod-db-host.txt 2>/dev/null || echo "N/A")
PROD_VM_IP=$(cat /tmp/prod-vm-ip.txt 2>/dev/null || echo "N/A")

echo "Production Infrastructure Details:"
echo "  - Cloud SQL Private IP: $PROD_DB_HOST"
echo "  - VM Public IP: $PROD_VM_IP"
echo "  - Database: financial_rise_production"
echo "  - VM: financial-rise-production-vm"
echo "  - Secret Manager: financial-rise-production-env"
echo ""

echo "========================================="
echo "NEXT STEPS - MANUAL CONFIGURATION"
echo "========================================="
echo ""
echo "1. Configure GitHub Secrets (see /tmp/github-secrets.txt):"
echo "   - Go to GitHub repository → Settings → Secrets"
echo "   - Add all 5 secrets listed in the file"
echo ""
echo "2. Create GitHub Production Environment:"
echo "   - Settings → Environments → New: 'production'"
echo "   - Add required reviewers for deployment approval"
echo ""
echo "3. Deploy to Production:"
echo "   - Push code: git push origin main"
echo "   - Approve deployment in GitHub Actions"
echo "   - Monitor: https://github.com/YOUR_REPO/actions"
echo ""
echo "4. Verify Production Deployment:"
echo "   - Health check: curl http://$PROD_VM_IP/api/v1/health"
echo "   - Frontend: http://$PROD_VM_IP/"
echo "   - Monitoring: https://console.cloud.google.com/monitoring"
echo ""

if [ "$SSL_CONFIRM" != "yes" ]; then
  echo "5. Set up SSL/HTTPS when domain is ready:"
  echo "   ./setup-production-phase3-ssl.sh"
  echo ""
fi

echo "========================================="
echo "PRODUCTION READY! 🚀"
echo "========================================="
echo ""
