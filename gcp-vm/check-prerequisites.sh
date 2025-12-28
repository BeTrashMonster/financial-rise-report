#!/bin/bash
# check-prerequisites.sh - Verify prerequisites for GCP deployment

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     CHECKING PREREQUISITES FOR GCP DEPLOYMENT              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

ERRORS=0
WARNINGS=0

# Check gcloud CLI
echo "🔍 Checking gcloud CLI..."
if command -v gcloud &> /dev/null; then
    GCLOUD_VERSION=$(gcloud version --format="value(version)")
    echo "   ✅ gcloud CLI installed (version: $GCLOUD_VERSION)"
else
    echo "   ❌ gcloud CLI not found"
    echo "      Install: https://cloud.google.com/sdk/docs/install"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check authentication
echo "🔍 Checking gcloud authentication..."
if gcloud auth list --filter=status:ACTIVE --format="value(account)" &> /dev/null; then
    ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
    echo "   ✅ Authenticated as: $ACTIVE_ACCOUNT"
else
    echo "   ❌ Not authenticated"
    echo "      Run: gcloud auth login"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check active project
echo "🔍 Checking active GCP project..."
ACTIVE_PROJECT=$(gcloud config get-value project 2>/dev/null)
if [ -n "$ACTIVE_PROJECT" ]; then
    echo "   ✅ Active project: $ACTIVE_PROJECT"
else
    echo "   ❌ No active project set"
    echo "      Run: gcloud config set project YOUR_PROJECT_ID"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# Check required APIs
if [ -n "$ACTIVE_PROJECT" ]; then
    echo "🔍 Checking required GCP APIs..."

    # Compute Engine API
    if gcloud services list --enabled --filter="name:compute.googleapis.com" --format="value(name)" 2>/dev/null | grep -q compute; then
        echo "   ✅ Compute Engine API enabled"
    else
        echo "   ❌ Compute Engine API not enabled"
        echo "      Run: gcloud services enable compute.googleapis.com"
        ERRORS=$((ERRORS + 1))
    fi

    # Secret Manager API
    if gcloud services list --enabled --filter="name:secretmanager.googleapis.com" --format="value(name)" 2>/dev/null | grep -q secretmanager; then
        echo "   ✅ Secret Manager API enabled"
    else
        echo "   ❌ Secret Manager API not enabled"
        echo "      Run: gcloud services enable secretmanager.googleapis.com"
        ERRORS=$((ERRORS + 1))
    fi
    echo ""
fi

# Check secrets
if [ -n "$ACTIVE_PROJECT" ]; then
    echo "🔍 Checking required secrets..."

    # Anthropic API key
    if gcloud secrets describe anthropic-api-key &>/dev/null; then
        echo "   ✅ anthropic-api-key secret exists"
    else
        echo "   ❌ anthropic-api-key secret not found"
        echo "      Create: echo -n 'YOUR_KEY' | gcloud secrets create anthropic-api-key --data-file=-"
        ERRORS=$((ERRORS + 1))
    fi

    # SendGrid API key (optional)
    if gcloud secrets describe sendgrid-api-key &>/dev/null; then
        echo "   ✅ sendgrid-api-key secret exists"
    else
        echo "   ⚠️  sendgrid-api-key secret not found (optional - email notifications will not work)"
        echo "      Create: echo -n 'YOUR_KEY' | gcloud secrets create sendgrid-api-key --data-file=-"
        WARNINGS=$((WARNINGS + 1))
    fi
    echo ""
fi

# Check environment variables
echo "🔍 Checking environment variables..."

if [ -n "$GCP_PROJECT_ID" ]; then
    echo "   ✅ GCP_PROJECT_ID set: $GCP_PROJECT_ID"
else
    echo "   ⚠️  GCP_PROJECT_ID not set (will use active project)"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -n "$EMAIL_TO" ]; then
    echo "   ✅ EMAIL_TO set: $EMAIL_TO"
else
    echo "   ❌ EMAIL_TO not set"
    echo "      Set: export EMAIL_TO=your-email@example.com"
    ERRORS=$((ERRORS + 1))
fi

if [ -n "$REPO_URL" ]; then
    echo "   ✅ REPO_URL set: $REPO_URL"
else
    echo "   ⚠️  REPO_URL not set (must provide during provisioning)"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -n "$REPO_BRANCH" ]; then
    echo "   ✅ REPO_BRANCH set: $REPO_BRANCH"
else
    echo "   ⚠️  REPO_BRANCH not set (will default to 'main')"
    WARNINGS=$((WARNINGS + 1))
fi

if [ -n "$EMAIL_FROM" ]; then
    echo "   ✅ EMAIL_FROM set: $EMAIL_FROM"
else
    echo "   ⚠️  EMAIL_FROM not set (will use default)"
    WARNINGS=$((WARNINGS + 1))
fi
echo ""

# Check billing
if [ -n "$ACTIVE_PROJECT" ]; then
    echo "🔍 Checking billing..."
    if gcloud beta billing projects describe "$ACTIVE_PROJECT" --format="value(billingEnabled)" 2>/dev/null | grep -q True; then
        echo "   ✅ Billing enabled for project"
    else
        echo "   ❌ Billing not enabled for project"
        echo "      Enable at: https://console.cloud.google.com/billing"
        ERRORS=$((ERRORS + 1))
    fi
    echo ""
fi

# Summary
echo "════════════════════════════════════════════════════════════"
echo "SUMMARY"
echo "════════════════════════════════════════════════════════════"
echo ""

if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo "✅ All prerequisites met!"
    echo ""
    echo "Ready to deploy. Run:"
    echo "  ./provision-autonomous-vm.sh"
    echo ""
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo "⚠️  $WARNINGS warnings (deployment possible but recommended to fix)"
    echo ""
    echo "You can proceed with deployment:"
    echo "  ./provision-autonomous-vm.sh"
    echo ""
    exit 0
else
    echo "❌ $ERRORS errors, $WARNINGS warnings"
    echo ""
    echo "Fix the errors above before deploying."
    echo ""
    exit 1
fi
