#!/bin/bash

###################################################################################
# PII Detection in Logs Script
#
# Purpose: Scans application logs for potential PII leakage
# Security: HIGH-008 - PII Masking in Logs
# Work Stream: 61
#
# Usage:
#   ./scripts/detect-pii-in-logs.sh [log-file-path]
#   ./scripts/detect-pii-in-logs.sh /var/log/app.log
#
# Exit Codes:
#   0 - No PII detected (PASS)
#   1 - PII detected (FAIL)
#   2 - Script error
###################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# PII detection patterns
EMAIL_PATTERN='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}'
SSN_PATTERN='[0-9]{3}-[0-9]{2}-[0-9]{4}'
PHONE_PATTERN='\(([0-9]{3})\)[-. ]?([0-9]{3})[-. ]?([0-9]{4})'
CREDIT_CARD_PATTERN='[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}'
IPV4_PATTERN='[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
JWT_PATTERN='eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'

# Log file to scan
LOG_FILE="${1:-/var/log/application.log}"

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file not found: $LOG_FILE${NC}"
    exit 2
fi

echo "================================================================"
echo " PII Detection Scan - Financial RISE Application"
echo "================================================================"
echo "Log File: $LOG_FILE"
echo "Scan Started: $(date)"
echo "================================================================"
echo ""

PII_FOUND=0

# Function to scan for pattern
scan_pattern() {
    local pattern=$1
    local pii_type=$2
    local exclude_pattern=$3

    echo -n "Scanning for $pii_type... "

    # Scan for pattern, excluding known safe patterns
    local matches
    if [ -n "$exclude_pattern" ]; then
        matches=$(grep -E "$pattern" "$LOG_FILE" | grep -v -E "$exclude_pattern" || true)
    else
        matches=$(grep -E "$pattern" "$LOG_FILE" || true)
    fi

    local count=$(echo "$matches" | grep -v '^$' | wc -l)

    if [ "$count" -gt 0 ]; then
        echo -e "${RED}FAIL - $count instances found${NC}"
        PII_FOUND=1

        # Show first 5 matches
        echo "  Sample violations (first 5):"
        echo "$matches" | head -5 | sed 's/^/    /'
        echo ""
    else
        echo -e "${GREEN}PASS${NC}"
    fi
}

# 1. Scan for Email Addresses (excluding sanitized emails)
scan_pattern "$EMAIL_PATTERN" "Email Addresses" '\*\*\*@'

# 2. Scan for SSN
scan_pattern "$SSN_PATTERN" "Social Security Numbers" '\[REDACTED - SSN\]'

# 3. Scan for Phone Numbers (excluding sanitized phones)
scan_pattern "$PHONE_PATTERN" "Phone Numbers" '\*\*\*-\*\*\*-'

# 4. Scan for Credit Cards (excluding sanitized cards)
scan_pattern "$CREDIT_CARD_PATTERN" "Credit Card Numbers" '\*\*\*\*-\*\*\*\*-\*\*\*\*-'

# 5. Scan for IPv4 Addresses (excluding sanitized IPs and common safe IPs)
# Exclude: sanitized (192.*.*.*), localhost (127.0.0.1), safe ranges
scan_pattern "$IPV4_PATTERN" "IPv4 Addresses" '(127\.0\.0\.1|0\.0\.0\.0|\*\.\*\.\*)'

# 6. Scan for JWT Tokens
scan_pattern "$JWT_PATTERN" "JWT Tokens" '\[REDACTED - TOKEN\]'

# 7. Scan for common password keywords
echo -n "Scanning for Password Leaks... "
PASSWORD_MATCHES=$(grep -iE '(password|passwd|pwd).*[:=]\s*[^[\[]' "$LOG_FILE" | grep -v '\[REDACTED - PASSWORD\]' || true)
PASSWORD_COUNT=$(echo "$PASSWORD_MATCHES" | grep -v '^$' | wc -l)

if [ "$PASSWORD_COUNT" -gt 0 ]; then
    echo -e "${RED}FAIL - $PASSWORD_COUNT instances found${NC}"
    PII_FOUND=1
    echo "  Sample violations (first 5):"
    echo "$PASSWORD_MATCHES" | head -5 | sed 's/^/    /'
    echo ""
else
    echo -e "${GREEN}PASS${NC}"
fi

# 8. Scan for DISC scores in production logs
if [ "${NODE_ENV:-production}" = "production" ]; then
    echo -n "Scanning for DISC Scores (Production)... "
    DISC_MATCHES=$(grep -E '(d_score|i_score|s_score|c_score).*[0-9]+' "$LOG_FILE" | grep -v '\[REDACTED - PII\]' || true)
    DISC_COUNT=$(echo "$DISC_MATCHES" | grep -v '^$' | wc -l)

    if [ "$DISC_COUNT" -gt 0 ]; then
        echo -e "${RED}FAIL - $DISC_COUNT instances found${NC}"
        PII_FOUND=1
        echo "  Sample violations (first 5):"
        echo "$DISC_MATCHES" | head -5 | sed 's/^/    /'
        echo ""
    else
        echo -e "${GREEN}PASS${NC}"
    fi
fi

# 9. Scan for financial data
echo -n "Scanning for Financial Data... "
FINANCIAL_MATCHES=$(grep -iE '(revenue|salary|income|expense).*\$[0-9,]+' "$LOG_FILE" | grep -v '\[REDACTED - FINANCIAL\]' || true)
FINANCIAL_COUNT=$(echo "$FINANCIAL_MATCHES" | grep -v '^$' | wc -l)

if [ "$FINANCIAL_COUNT" -gt 0 ]; then
    echo -e "${RED}FAIL - $FINANCIAL_COUNT instances found${NC}"
    PII_FOUND=1
    echo "  Sample violations (first 5):"
    echo "$FINANCIAL_MATCHES" | head -5 | sed 's/^/    /'
    echo ""
else
    echo -e "${GREEN}PASS${NC}"
fi

echo ""
echo "================================================================"
echo " Scan Summary"
echo "================================================================"
echo "Log File: $LOG_FILE"
echo "Total Lines Scanned: $(wc -l < "$LOG_FILE")"
echo "Scan Completed: $(date)"
echo ""

if [ "$PII_FOUND" -eq 0 ]; then
    echo -e "${GREEN}✓ PASS - No PII leakage detected${NC}"
    echo ""
    echo "All sensitive data appears to be properly sanitized."
    exit 0
else
    echo -e "${RED}✗ FAIL - PII leakage detected${NC}"
    echo ""
    echo "ACTION REQUIRED:"
    echo "1. Review the violations listed above"
    echo "2. Identify the source of PII leakage"
    echo "3. Update code to use PIISafeLogger or LogSanitizer"
    echo "4. Re-run this script to verify fixes"
    echo ""
    echo "Refer to: docs/PII-LOGGING-POLICY.md for remediation guidance"
    exit 1
fi
