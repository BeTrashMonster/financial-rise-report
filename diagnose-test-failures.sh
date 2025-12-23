#!/bin/bash
# Diagnose test failures with detailed output
# Run in WSL

set +e  # Don't exit on error

echo "=================================================="
echo "Test Failure Diagnosis"
echo "=================================================="
echo ""

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

cd /mnt/c/Users/Admin/src/financial-rise-frontend

echo "Node version: $(node --version)"
echo "npm version: $(npm --version)"
echo ""

echo "Running tests with detailed output..."
echo ""

# Run tests and capture output
npm test -- --reporter=verbose 2>&1 | tee /mnt/c/Users/Admin/src/test-diagnosis.txt

echo ""
echo "=================================================="
echo "Test output saved to: /mnt/c/Users/Admin/src/test-diagnosis.txt"
echo "=================================================="
echo ""

# Show summary of failures
echo "Analyzing failures..."
grep -E "FAIL|Error|×|expected|received" /mnt/c/Users/Admin/src/test-diagnosis.txt | head -100

echo ""
echo "Full details saved in test-diagnosis.txt"
