#!/bin/bash
# Quick test script to verify WSL environment is working

echo "=================================================="
echo "WSL Environment Test"
echo "=================================================="
echo ""

# Check if in WSL
if grep -qi microsoft /proc/version; then
    echo "✓ Running in WSL"
else
    echo "✗ NOT running in WSL! This script must be run inside WSL."
    exit 1
fi

echo ""
echo "System Information:"
echo "  OS: $(uname -s)"
echo "  Kernel: $(uname -r)"
echo "  Architecture: $(uname -m)"
echo ""

# Check Node.js
if command -v node &> /dev/null; then
    echo "✓ Node.js installed: $(node --version)"
else
    echo "✗ Node.js not found"
    exit 1
fi

# Check npm
if command -v npm &> /dev/null; then
    echo "✓ npm installed: $(npm --version)"
else
    echo "✗ npm not found"
    exit 1
fi

# Check if in project directory
if [ -f "package.json" ]; then
    echo "✓ package.json found"
    echo "  Project: $(node -p "require('./package.json').name")"
else
    echo "✗ package.json not found - are you in the project directory?"
    exit 1
fi

# Check if node_modules exists
if [ -d "node_modules" ]; then
    echo "✓ node_modules installed"
else
    echo "⚠ node_modules not found - run 'npm install' first"
fi

echo ""
echo "=================================================="
echo "Environment ready! Run 'npm test' to test."
echo "=================================================="
