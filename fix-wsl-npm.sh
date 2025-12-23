#!/bin/bash
# Fix WSL npm installation issues
# Run this inside WSL

set -e

echo "=================================================="
echo "Fixing WSL npm Installation Issues"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Navigate to project
PROJECT_PATH="/mnt/c/Users/Admin/src/financial-rise-frontend"
cd "$PROJECT_PATH"

echo -e "${CYAN}Step 1: Checking current Node.js version...${NC}"
which node
NODE_VERSION=$(node --version)
echo "Current Node.js version: $NODE_VERSION"

# Check if we have old Node.js (v12 or older has the WSL bug in npm)
if [[ "$NODE_VERSION" == v12* ]] || [[ "$NODE_VERSION" == v10* ]] || [[ "$NODE_VERSION" == v8* ]]; then
    echo -e "${YELLOW}Found old Node.js $NODE_VERSION with broken npm${NC}"
    echo -e "${YELLOW}Upgrading to Node.js 20 LTS...${NC}"

    # Remove old nodejs and npm
    sudo apt remove nodejs npm -y 2>/dev/null || true
    sudo apt autoremove -y

    # Install Node.js 20 LTS
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs

    echo ""
    echo -e "${GREEN}Node.js upgraded successfully:${NC}"
    which node
    node --version
    npm --version
else
    # Check if node is from Windows
    NODE_PATH=$(which node)
    if [[ "$NODE_PATH" == *"/mnt/c/"* ]]; then
        echo -e "${RED}ERROR: Node.js is being loaded from Windows, not WSL!${NC}"
        echo "Reinstalling in WSL..."

        sudo apt remove nodejs npm -y 2>/dev/null || true
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt install -y nodejs

        echo ""
        echo -e "${GREEN}Node.js installed in WSL:${NC}"
        which node
        node --version
        npm --version
    else
        echo -e "${GREEN}✓ Node.js is up to date in WSL${NC}"
        npm --version
    fi
fi

echo ""
echo -e "${CYAN}Step 2: Cleaning npm cache and node_modules...${NC}"
rm -rf node_modules package-lock.json
npm cache clean --force

echo ""
echo -e "${CYAN}Step 3: Configuring npm for WSL...${NC}"
# Set npm to ignore optional dependencies that might cause issues
npm config set legacy-peer-deps true
npm config set optional false

echo ""
echo -e "${CYAN}Step 4: Installing dependencies with WSL-friendly settings...${NC}"
# Install with flags that work better in WSL
npm install --no-optional --legacy-peer-deps

echo ""
echo -e "${CYAN}Step 5: Verifying installation...${NC}"
if [ -d "node_modules" ]; then
    echo -e "${GREEN}✓ node_modules directory created${NC}"
else
    echo -e "${RED}✗ node_modules directory not found${NC}"
    exit 1
fi

echo ""
echo -e "${CYAN}Step 6: Running tests...${NC}"
npm test

echo ""
echo "=================================================="
echo -e "${GREEN}Fix Complete!${NC}"
echo "=================================================="
echo ""
echo -e "${YELLOW}If you still have issues, try:${NC}"
echo "1. Close and reopen your WSL terminal"
echo "2. Run: cd /mnt/c/Users/Admin/src/financial-rise-frontend"
echo "3. Run: npm test"
echo ""
