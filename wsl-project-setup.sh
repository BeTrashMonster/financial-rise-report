#!/bin/bash
# Financial RISE Project - WSL Environment Setup
# Run this inside WSL after initial installation

set -e

echo "=================================================="
echo "Financial RISE Project - WSL Setup"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Step 1: Updating Ubuntu packages...${NC}"
sudo apt update && sudo apt upgrade -y

echo ""
echo -e "${CYAN}Step 2: Installing Node.js 20 LTS...${NC}"
# Install Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Verify installation
echo ""
echo -e "${GREEN}Node.js version:${NC} $(node --version)"
echo -e "${GREEN}npm version:${NC} $(npm --version)"

echo ""
echo -e "${CYAN}Step 3: Installing development tools...${NC}"
sudo apt install -y git build-essential

echo ""
echo -e "${CYAN}Step 4: Setting up project directory...${NC}"
# Navigate to Windows project directory via WSL mount
PROJECT_PATH="/mnt/c/Users/Admin/src/financial-rise-frontend"

if [ ! -d "$PROJECT_PATH" ]; then
    echo -e "${YELLOW}Warning: Project directory not found at $PROJECT_PATH${NC}"
    echo "Please ensure your project is at C:\\Users\\Admin\\src\\financial-rise-frontend"
    exit 1
fi

cd "$PROJECT_PATH"
echo -e "${GREEN}Current directory: $(pwd)${NC}"

echo ""
echo -e "${CYAN}Step 5: Installing project dependencies...${NC}"
npm install

echo ""
echo -e "${CYAN}Step 6: Running tests...${NC}"
npm test

echo ""
echo "=================================================="
echo -e "${GREEN}Setup Complete!${NC}"
echo "=================================================="
echo ""
echo -e "${YELLOW}To run tests in the future:${NC}"
echo "1. Open WSL terminal (type 'wsl' in PowerShell or search for 'Ubuntu')"
echo "2. cd /mnt/c/Users/Admin/src/financial-rise-frontend"
echo "3. npm test"
echo ""
echo -e "${YELLOW}Helpful commands:${NC}"
echo "  npm test              - Run all tests"
echo "  npm run test:coverage - Run tests with coverage"
echo "  npm run test:watch    - Run tests in watch mode"
echo "  npm run dev           - Start dev server"
echo ""
echo -e "${CYAN}Create an alias for quick access:${NC}"
echo "echo \"alias fr='cd /mnt/c/Users/Admin/src/financial-rise-frontend'\" >> ~/.bashrc"
echo "source ~/.bashrc"
echo "Then just type 'fr' to jump to your project!"
echo ""
