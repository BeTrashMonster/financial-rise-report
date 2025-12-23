#!/bin/bash
# Proper test fix - restore from git first, then make Windows-side edits
# Run this in WSL

set -e

echo "=================================================="
echo "Proper Test Fix - Clean Restore"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

cd /mnt/c/Users/Admin/src

echo -e "${CYAN}Step 1: Restoring ALL test files from git...${NC}"
cd financial-rise-frontend

# Restore everything to clean state
git checkout src/services/__tests__/api.test.ts
git checkout src/pages/__tests__/CreateAssessment.test.tsx
git checkout src/pages/__tests__/Questionnaire.test.tsx
git checkout vitest.config.ts

echo -e "${GREEN}✓ All files restored to original state${NC}"

cd /mnt/c/Users/Admin/src

echo ""
echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Files are now clean. Please run:${NC}"
echo -e "${YELLOW}========================================${NC}"
echo ""
echo -e "${CYAN}In Windows (Claude Code):${NC}"
echo "  1. I will now apply precise fixes using the Edit tool"
echo "  2. Then you can run: npm test"
echo ""
echo -e "${GREEN}✓ Ready for Windows-side edits${NC}"
echo ""
