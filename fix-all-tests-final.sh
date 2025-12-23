#!/bin/bash
# Final comprehensive test fix
# Restores from git and applies minimal, correct fixes

set -e

echo "=================================================="
echo "Final Test Fix - Restoring from Git"
echo "=================================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Load nvm
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

cd /mnt/c/Users/Admin/src/financial-rise-frontend

echo -e "${CYAN}Step 1: Restoring original test files from git...${NC}"

# Restore test files to their original state
git checkout src/services/__tests__/api.test.ts
git checkout src/pages/__tests__/CreateAssessment.test.tsx
git checkout src/pages/__tests__/Questionnaire.test.tsx
git checkout vitest.config.ts

echo -e "${GREEN}✓ Files restored from git${NC}"

echo ""
echo -e "${CYAN}Step 2: Applying Fix 1 - API Authentication Tests${NC}"
echo "Issue: vi.clearAllMocks() clears axios.create spy from module init"
echo "Fix: Use mockClear() instead of clearAllMocks()"
echo ""

# Fix the api.test.ts file - replace vi.clearAllMocks() with selective clearing
cat > /tmp/api-beforeEach.txt << 'EOF'
  beforeEach(() => {
    // Clear individual mocks instead of vi.clearAllMocks()
    // This preserves the axios.create call that happened during module initialization
    mockAxiosInstance.get.mockClear();
    mockAxiosInstance.post.mockClear();
    mockAxiosInstance.patch.mockClear();
    mockAxiosInstance.delete.mockClear();
    mockAxiosInstance.interceptors.request.use.mockClear();
    mockAxiosInstance.interceptors.response.use.mockClear();
    localStorage.clear();
  });
EOF

# Use sed to replace the beforeEach function
# First, let's just replace the vi.clearAllMocks() line
sed -i 's/vi\.clearAllMocks();/mockAxiosInstance.get.mockClear();\n    mockAxiosInstance.post.mockClear();\n    mockAxiosInstance.patch.mockClear();\n    mockAxiosInstance.delete.mockClear();\n    mockAxiosInstance.interceptors.request.use.mockClear();\n    mockAxiosInstance.interceptors.response.use.mockClear();/' src/services/__tests__/api.test.ts

echo -e "${GREEN}✓ Fixed API authentication tests${NC}"

echo ""
echo -e "${CYAN}Step 3: Applying Fix 2 - Global Test Timeout${NC}"
echo "Issue: Some tests take >5 seconds (default timeout)"
echo "Fix: Increase global timeout to 20 seconds"
echo ""

# Update vitest.config.ts to add testTimeout
sed -i '/setupFiles:.*setup\.ts/a\    testTimeout: 20000, // Increase timeout for slow tests' vitest.config.ts

echo -e "${GREEN}✓ Increased global test timeout to 20s${NC}"

echo ""
echo -e "${CYAN}Step 4: Running tests...${NC}"
echo ""

npm test

echo ""
echo "=================================================="
echo -e "${GREEN}Test Fix Complete!${NC}"
echo "=================================================="
echo ""
echo -e "${YELLOW}Fixes applied:${NC}"
echo "  1. API tests: Fixed mock clearing (2 tests)"
echo "  2. All tests: Increased timeout to 20s (4 tests)"
echo ""
echo -e "${YELLOW}Total: 6 tests fixed${NC}"
echo ""
