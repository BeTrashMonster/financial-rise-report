#!/bin/bash

# Financial RISE - Complete Test Setup and Execution Script
# This script sets up the test environment and runs all tests based on the specifications

set -e  # Exit on error

echo "=========================================="
echo "Financial RISE - Test Setup & Execution"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# ==========================================
# STEP 1: Environment Setup
# ==========================================

echo -e "${YELLOW}Step 1: Checking environment...${NC}"

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed${NC}"
    echo "Install Node.js 18+ with: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash"
    echo "Then run: nvm install 18 && nvm use 18"
    exit 1
fi

NODE_VERSION=$(node -v)
echo -e "${GREEN}✓ Node.js ${NODE_VERSION} found${NC}"

# Check npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}Error: npm is not installed${NC}"
    exit 1
fi

NPM_VERSION=$(npm -v)
echo -e "${GREEN}✓ npm ${NPM_VERSION} found${NC}"

echo ""

# ==========================================
# STEP 2: Backend Setup
# ==========================================

echo -e "${YELLOW}Step 2: Setting up Backend Tests...${NC}"

cd financial-rise-backend

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing backend dependencies..."
    npm install
fi

# Create test directory structure
echo "Creating test directory structure..."
mkdir -p src/__tests__/{unit,integration}
mkdir -p src/__tests__/unit/{controllers,services,middleware,utils}
mkdir -p src/__tests__/integration/{api,database}

# Create a sample test file template
cat > src/__tests__/unit/sample.test.ts << 'EOF'
/**
 * Sample Test File - Replace with actual tests
 * This demonstrates the test structure for Financial RISE backend
 */

describe('Sample Test Suite', () => {
  it('should pass a basic test', () => {
    expect(true).toBe(true);
  });

  it('should demonstrate async testing', async () => {
    const result = await Promise.resolve('success');
    expect(result).toBe('success');
  });
});
EOF

echo -e "${GREEN}✓ Backend test structure created${NC}"
echo ""

# ==========================================
# STEP 3: Frontend Setup
# ==========================================

echo -e "${YELLOW}Step 3: Setting up Frontend Tests...${NC}"

cd ../financial-rise-frontend

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi

# Create test directory structure
echo "Creating test directory structure..."
mkdir -p src/__tests__/{components,hooks,services,utils,pages}
mkdir -p src/__tests__/components/{Assessment,Questions,Reports,Dashboard,Layout}
mkdir -p src/__tests__/e2e

# Create a sample component test
cat > src/__tests__/components/sample.test.tsx << 'EOF'
/**
 * Sample Component Test - Replace with actual tests
 * This demonstrates the test structure for Financial RISE frontend
 */

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';

// Sample component for testing
const SampleComponent = () => <div>Hello World</div>;

describe('Sample Component Test', () => {
  it('should render successfully', () => {
    render(<SampleComponent />);
    expect(screen.getByText('Hello World')).toBeInTheDocument();
  });
});
EOF

echo -e "${GREEN}✓ Frontend test structure created${NC}"
echo ""

# ==========================================
# STEP 4: Generate Test Files from Specs
# ==========================================

echo -e "${YELLOW}Step 4: Generating test files from specifications...${NC}"

cd "$SCRIPT_DIR"

# Create test generation script
cat > generate-tests.js << 'EOFJS'
#!/usr/bin/env node

/**
 * Test Generator - Creates test files from specifications
 * Based on all 50 work streams defined in the roadmap
 */

const fs = require('fs');
const path = require('path');

// Phase 1: MVP Foundation Tests
const phase1Tests = {
  backend: [
    'auth/authentication.test.ts',
    'auth/authorization.test.ts',
    'assessment/assessment-crud.test.ts',
    'assessment/questionnaire.test.ts',
    'disc/disc-algorithm.test.ts',
    'phase/phase-determination.test.ts',
    'reports/report-generation.test.ts',
    'reports/pdf-export.test.ts',
    'admin/user-management.test.ts',
    'admin/activity-logging.test.ts'
  ],
  frontend: [
    'Auth/Login.test.tsx',
    'Auth/Register.test.tsx',
    'Assessment/AssessmentList.test.tsx',
    'Assessment/CreateAssessment.test.tsx',
    'Questions/Questionnaire.test.tsx',
    'Reports/ClientReport.test.tsx',
    'Reports/ConsultantReport.test.tsx',
    'Dashboard/Dashboard.test.tsx'
  ]
};

// Phase 2: Enhanced Engagement Tests
const phase2Tests = {
  backend: [
    'checklist/checklist-crud.test.ts',
    'checklist/auto-generation.test.ts',
    'scheduler/scheduler-integration.test.ts',
    'dashboard/filtering.test.ts',
    'dashboard/search.test.ts',
    'email/email-delivery.test.ts',
    'branding/branding.test.ts',
    'notes/consultant-notes.test.ts',
    'disc/secondary-traits.test.ts'
  ],
  frontend: [
    'Checklist/ChecklistView.test.tsx',
    'Checklist/ChecklistItem.test.tsx',
    'Scheduler/SchedulerSettings.test.tsx',
    'Dashboard/Filters.test.tsx',
    'Dashboard/Search.test.tsx',
    'Email/EmailComposer.test.tsx',
    'Branding/BrandingSettings.test.tsx'
  ]
};

// Phase 3: Advanced Features Tests
const phase3Tests = {
  backend: [
    'conditional/conditional-questions.test.ts',
    'conditional/rule-engine.test.ts',
    'phase/multi-phase.test.ts',
    'analytics/analytics.test.ts',
    'analytics/csv-export.test.ts',
    'shareable/shareable-links.test.ts',
    'shareable/access-control.test.ts',
    'monitoring/performance-metrics.test.ts',
    'logging/activity-logging.test.ts',
    'logging/log-search.test.ts'
  ],
  frontend: [
    'ConditionalQuestions/RuleBuilder.test.tsx',
    'ConditionalQuestions/QuestionFlow.test.tsx',
    'Analytics/AnalyticsDashboard.test.tsx',
    'Analytics/ExportButton.test.tsx',
    'ShareableLinks/ShareModal.test.tsx',
    'ShareableLinks/PublicViewer.test.tsx',
    'Admin/PerformanceMonitoring.test.tsx',
    'Admin/ActivityLogs.test.tsx'
  ]
};

console.log('📝 Generating test files from specifications...\n');

// Generate backend tests
const backendTestDir = path.join(__dirname, 'financial-rise-backend/src/__tests__');
[...phase1Tests.backend, ...phase2Tests.backend, ...phase3Tests.backend].forEach(testPath => {
  const fullPath = path.join(backendTestDir, 'unit', testPath);
  const dir = path.dirname(fullPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const testName = path.basename(testPath, '.test.ts');
  const testContent = `/**
 * ${testName} Tests
 * Generated from Financial RISE specifications
 *
 * TODO: Implement tests based on specification documents
 * Spec Reference: See docs/ directory for detailed requirements
 */

describe('${testName}', () => {
  describe('Unit Tests', () => {
    it('should be implemented based on specification', () => {
      // TODO: Implement actual tests
      expect(true).toBe(true);
    });
  });

  describe('Integration Tests', () => {
    it('should be implemented based on specification', () => {
      // TODO: Implement actual tests
      expect(true).toBe(true);
    });
  });
});
`;

  fs.writeFileSync(fullPath, testContent);
  console.log(`✓ Created: ${testPath}`);
});

// Generate frontend tests
const frontendTestDir = path.join(__dirname, 'financial-rise-frontend/src/__tests__');
[...phase1Tests.frontend, ...phase2Tests.frontend, ...phase3Tests.frontend].forEach(testPath => {
  const fullPath = path.join(frontendTestDir, 'components', testPath);
  const dir = path.dirname(fullPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const testName = path.basename(testPath, '.test.tsx');
  const testContent = `/**
 * ${testName} Tests
 * Generated from Financial RISE specifications
 *
 * TODO: Implement tests based on specification documents
 * Spec Reference: See docs/ directory for detailed requirements
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

describe('${testName}', () => {
  describe('Rendering', () => {
    it('should render successfully', () => {
      // TODO: Implement based on specification
      expect(true).toBe(true);
    });
  });

  describe('User Interactions', () => {
    it('should handle user interactions', async () => {
      // TODO: Implement based on specification
      expect(true).toBe(true);
    });
  });

  describe('Accessibility', () => {
    it('should be WCAG 2.1 AA compliant', () => {
      // TODO: Test keyboard navigation, screen reader support, ARIA labels
      expect(true).toBe(true);
    });
  });
});
`;

  fs.writeFileSync(fullPath, testContent);
  console.log(`✓ Created: ${testPath}`);
});

console.log('\n✅ Test file generation complete!');
console.log(`   Backend tests: ${phase1Tests.backend.length + phase2Tests.backend.length + phase3Tests.backend.length}`);
console.log(`   Frontend tests: ${phase1Tests.frontend.length + phase2Tests.frontend.length + phase3Tests.frontend.length}`);
console.log('\n⚠️  Note: Tests are placeholder stubs. Implement based on specification documents in docs/ directory.\n');
EOFJS

chmod +x generate-tests.js
node generate-tests.js

echo ""

# ==========================================
# STEP 5: Run Backend Tests
# ==========================================

echo -e "${YELLOW}Step 5: Running Backend Tests...${NC}"

cd financial-rise-backend

echo "Running Jest tests with coverage..."
npm test -- --verbose 2>&1 | tee ../backend-test-results.txt

BACKEND_EXIT_CODE=${PIPESTATUS[0]}

if [ $BACKEND_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Backend tests passed!${NC}"
else
    echo -e "${RED}✗ Backend tests failed with exit code ${BACKEND_EXIT_CODE}${NC}"
fi

echo ""

# ==========================================
# STEP 6: Run Frontend Tests
# ==========================================

echo -e "${YELLOW}Step 6: Running Frontend Tests...${NC}"

cd ../financial-rise-frontend

echo "Running Vitest with coverage..."
npm run test:coverage 2>&1 | tee ../frontend-test-results.txt

FRONTEND_EXIT_CODE=${PIPESTATUS[0]}

if [ $FRONTEND_EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ Frontend tests passed!${NC}"
else
    echo -e "${RED}✗ Frontend tests failed with exit code ${FRONTEND_EXIT_CODE}${NC}"
fi

echo ""

# ==========================================
# STEP 7: Generate Test Summary
# ==========================================

cd "$SCRIPT_DIR"

echo -e "${YELLOW}Step 7: Generating Test Summary...${NC}"

cat > TEST-SUMMARY.md << 'EOFSUMMARY'
# Financial RISE - Test Execution Summary

**Date:** $(date)
**Generated By:** Automated Test Script

## Test Execution Results

### Backend Tests (Jest)

See `backend-test-results.txt` for detailed output.

**Test Framework:** Jest with ts-jest
**Coverage Tool:** Istanbul
**Configuration:** `financial-rise-backend/jest.config.js`

### Frontend Tests (Vitest)

See `frontend-test-results.txt` for detailed output.

**Test Framework:** Vitest with React Testing Library
**Coverage Tool:** V8
**Configuration:** `financial-rise-frontend/vitest.config.ts`

## Test Structure

### Backend Tests
- Unit Tests: `src/__tests__/unit/`
  - Controllers
  - Services
  - Middleware
  - Utils
- Integration Tests: `src/__tests__/integration/`
  - API endpoints
  - Database operations

### Frontend Tests
- Component Tests: `src/__tests__/components/`
- Hook Tests: `src/__tests__/hooks/`
- Service Tests: `src/__tests__/services/`
- E2E Tests: `src/__tests__/e2e/` (Playwright)

## Coverage Requirements

Per specifications:
- **Minimum:** 80% code coverage for business logic
- **Target:** 90%+ coverage for critical paths
- **Critical Components:** 100% coverage required
  - Authentication
  - DISC algorithm
  - Phase determination
  - Report generation

## Next Steps

1. **Implement Test Cases**
   - Review specification documents in `docs/` directory
   - Replace placeholder tests with actual implementations
   - Follow TDD approach for new features

2. **Run Continuous Testing**
   - Backend: `npm test:watch` in financial-rise-backend
   - Frontend: `npm run test:watch` in financial-rise-frontend

3. **Review Coverage Reports**
   - Backend: `financial-rise-backend/coverage/`
   - Frontend: `financial-rise-frontend/coverage/`
   - Open `coverage/lcov-report/index.html` in browser

4. **Run E2E Tests**
   - `npm run test:e2e` in financial-rise-frontend
   - Requires all backend services running

## Specification References

All test requirements are documented in:
- Phase 1: MVP tests (Work Streams 1-25)
- Phase 2: Enhancement tests (Work Streams 26-40)
- Phase 3: Advanced feature tests (Work Streams 41-50)

See `plans/roadmap.md` for complete work stream details.
EOFSUMMARY

echo -e "${GREEN}✓ Test summary generated: TEST-SUMMARY.md${NC}"
echo ""

# ==========================================
# Final Summary
# ==========================================

echo "=========================================="
echo "Test Setup & Execution Complete"
echo "=========================================="
echo ""
echo "Results:"
if [ $BACKEND_EXIT_CODE -eq 0 ]; then
    echo -e "  ${GREEN}✓ Backend Tests: PASSED${NC}"
else
    echo -e "  ${RED}✗ Backend Tests: FAILED${NC}"
fi

if [ $FRONTEND_EXIT_CODE -eq 0 ]; then
    echo -e "  ${GREEN}✓ Frontend Tests: PASSED${NC}"
else
    echo -e "  ${RED}✗ Frontend Tests: FAILED${NC}"
fi

echo ""
echo "Generated Files:"
echo "  - backend-test-results.txt"
echo "  - frontend-test-results.txt"
echo "  - TEST-SUMMARY.md"
echo ""
echo "Coverage Reports:"
echo "  - financial-rise-backend/coverage/"
echo "  - financial-rise-frontend/coverage/"
echo ""
echo "Next Steps:"
echo "  1. Review test results above"
echo "  2. Open coverage reports in browser"
echo "  3. Implement actual test cases (currently placeholders)"
echo "  4. Aim for 80%+ coverage per specifications"
echo ""
echo "Watch Mode (for development):"
echo "  Backend:  cd financial-rise-backend && npm run test:watch"
echo "  Frontend: cd financial-rise-frontend && npm run test:watch"
echo ""

# Exit with failure if either test suite failed
if [ $BACKEND_EXIT_CODE -ne 0 ] || [ $FRONTEND_EXIT_CODE -ne 0 ]; then
    exit 1
fi

exit 0
