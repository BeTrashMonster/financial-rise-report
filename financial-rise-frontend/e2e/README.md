# End-to-End Testing Suite

## Overview

This directory contains comprehensive E2E tests for the Financial RISE Report application using Playwright. The test suite covers all critical user workflows including authentication, assessment completion, report generation, and administrative functions.

## Test Coverage

### 1. Authentication Tests (`auth.spec.ts`)
- User registration with validation
- Login with valid/invalid credentials
- Logout functionality
- Session persistence
- Protected route handling

### 2. Assessment Workflow Tests (`assessment-workflow.spec.ts`)
- Assessment creation
- Complete questionnaire workflow
- Question navigation (back/forward)
- Progress indicators
- Draft saving and resumption
- Field validation

### 3. Auto-Save Tests (`auto-save.spec.ts`)
- Periodic auto-save functionality
- Save status indicators
- Data persistence across page refreshes
- Rapid change handling
- Offline error handling
- Save retry mechanism

### 4. Report Generation Tests (`report-generation.spec.ts`)
- Consultant report generation
- Client report generation
- PDF downloads (both report types)
- PDF preview in browser
- DISC profile display
- Phase determination results
- Action recommendations
- Report regeneration
- Error handling

### 5. Admin User Management Tests (`admin.spec.ts`)
- Admin dashboard access
- User list display
- User creation
- User editing
- User deactivation/deletion
- User search and filtering
- Activity log viewing
- Password reset
- Role management
- Access control verification

### 6. Accessibility Tests (`accessibility.spec.ts`)
- WCAG 2.1 Level AA compliance
- Keyboard navigation
- Screen reader support
- Focus management
- ARIA attributes
- Color contrast
- Alternative text
- Error announcements
- Landmark regions
- Form validation accessibility

### 7. Performance Tests (`performance.spec.ts`)
- Page load times (<3 seconds per REQ-PERF-001)
- Report generation time (<5 seconds per REQ-PERF-002)
- PDF download responsiveness
- Auto-save latency
- Bundle size optimization
- Image optimization
- API response times
- Concurrent user handling

## Prerequisites

1. **Node.js** >= 18.0.0
2. **npm** >= 9.0.0
3. **Playwright browsers** (installed automatically)

## Installation

```bash
# Install dependencies
cd financial-rise-frontend
npm install

# Install Playwright browsers
npx playwright install
```

## Running Tests

### Run All E2E Tests

```bash
npm run test:e2e
```

### Run Tests with UI Mode (Interactive)

```bash
npm run test:e2e:ui
```

### Run Tests in Headed Mode (See Browser)

```bash
npm run test:e2e:headed
```

### Debug Tests

```bash
npm run test:e2e:debug
```

### Cross-Browser Testing

```bash
# Run on Chromium only
npm run test:e2e:chromium

# Run on Firefox only
npm run test:e2e:firefox

# Run on WebKit (Safari) only
npm run test:e2e:webkit

# Run on mobile browsers
npm run test:e2e:mobile
```

### View Test Reports

```bash
npm run test:e2e:report
```

## Test Configuration

Test configuration is defined in `playwright.config.ts`:

- **Base URL**: `http://localhost:5173` (configurable via `E2E_BASE_URL` env var)
- **Timeout**: 30 seconds per test
- **Retries**: 2 retries on CI, 0 locally
- **Browsers**: Chromium, Firefox, WebKit
- **Mobile**: Pixel 5, iPhone 12, iPad Pro
- **Screenshots**: On failure only
- **Videos**: Retained on failure
- **Traces**: On first retry

## Test Environment Setup

### Development Server

Tests automatically start the dev server before running:

```bash
# This happens automatically
npm run dev
```

### Test Users

The following test users should exist in your test database:

| Email | Password | Role |
|-------|----------|------|
| consultant@test.com | Test123! | Consultant |
| admin@test.com | Admin123! | Admin |
| client@test.com | Client123! | Client |

### Environment Variables

Create a `.env.test` file for test-specific configuration:

```bash
E2E_BASE_URL=http://localhost:5173
API_BASE_URL=http://localhost:3000
TEST_TIMEOUT=30000
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: 18
      - name: Install dependencies
        run: npm ci
      - name: Install Playwright Browsers
        run: npx playwright install --with-deps
      - name: Run E2E tests
        run: npm run test:e2e
      - uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report
          path: playwright-report/
```

## Writing New Tests

### Test Structure

```typescript
import { test, expect } from '@playwright/test';

test.describe('Feature Name', () => {
  test.beforeEach(async ({ page }) => {
    // Setup before each test
    await page.goto('/');
  });

  test('should perform expected behavior', async ({ page }) => {
    // Arrange
    await page.getByLabel(/email/i).fill('test@example.com');

    // Act
    await page.getByRole('button', { name: /submit/i }).click();

    // Assert
    await expect(page.getByText(/success/i)).toBeVisible();
  });
});
```

### Best Practices

1. **Use semantic selectors**: Prefer `getByRole`, `getByLabel`, `getByText` over CSS selectors
2. **Wait for elements**: Use `waitFor` methods instead of fixed timeouts
3. **Test user journeys**: Focus on complete workflows, not implementation details
4. **Isolate tests**: Each test should be independent
5. **Use test data**: Generate unique test data using timestamps
6. **Handle async**: Always await asynchronous operations
7. **Clean up**: Ensure tests don't leave side effects

### Locator Strategies

```typescript
// Prefer (Accessibility-friendly)
page.getByRole('button', { name: /submit/i })
page.getByLabel(/email/i)
page.getByText(/welcome/i)
page.getByPlaceholder(/search/i)

// Use sparingly
page.locator('[data-testid="custom-element"]')
page.locator('.css-class')
```

## Debugging Tests

### Visual Debugging

```bash
# Open Playwright Inspector
npm run test:e2e:debug
```

### Console Logs

```typescript
test('debug test', async ({ page }) => {
  page.on('console', msg => console.log(msg.text()));

  await page.goto('/');
});
```

### Screenshots

```typescript
test('take screenshot', async ({ page }) => {
  await page.goto('/');
  await page.screenshot({ path: 'screenshot.png' });
});
```

### Trace Viewer

```bash
# Record trace
npx playwright test --trace on

# View trace
npx playwright show-trace trace.zip
```

## Test Maintenance

### Updating Snapshots

If visual snapshots need updating:

```bash
npx playwright test --update-snapshots
```

### Flaky Test Handling

1. Increase timeout for specific tests:
   ```typescript
   test('slow test', async ({ page }) => {
     test.setTimeout(60000);
     // ...
   });
   ```

2. Add retry logic:
   ```typescript
   test('flaky test', async ({ page }) => {
     test.retry(2);
     // ...
   });
   ```

3. Wait for network idle:
   ```typescript
   await page.waitForLoadState('networkidle');
   ```

## Performance Benchmarks

The test suite includes performance benchmarks to ensure:

- **Page loads**: < 3 seconds (REQ-PERF-001)
- **Report generation**: < 5 seconds (REQ-PERF-002)
- **Auto-save**: < 1 second
- **API calls**: < 500ms
- **Bundle size**: < 2MB
- **Image sizes**: < 500KB each

## Accessibility Standards

All tests verify WCAG 2.1 Level AA compliance:

- Keyboard navigation
- Screen reader compatibility
- Color contrast ratios
- Focus management
- ARIA attributes
- Semantic HTML
- Error announcements

## Troubleshooting

### Browsers Not Installing

```bash
# Install with dependencies
npx playwright install --with-deps
```

### Port Already in Use

```bash
# Kill process on port 5173
npx kill-port 5173

# Or specify different port
E2E_BASE_URL=http://localhost:5174 npm run test:e2e
```

### Test Timeout

```bash
# Increase global timeout
npx playwright test --timeout=60000
```

### WSL Issues (Windows)

```bash
# Install browser dependencies
sudo npx playwright install-deps
```

## Resources

- [Playwright Documentation](https://playwright.dev/)
- [Best Practices](https://playwright.dev/docs/best-practices)
- [Accessibility Testing](https://playwright.dev/docs/accessibility-testing)
- [CI/CD Integration](https://playwright.dev/docs/ci)

## Test Results

Test results are stored in:
- HTML Report: `playwright-report/`
- JSON Results: `test-results/e2e-results.json`
- JUnit XML: `test-results/e2e-junit.xml`

## Contributing

When adding new tests:

1. Follow existing test structure
2. Use descriptive test names
3. Add comments for complex logic
4. Update this README if adding new test categories
5. Ensure all tests pass before committing

## Support

For issues or questions about the test suite:
- Check existing test examples
- Review Playwright documentation
- File an issue in the project repository
