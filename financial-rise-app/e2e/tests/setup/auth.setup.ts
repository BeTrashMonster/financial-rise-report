import { test as setup, expect } from '@playwright/test';
import path from 'path';

const authFile = path.join(__dirname, '../.auth/consultant.json');

/**
 * Setup authenticated state for tests
 * This runs once before all tests that require authentication
 */
setup('authenticate as consultant', async ({ page }) => {
  // Navigate to login page
  await page.goto('/login');

  // Fill in credentials
  // TODO: Update with your test credentials or environment variables
  await page.getByLabel(/email|username/i).fill(process.env.TEST_USER_EMAIL || 'test@example.com');
  await page.getByLabel(/password/i).fill(process.env.TEST_USER_PASSWORD || 'testpassword123');

  // Click login
  await page.getByRole('button', { name: /sign in|login/i }).click();

  // Wait for successful navigation
  await page.waitForURL(/.*dashboard|home.*/);

  // Verify we're logged in
  await expect(page.getByText(/welcome|dashboard/i)).toBeVisible();

  // Save authenticated state
  await page.context().storageState({ path: authFile });
});
