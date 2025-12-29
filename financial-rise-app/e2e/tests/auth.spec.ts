import { test, expect } from '@playwright/test';

test.describe('Authentication Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login');
  });

  test('should display login form', async ({ page }) => {
    await expect(page.getByLabel(/email|username/i)).toBeVisible();
    await expect(page.getByRole('textbox', { name: /password/i })).toBeVisible();
    await expect(page.getByRole('button', { name: /sign in|login/i })).toBeVisible();
  });

  test('should show error on invalid credentials', async ({ page }) => {
    await page.getByLabel(/email/i).fill('invalid@example.com');
    await page.getByLabel(/password/i).fill('wrongpassword');

    // Click login and wait for response
    await page.getByRole('button', { name: /sign in|login/i }).click();

    // Check for error message - should contain 'Invalid' or 'password'
    await expect(page.getByText(/invalid|password.*incorrect|login.*failed|unauthorized/i)).toBeVisible({ timeout: 10000 });
  });

  test('should successfully login with valid credentials', async ({ page }) => {
    // Test user has been created in database

    // Note: Update these credentials or use test fixtures
    await page.getByLabel(/email|username/i).fill('test@example.com');
    await page.locator('input[name="password"]').fill('testpassword123');
    await page.getByRole('button', { name: /sign in|login/i }).click();

    // Should redirect to dashboard or home
    await expect(page).toHaveURL(/.*dashboard|home.*/, { timeout: 10000 });
  });

  test('should be able to logout', async ({ page }) => {
    // Test user has been created in database

    // First login
    await page.getByLabel(/email|username/i).fill('test@example.com');
    await page.locator('input[name="password"]').fill('testpassword123');
    await page.getByRole('button', { name: /sign in|login/i }).click();

    // Wait for dashboard
    await expect(page).toHaveURL(/.*dashboard|home.*/, { timeout: 10000 });

    // Find and click logout
    const logoutButton = page.getByRole('button', { name: /logout|sign out/i });
    await logoutButton.click();

    // Should redirect back to login or homepage
    await expect(page).toHaveURL(/.*login|^\/$|\/$/);
  });
});
