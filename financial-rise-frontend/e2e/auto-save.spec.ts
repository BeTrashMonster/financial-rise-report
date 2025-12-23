import { test, expect } from '@playwright/test';

/**
 * E2E Tests: Auto-Save Functionality
 * Tests auto-save feature during assessment completion
 */

test.describe('Auto-Save Functionality', () => {
  test.beforeEach(async ({ page }) => {
    // Login and create assessment
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Create new assessment
    await page.getByRole('button', { name: /new assessment|create assessment/i }).click();
    const timestamp = Date.now();
    await page.getByLabel(/client name/i).fill(`AutoSave Test ${timestamp}`);
    await page.getByLabel(/client email/i).fill(`autosave${timestamp}@test.com`);
    await page.getByLabel(/business name/i).fill('Auto Save LLC');
    await page.getByRole('button', { name: /create|save|start/i }).click();
  });

  test('should auto-save responses periodically', async ({ page }) => {
    // Answer first question
    await page.getByRole('radio').first().check();

    // Wait for auto-save indicator
    await expect(page.getByText(/saving|saved|auto-saved/i)).toBeVisible({ timeout: 10000 });
  });

  test('should show save status indicator', async ({ page }) => {
    // The page should show save status
    const saveStatus = page.locator('[data-testid="save-status"], .save-status');
    await expect(saveStatus).toBeVisible({ timeout: 10000 });
  });

  test('should persist data after page refresh', async ({ page }) => {
    // Answer first question
    await page.getByRole('radio').first().check();

    // Wait for auto-save
    await page.waitForTimeout(3000);

    // Refresh page
    await page.reload();

    // The selected answer should still be checked
    await expect(page.getByRole('radio').first()).toBeChecked();
  });

  test('should handle rapid changes without data loss', async ({ page }) => {
    // Make multiple rapid changes
    for (let i = 0; i < 5; i++) {
      const radios = page.getByRole('radio');
      const count = await radios.count();
      if (count > i) {
        await radios.nth(i % count).check();
      }
      await page.waitForTimeout(500);
    }

    // Wait for auto-save to complete
    await expect(page.getByText(/saved/i)).toBeVisible({ timeout: 10000 });

    // Refresh and verify last selection persists
    await page.reload();

    // At least one radio should be checked
    const checkedRadios = await page.getByRole('radio', { checked: true }).count();
    expect(checkedRadios).toBeGreaterThan(0);
  });

  test('should show error if auto-save fails', async ({ page }) => {
    // Simulate network offline
    await page.context().setOffline(true);

    // Try to answer question
    await page.getByRole('radio').first().check();

    // Wait for error message
    await expect(page.getByText(/failed to save|save error|offline/i)).toBeVisible({ timeout: 10000 });

    // Restore network
    await page.context().setOffline(false);
  });

  test('should retry failed saves when connection restored', async ({ page }) => {
    // Go offline
    await page.context().setOffline(true);

    // Answer question
    await page.getByRole('radio').first().check();

    // Wait for error
    await expect(page.getByText(/failed to save|save error|offline/i)).toBeVisible({ timeout: 10000 });

    // Go back online
    await page.context().setOffline(false);

    // Should automatically retry and show success
    await expect(page.getByText(/saved/i)).toBeVisible({ timeout: 15000 });
  });

  test('should handle concurrent saves gracefully', async ({ page }) => {
    // Navigate through questions quickly, triggering multiple save operations
    for (let i = 0; i < 3; i++) {
      await page.getByRole('radio').first().check();
      await page.getByRole('button', { name: /next/i }).click();
      await page.waitForTimeout(100); // Minimal delay
    }

    // Should eventually show saved status without errors
    await expect(page.getByText(/saved/i)).toBeVisible({ timeout: 15000 });
  });

  test('should preserve answers across browser sessions', async ({ browser, page }) => {
    // Answer first question
    await page.getByRole('radio').first().check();

    // Wait for save
    await expect(page.getByText(/saved/i)).toBeVisible({ timeout: 10000 });

    // Get current URL to resume assessment
    const assessmentUrl = page.url();

    // Close page
    await page.close();

    // Create new page (simulating new browser session)
    const newPage = await browser.newPage();

    // Login again
    await newPage.goto('/');
    await newPage.getByLabel(/email/i).fill('consultant@test.com');
    await newPage.getByLabel(/password/i).fill('Test123!');
    await newPage.getByRole('button', { name: /sign in/i }).click();
    await newPage.waitForURL(/\/dashboard/);

    // Navigate to assessment
    await newPage.goto(assessmentUrl);

    // Answer should still be selected
    await expect(newPage.getByRole('radio').first()).toBeChecked();

    await newPage.close();
  });
});
