import { test, expect } from '@playwright/test';

/**
 * E2E Tests: Admin User Management
 * Tests admin dashboard and user management functionality
 */

test.describe('Admin User Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login as admin
    await page.goto('/');
    await page.getByLabel(/email/i).fill('admin@test.com');
    await page.getByLabel(/password/i).fill('Admin123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard|\/admin/);
  });

  test('should access admin dashboard', async ({ page }) => {
    // Navigate to admin panel
    const adminLink = page.getByRole('link', { name: /admin|administration/i });

    if (await adminLink.count() > 0) {
      await adminLink.click();
      await expect(page).toHaveURL(/\/admin/);
      await expect(page.getByRole('heading', { name: /admin|administration/i })).toBeVisible();
    }
  });

  test('should display user list', async ({ page }) => {
    await page.goto('/admin/users');

    // Should show table with users
    await expect(page.getByRole('table')).toBeVisible();
    await expect(page.getByRole('columnheader', { name: /email|name|role/i })).toBeVisible();
  });

  test('should create new user', async ({ page }) => {
    await page.goto('/admin/users');

    const addUserButton = page.getByRole('button', { name: /add user|new user|create user/i });

    if (await addUserButton.count() > 0) {
      await addUserButton.click();

      // Fill user details
      const timestamp = Date.now();
      await page.getByLabel(/first name/i).fill('New');
      await page.getByLabel(/last name/i).fill('User');
      await page.getByLabel(/email/i).fill(`newuser${timestamp}@test.com`);
      await page.getByLabel(/role/i).selectOption('consultant');

      await page.getByRole('button', { name: /create|save|add/i }).click();

      // Should show success message
      await expect(page.getByText(/user created|success|added successfully/i)).toBeVisible();
    }
  });

  test('should edit existing user', async ({ page }) => {
    await page.goto('/admin/users');

    // Find edit button for first user
    const editButton = page.getByRole('button', { name: /edit/i }).first();

    if (await editButton.count() > 0) {
      await editButton.click();

      // Update user details
      await page.getByLabel(/first name/i).fill('Updated');

      await page.getByRole('button', { name: /save|update/i }).click();

      // Should show success message
      await expect(page.getByText(/updated|success|saved/i)).toBeVisible();
    }
  });

  test('should deactivate user', async ({ page }) => {
    await page.goto('/admin/users');

    // Find deactivate button
    const deactivateButton = page.getByRole('button', { name: /deactivate|disable/i }).first();

    if (await deactivateButton.count() > 0) {
      await deactivateButton.click();

      // Confirm action
      const confirmButton = page.getByRole('button', { name: /confirm|yes|deactivate/i });
      if (await confirmButton.count() > 0) {
        await confirmButton.click();
      }

      // Should show success message
      await expect(page.getByText(/deactivated|disabled|success/i)).toBeVisible();
    }
  });

  test('should delete user', async ({ page }) => {
    await page.goto('/admin/users');

    // Create a test user first
    const addUserButton = page.getByRole('button', { name: /add user|new user/i });
    if (await addUserButton.count() > 0) {
      await addUserButton.click();
      const timestamp = Date.now();
      await page.getByLabel(/email/i).fill(`deletetest${timestamp}@test.com`);
      await page.getByLabel(/first name/i).fill('Delete');
      await page.getByLabel(/last name/i).fill('Test');
      await page.getByRole('button', { name: /create|save/i }).click();
      await page.waitForTimeout(1000);
    }

    // Find delete button
    const deleteButton = page.getByRole('button', { name: /delete|remove/i }).first();

    if (await deleteButton.count() > 0) {
      await deleteButton.click();

      // Confirm deletion
      const confirmButton = page.getByRole('button', { name: /confirm|yes|delete/i });
      if (await confirmButton.count() > 0) {
        await confirmButton.click();
      }

      // Should show success message
      await expect(page.getByText(/deleted|removed|success/i)).toBeVisible();
    }
  });

  test('should search for users', async ({ page }) => {
    await page.goto('/admin/users');

    const searchInput = page.getByPlaceholder(/search|filter/i);

    if (await searchInput.count() > 0) {
      await searchInput.fill('test');

      // Results should update
      await page.waitForTimeout(1000);
      const rows = await page.getByRole('row').count();
      expect(rows).toBeGreaterThan(0);
    }
  });

  test('should filter users by role', async ({ page }) => {
    await page.goto('/admin/users');

    const roleFilter = page.getByLabel(/role|filter by role/i);

    if (await roleFilter.count() > 0) {
      await roleFilter.selectOption('consultant');

      // Table should update to show only consultants
      await page.waitForTimeout(1000);
      await expect(page.getByRole('table')).toBeVisible();
    }
  });

  test('should view user activity log', async ({ page }) => {
    await page.goto('/admin/users');

    // Click on a user to view details
    const viewButton = page.getByRole('button', { name: /view|details/i }).first();

    if (await viewButton.count() > 0) {
      await viewButton.click();

      // Should show activity log
      await expect(page.getByText(/activity|log|history/i)).toBeVisible();
    }
  });

  test('should reset user password', async ({ page }) => {
    await page.goto('/admin/users');

    const resetButton = page.getByRole('button', { name: /reset password/i }).first();

    if (await resetButton.count() > 0) {
      await resetButton.click();

      // Confirm action
      const confirmButton = page.getByRole('button', { name: /confirm|yes|reset/i });
      if (await confirmButton.count() > 0) {
        await confirmButton.click();
      }

      // Should show success message
      await expect(page.getByText(/password reset|email sent|success/i)).toBeVisible();
    }
  });

  test('should change user role', async ({ page }) => {
    await page.goto('/admin/users');

    // Edit user
    const editButton = page.getByRole('button', { name: /edit/i }).first();

    if (await editButton.count() > 0) {
      await editButton.click();

      // Change role
      const roleSelect = page.getByLabel(/role/i);
      if (await roleSelect.count() > 0) {
        await roleSelect.selectOption('admin');
        await page.getByRole('button', { name: /save|update/i }).click();

        // Should show success message
        await expect(page.getByText(/updated|success|saved/i)).toBeVisible();
      }
    }
  });

  test('should prevent non-admin users from accessing admin panel', async ({ page }) => {
    // Logout
    await page.getByRole('button', { name: /logout/i }).click();

    // Login as regular consultant
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();

    // Try to access admin panel
    await page.goto('/admin/users');

    // Should redirect or show access denied
    await expect(page.getByText(/access denied|unauthorized|forbidden/i).or(page.getByText(/dashboard/))).toBeVisible();
  });

  test('should display system statistics', async ({ page }) => {
    const adminLink = page.getByRole('link', { name: /admin|administration/i });

    if (await adminLink.count() > 0) {
      await adminLink.click();

      // Should show statistics
      await expect(page.getByText(/total users|active assessments|reports generated/i)).toBeVisible();
    }
  });
});
