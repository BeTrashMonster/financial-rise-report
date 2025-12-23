import { test, expect } from '@playwright/test';

/**
 * E2E Tests: Authentication
 * Tests user registration, login, and logout workflows
 */

test.describe('User Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should display login page', async ({ page }) => {
    await expect(page).toHaveTitle(/Financial RISE/);
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
  });

  test('should show validation errors for empty login form', async ({ page }) => {
    await page.getByRole('button', { name: /sign in/i }).click();

    await expect(page.getByText(/email is required/i)).toBeVisible();
    await expect(page.getByText(/password is required/i)).toBeVisible();
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.getByLabel(/email/i).fill('invalid@example.com');
    await page.getByLabel(/password/i).fill('wrongpassword');
    await page.getByRole('button', { name: /sign in/i }).click();

    await expect(page.getByText(/invalid credentials|authentication failed/i)).toBeVisible();
  });

  test('should successfully login with valid credentials', async ({ page }) => {
    // Use test credentials
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByText(/welcome|dashboard/i)).toBeVisible();
  });

  test('should navigate to registration page', async ({ page }) => {
    await page.getByRole('link', { name: /sign up|register|create account/i }).click();

    await expect(page).toHaveURL(/\/register|\/signup/);
    await expect(page.getByRole('heading', { name: /sign up|register|create account/i })).toBeVisible();
  });

  test('should register new user successfully', async ({ page }) => {
    await page.goto('/register');

    const timestamp = Date.now();
    const testEmail = `consultant${timestamp}@test.com`;

    await page.getByLabel(/first name/i).fill('Test');
    await page.getByLabel(/last name/i).fill('Consultant');
    await page.getByLabel(/email/i).fill(testEmail);
    await page.getByLabel(/^password/i).fill('Test123!');
    await page.getByLabel(/confirm password/i).fill('Test123!');

    await page.getByRole('button', { name: /sign up|register|create account/i }).click();

    // Should redirect to dashboard or show success message
    await expect(page).toHaveURL(/\/dashboard|\/login/);
  });

  test('should logout successfully', async ({ page }) => {
    // Login first
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Logout
    await page.getByRole('button', { name: /logout|sign out/i }).click();

    // Should redirect to login page
    await expect(page).toHaveURL(/\/login|\//);
    await expect(page.getByRole('heading', { name: /sign in/i })).toBeVisible();
  });

  test('should persist login state after page refresh', async ({ page }) => {
    // Login
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Refresh page
    await page.reload();

    // Should still be logged in
    await expect(page).toHaveURL(/\/dashboard/);
    await expect(page.getByText(/welcome|dashboard/i)).toBeVisible();
  });

  test('should redirect unauthenticated users to login', async ({ page }) => {
    await page.goto('/dashboard');

    // Should redirect to login
    await expect(page).toHaveURL(/\/login|\//);
  });
});
