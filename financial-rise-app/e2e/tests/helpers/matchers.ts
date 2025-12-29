import { expect } from '@playwright/test';

/**
 * Custom matchers for Financial RISE specific assertions
 */

/**
 * Check if page has required accessibility features
 */
export async function expectAccessibility(page: any) {
  // Check for skip navigation link
  const skipNav = page.locator('[href="#main-content"]');
  await expect(skipNav).toBeAttached();

  // Check for lang attribute
  const html = page.locator('html');
  await expect(html).toHaveAttribute('lang', 'en');
}

/**
 * Check if report has been generated successfully
 */
export async function expectReportGenerated(page: any) {
  // Check for report elements
  await expect(page.getByText(/consultant report|client report/i)).toBeVisible();
  await expect(page.getByText(/financial phase/i)).toBeVisible();

  // Check for download/view buttons
  const downloadButton = page.getByRole('button', { name: /download|view report/i });
  await expect(downloadButton).toBeVisible();
}

/**
 * Check if error message is displayed correctly
 */
export async function expectErrorMessage(page: any, message?: string | RegExp) {
  const errorAlert = page.locator('[role="alert"]');
  await expect(errorAlert).toBeVisible();

  if (message) {
    await expect(errorAlert).toContainText(message);
  }
}

/**
 * Check if success message is displayed
 */
export async function expectSuccessMessage(page: any, message?: string | RegExp) {
  const successAlert = page.locator('[role="alert"]').filter({ hasText: /success|saved|created/i });
  await expect(successAlert).toBeVisible();

  if (message) {
    await expect(successAlert).toContainText(message);
  }
}

/**
 * Check if loading state is shown
 */
export async function expectLoading(page: any) {
  const loader = page.locator('[role="progressbar"], [aria-busy="true"]');
  await expect(loader).toBeVisible();
}

/**
 * Check if loading state is hidden
 */
export async function expectNotLoading(page: any) {
  const loader = page.locator('[role="progressbar"], [aria-busy="true"]');
  await expect(loader).not.toBeVisible();
}
