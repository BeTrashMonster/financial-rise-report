import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

/**
 * E2E Tests: Accessibility (WCAG 2.1 Level AA Compliance)
 * Tests keyboard navigation, screen reader compatibility, and ARIA compliance
 */

test.describe('Accessibility Compliance', () => {
  test('login page should have no accessibility violations', async ({ page }) => {
    await page.goto('/');

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('dashboard should have no accessibility violations', async ({ page }) => {
    // Login first
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('assessment questionnaire should have no accessibility violations', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    await page.getByRole('button', { name: /new assessment/i }).click();
    await page.getByLabel(/client name/i).fill('A11y Test');
    await page.getByLabel(/client email/i).fill('a11y@test.com');
    await page.getByLabel(/business name/i).fill('Test LLC');
    await page.getByRole('button', { name: /create/i }).click();

    const accessibilityScanResults = await new AxeBuilder({ page }).analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });

  test('should support keyboard navigation on login page', async ({ page }) => {
    await page.goto('/');

    // Tab through form fields
    await page.keyboard.press('Tab'); // Email field
    await expect(page.getByLabel(/email/i)).toBeFocused();

    await page.keyboard.press('Tab'); // Password field
    await expect(page.getByLabel(/password/i)).toBeFocused();

    await page.keyboard.press('Tab'); // Submit button
    await expect(page.getByRole('button', { name: /sign in/i })).toBeFocused();

    // Should be able to submit with Enter
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.keyboard.press('Tab');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.keyboard.press('Enter');

    await expect(page).toHaveURL(/\/dashboard/, { timeout: 10000 });
  });

  test('should support keyboard navigation in assessment', async ({ page }) => {
    // Login
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Create assessment
    await page.getByRole('button', { name: /new assessment/i }).click();
    await page.getByLabel(/client name/i).fill('Keyboard Test');
    await page.getByLabel(/client email/i).fill('keyboard@test.com');
    await page.getByLabel(/business name/i).fill('Test LLC');
    await page.getByRole('button', { name: /create/i }).click();

    // Navigate with arrow keys for radio buttons
    await page.keyboard.press('Tab'); // Focus on first radio group
    await page.keyboard.press('ArrowDown'); // Select second option
    await page.keyboard.press('ArrowDown'); // Select third option

    // Navigate to Next button with Tab
    await page.keyboard.press('Tab');
    await expect(page.getByRole('button', { name: /next/i })).toBeFocused();

    // Submit with Enter
    await page.keyboard.press('Enter');
  });

  test('should have proper focus indicators', async ({ page }) => {
    await page.goto('/');

    // Tab to email field
    await page.keyboard.press('Tab');

    // Check that focused element has visible focus indicator
    const focusedElement = await page.evaluateHandle(() => document.activeElement);
    const outlineStyle = await page.evaluate((el: Element) => {
      const styles = window.getComputedStyle(el);
      return {
        outline: styles.outline,
        outlineWidth: styles.outlineWidth,
        outlineStyle: styles.outlineStyle
      };
    }, focusedElement);

    // Should have some form of outline (browser default or custom)
    expect(
      outlineStyle.outlineWidth !== '0px' ||
      outlineStyle.outlineStyle !== 'none'
    ).toBeTruthy();
  });

  test('should have proper ARIA labels on form fields', async ({ page }) => {
    await page.goto('/');

    // Check email field has aria-label or associated label
    const emailField = page.getByLabel(/email/i);
    await expect(emailField).toHaveAttribute('aria-label', /.+/);
    // OR has associated <label> element
    // await expect(emailField).toHaveAccessibleName();
  });

  test('should have proper heading hierarchy', async ({ page }) => {
    await page.goto('/');

    // Get all headings
    const headings = await page.locator('h1, h2, h3, h4, h5, h6').all();

    expect(headings.length).toBeGreaterThan(0);

    // Check that there's at least one h1
    const h1Count = await page.locator('h1').count();
    expect(h1Count).toBeGreaterThanOrEqual(1);
  });

  test('should have sufficient color contrast', async ({ page }) => {
    await page.goto('/');

    // Run axe with specific contrast rules
    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2aa'])
      .analyze();

    const contrastViolations = accessibilityScanResults.violations.filter(
      v => v.id === 'color-contrast'
    );

    expect(contrastViolations).toEqual([]);
  });

  test('should have alt text for images', async ({ page }) => {
    await page.goto('/');

    // Check all images have alt text
    const images = await page.locator('img').all();

    for (const img of images) {
      const alt = await img.getAttribute('alt');
      // Alt can be empty string for decorative images, but must be present
      expect(alt).not.toBeNull();
    }
  });

  test('should have accessible error messages', async ({ page }) => {
    await page.goto('/');

    // Trigger validation errors
    await page.getByRole('button', { name: /sign in/i }).click();

    // Error messages should be associated with form fields
    const emailError = page.getByText(/email is required/i);
    await expect(emailError).toBeVisible();

    // Check if error has role="alert" or aria-live="polite"
    const errorElement = await emailError.elementHandle();
    if (errorElement) {
      const role = await errorElement.getAttribute('role');
      const ariaLive = await errorElement.getAttribute('aria-live');
      expect(role === 'alert' || ariaLive === 'polite' || ariaLive === 'assertive').toBeTruthy();
    }
  });

  test('should have skip to main content link', async ({ page }) => {
    await page.goto('/');

    // Tab to first element (should be skip link)
    await page.keyboard.press('Tab');

    const skipLink = page.getByRole('link', { name: /skip to (main )?content/i });

    if (await skipLink.count() > 0) {
      await expect(skipLink).toBeFocused();

      // Click skip link
      await skipLink.click();

      // Main content should be focused
      const main = page.locator('main, [role="main"]');
      await expect(main).toBeFocused();
    }
  });

  test('should have proper landmark regions', async ({ page }) => {
    await page.goto('/');

    // Check for standard landmarks
    await expect(page.locator('header, [role="banner"]')).toBeVisible();
    await expect(page.locator('main, [role="main"]')).toBeVisible();
    await expect(page.locator('footer, [role="contentinfo"]')).toBeVisible();
  });

  test('should have accessible form validation', async ({ page }) => {
    await page.goto('/');

    // Fill invalid email
    await page.getByLabel(/email/i).fill('invalid-email');
    await page.getByRole('button', { name: /sign in/i }).click();

    // Error should be announced to screen readers
    const emailField = page.getByLabel(/email/i);
    const ariaInvalid = await emailField.getAttribute('aria-invalid');
    const ariaDescribedBy = await emailField.getAttribute('aria-describedby');

    expect(ariaInvalid).toBe('true');
    expect(ariaDescribedBy).not.toBeNull();
  });

  test('should support screen reader announcements for dynamic content', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();

    // Create assessment (dynamic content)
    await page.waitForURL(/\/dashboard/);
    await page.getByRole('button', { name: /new assessment/i }).click();

    // Modal/dialog should have aria-live region or role="dialog"
    const dialog = page.locator('[role="dialog"], .MuiDialog-root');

    if (await dialog.count() > 0) {
      await expect(dialog).toHaveAttribute('role', 'dialog');
      await expect(dialog).toHaveAttribute('aria-modal', 'true');
    }
  });

  test('should have accessible buttons and links', async ({ page }) => {
    await page.goto('/');

    // All buttons should have accessible names
    const buttons = await page.getByRole('button').all();

    for (const button of buttons) {
      const name = await button.textContent();
      const ariaLabel = await button.getAttribute('aria-label');

      // Button must have text content or aria-label
      expect(name?.trim() || ariaLabel).toBeTruthy();
    }
  });

  test('should handle focus trapping in modals', async ({ page }) => {
    await page.goto('/');
    await page.getByLabel(/email/i).fill('consultant@test.com');
    await page.getByLabel(/password/i).fill('Test123!');
    await page.getByRole('button', { name: /sign in/i }).click();
    await page.waitForURL(/\/dashboard/);

    // Open modal
    await page.getByRole('button', { name: /new assessment/i }).click();

    // Tab should stay within modal
    const initialFocus = await page.evaluate(() => document.activeElement?.tagName);

    // Tab multiple times
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press('Tab');
    }

    // Focus should still be within dialog
    const dialog = page.locator('[role="dialog"]');
    if (await dialog.count() > 0) {
      const focusedElement = await page.evaluateHandle(() => document.activeElement);
      const isWithinDialog = await page.evaluate(
        ({ dialog, focused }) => dialog.contains(focused),
        { dialog: await dialog.elementHandle(), focused: focusedElement }
      );

      expect(isWithinDialog).toBeTruthy();
    }
  });
});
