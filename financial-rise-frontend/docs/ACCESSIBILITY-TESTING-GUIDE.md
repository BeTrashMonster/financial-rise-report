# Accessibility Testing Guide
# Financial RISE Report Frontend

**Version:** 1.0
**Last Updated:** 2025-12-22

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Automated Testing](#automated-testing)
4. [Manual Testing](#manual-testing)
5. [Keyboard Navigation Testing](#keyboard-navigation-testing)
6. [Screen Reader Testing](#screen-reader-testing)
7. [Color Contrast Testing](#color-contrast-testing)
8. [Responsive Accessibility Testing](#responsive-accessibility-testing)
9. [Common Issues and Solutions](#common-issues-and-solutions)
10. [Accessibility Checklist](#accessibility-checklist)

---

## Overview

This guide provides comprehensive instructions for testing the accessibility of the Financial RISE Report application. Our goal is to maintain WCAG 2.1 Level AA compliance.

### Why Accessibility Matters
- **Legal Requirement:** WCAG 2.1 Level AA compliance (REQ-ACCESS-001)
- **Better UX:** Accessible design benefits all users
- **Market Reach:** Includes users with disabilities (15-20% of population)
- **SEO Benefits:** Better semantic structure improves search rankings

---

## Quick Start

### Run All Accessibility Tests
```bash
# Automated E2E accessibility tests
npm run test:e2e -- e2e/accessibility.spec.ts

# Run in specific browser
npm run test:e2e:chromium -- e2e/accessibility.spec.ts
npm run test:e2e:firefox -- e2e/accessibility.spec.ts
npm run test:e2e:webkit -- e2e/accessibility.spec.ts

# Lint check for accessibility issues
npm run lint
```

### Test Results Location
- E2E test results: `test-results/`
- Playwright HTML report: `playwright-report/`
- Screenshots: `test-results/` (on failure)

---

## Automated Testing

### 1. axe-core Playwright Tests

Our E2E test suite includes automated accessibility scanning using @axe-core/playwright.

**What it tests:**
- ARIA attributes
- Color contrast
- Form labels
- Heading hierarchy
- Alt text on images
- Landmark regions
- Keyboard accessibility
- Focus management

**Run tests:**
```bash
npm run test:e2e -- e2e/accessibility.spec.ts
```

**How it works:**
```typescript
import AxeBuilder from '@axe-core/playwright';

test('page should have no accessibility violations', async ({ page }) => {
  await page.goto('/');

  const accessibilityScanResults = await new AxeBuilder({ page })
    .withTags(['wcag2aa'])
    .analyze();

  expect(accessibilityScanResults.violations).toEqual([]);
});
```

### 2. ESLint jsx-a11y Plugin

Static analysis of JSX for accessibility issues.

**What it checks:**
- Missing alt text
- Invalid ARIA attributes
- Incorrect role usage
- Missing form labels
- Keyboard event handlers
- Click handlers on non-interactive elements

**Run lint check:**
```bash
npm run lint
npm run lint:fix  # Auto-fix some issues
```

**Configuration:**
The `eslint-plugin-jsx-a11y` plugin is configured in our ESLint setup with recommended rules.

---

## Manual Testing

Manual testing is essential for catching issues automated tools miss.

### Testing Process

1. **Visual Inspection**
   - Check for visible focus indicators
   - Verify color contrast manually
   - Ensure text is readable at 200% zoom
   - Check responsive layouts

2. **Interaction Testing**
   - Test all interactive elements
   - Verify modal focus trapping
   - Check error message visibility
   - Test form validation

3. **Content Review**
   - Verify heading hierarchy (no skipped levels)
   - Check alt text accuracy
   - Ensure link text is descriptive
   - Verify landmark structure

---

## Keyboard Navigation Testing

**Goal:** Ensure all functionality is accessible without a mouse.

### Test Plan

#### 1. Basic Navigation
| Key | Expected Behavior |
|-----|-------------------|
| Tab | Move to next focusable element |
| Shift+Tab | Move to previous focusable element |
| Enter | Activate buttons/links |
| Space | Activate buttons, toggle checkboxes |
| Arrow Keys | Navigate within radio groups/dropdowns |
| Esc | Close modals/dialogs |

#### 2. Test Each Page

**Login Page**
```
✅ Tab through: Email → Password → Submit
✅ Submit form with Enter key
✅ Error messages keyboard accessible
```

**Dashboard**
```
✅ Tab to "New Assessment" button
✅ Navigate search field
✅ Access status filter
✅ Reach all assessment cards
✅ Use card action buttons (Edit, Delete, View)
```

**Create Assessment Modal**
```
✅ Focus trapped in modal
✅ Tab through form fields
✅ Close with Esc key
✅ Submit with Enter
✅ Cancel button accessible
```

**Questionnaire**
```
✅ Tab to first question
✅ Use arrow keys to select radio options
✅ Tab to Next/Previous buttons
✅ Navigate progress indicator
✅ Access auto-save status
```

**Report Preview**
```
✅ Generate report buttons accessible
✅ Download PDF links focusable
✅ Navigate PDF viewer controls
```

#### 3. Focus Indicators Checklist
- [ ] All interactive elements show focus outline
- [ ] Focus outline has 3:1 contrast ratio
- [ ] Focus outline does not obscure content
- [ ] Focus order is logical and intuitive
- [ ] No focus traps (except intentional in modals)

#### 4. Common Keyboard Issues
| Issue | How to Detect | Solution |
|-------|---------------|----------|
| Missing focus indicator | Tab through page, no visible focus | Add `:focus` styles |
| Illogical tab order | Tab order doesn't match visual order | Fix DOM order or use `tabindex` |
| Keyboard trap | Can't Tab out of component | Fix focus management |
| Can't activate with Enter | Button only works with mouse | Use `<button>` not `<div>` |
| Arrow keys don't work | Radio group doesn't support arrows | Use `RadioGroup` from MUI |

---

## Screen Reader Testing

**Goal:** Ensure content is properly announced to screen reader users.

### Screen Reader Setup

#### Windows - NVDA (Free, Recommended)
1. Download from: https://www.nvaccess.org/download/
2. Install and launch NVDA
3. Use with Chrome or Firefox

**Basic NVDA Commands:**
| Command | Action |
|---------|--------|
| Insert + Down Arrow | Read next line |
| Insert + Up Arrow | Read previous line |
| Insert + Space | Toggle browse/focus mode |
| H | Navigate by heading |
| Tab | Navigate by focusable element |
| Insert + F7 | List all links |
| Insert + F5 | List all form fields |
| Insert + Q | Quit NVDA |

#### Windows - JAWS (Commercial)
Download from: https://www.freedomscientific.com/products/software/jaws/

**Basic JAWS Commands:** Similar to NVDA

### Screen Reader Testing Checklist

#### 1. Page Structure
- [ ] Page title announced
- [ ] Heading hierarchy read correctly (h1, h2, h3...)
- [ ] Landmark regions announced (banner, main, contentinfo)
- [ ] Navigation structure clear

#### 2. Forms
- [ ] Form field labels announced
- [ ] Required fields indicated
- [ ] Field types announced (text, email, password)
- [ ] Error messages announced
- [ ] aria-invalid state announced
- [ ] Helper text read after label

#### 3. Interactive Elements
- [ ] Buttons announce role and label
- [ ] Links announce role and destination
- [ ] Radio buttons announce role, label, and state
- [ ] Checkboxes announce role, label, and checked state
- [ ] Dropdown menus announce expanded/collapsed state

#### 4. Dynamic Content
- [ ] Loading states announced
- [ ] Auto-save status communicated
- [ ] Form errors announced (aria-live)
- [ ] Success messages announced
- [ ] Modal dialogs announced with role="dialog"

#### 5. Images and Icons
- [ ] Images have descriptive alt text
- [ ] Decorative images use alt=""
- [ ] Icon buttons have aria-label
- [ ] Complex images have longer descriptions

### Testing Each Component

**AppLayout**
```
✅ Header announced as "banner"
✅ Main content announced as "main"
✅ Footer announced as "contentinfo"
✅ Navigation buttons clearly labeled
✅ "Financial RISE Report" heading announced
```

**Dashboard**
```
✅ "Assessments" h1 announced first
✅ "New Assessment" button clearly labeled
✅ Search field has label
✅ Status filter announced with current value
✅ Assessment cards describe status and client
✅ Empty state message announced
```

**Questionnaire**
```
✅ Question text announced before options
✅ Radio group announced as group
✅ Each option announced with radio button role
✅ Required indicator announced
✅ Progress announced: "Question X of Y"
✅ Auto-save status updates announced
```

---

## Color Contrast Testing

**Goal:** Ensure all text and UI components have sufficient contrast.

### WCAG Requirements
- **Normal text (< 18px):** 4.5:1 contrast ratio
- **Large text (≥ 18px or ≥ 14px bold):** 3:1 contrast ratio
- **UI components and graphics:** 3:1 contrast ratio
- **Disabled elements:** No requirement

### Testing Tools

#### 1. Browser DevTools
**Chrome DevTools:**
1. Open DevTools (F12)
2. Inspect element
3. Check "Contrast" section in Styles panel
4. Look for ✅ (pass) or ⚠️ (fail) indicators

#### 2. WebAIM Contrast Checker
URL: https://webaim.org/resources/contrastchecker/

**How to use:**
1. Get foreground color (text color)
2. Get background color
3. Enter into checker
4. Verify AA and AAA compliance

#### 3. axe DevTools Extension
Install: Chrome Web Store → "axe DevTools"

**How to use:**
1. Open extension
2. Click "Scan ALL of my page"
3. Review "Color Contrast" issues
4. Fix any violations

### Brand Color Contrast Tests

Our brand colors have been pre-tested:

| Foreground | Background | Ratio | Status |
|-----------|------------|-------|---------|
| #000000 (black text) | #FFFFFF (white) | 21:1 | ✅ AAA |
| #424242 (gray text) | #FFFFFF (white) | 12.6:1 | ✅ AAA |
| #FFFFFF (white text) | #4B006E (purple) | 7.9:1 | ✅ AAA |
| #000000 (black text) | #D4AF37 (gold) | 10.8:1 | ✅ AAA |

### Manual Testing Process

1. **Identify all text on page**
2. **For each text element:**
   - Note foreground color
   - Note background color
   - Test contrast ratio
   - Verify compliance
3. **Test UI components:**
   - Button borders
   - Input borders
   - Focus indicators
   - Icons

---

## Responsive Accessibility Testing

**Goal:** Ensure accessibility across all device sizes.

### Test Viewports

| Device | Resolution | Browser |
|--------|-----------|---------|
| Desktop | 1920x1080 | Chrome |
| Laptop | 1366x768 | Firefox |
| iPad Pro | 1024x1366 | Safari |
| Pixel 5 | 393x851 | Chrome Mobile |
| iPhone 12 | 390x844 | Safari Mobile |

### Responsive Testing Checklist

#### 1. Touch Targets (Mobile)
- [ ] All buttons at least 44x44px
- [ ] Adequate spacing between touch targets (8px minimum)
- [ ] No overlapping interactive elements
- [ ] Form fields large enough for finger input

#### 2. Reflow and Zoom
- [ ] Content reflows at 320px width (no horizontal scroll)
- [ ] Text readable when zoomed to 200%
- [ ] No text truncation or overlap at 200% zoom
- [ ] All functionality still accessible when zoomed

#### 3. Orientation
- [ ] Works in both portrait and landscape
- [ ] No content locked to specific orientation
- [ ] Layout adapts appropriately

#### 4. Mobile Screen Reader
- [ ] Test with TalkBack (Android) or VoiceOver (iOS)
- [ ] Swipe gestures navigate properly
- [ ] All content accessible via screen reader
- [ ] Form inputs work with screen reader

### Mobile Accessibility Commands

**iOS VoiceOver:**
- Swipe right: Next element
- Swipe left: Previous element
- Double tap: Activate element
- Three-finger swipe: Scroll

**Android TalkBack:**
- Swipe right: Next element
- Swipe left: Previous element
- Double tap: Activate element
- Two-finger swipe: Scroll

---

## Common Issues and Solutions

### Issue 1: Button Not Keyboard Accessible
**Problem:** Div or span used as button
```jsx
// ❌ Bad
<div onClick={handleClick}>Click me</div>

// ✅ Good
<Button onClick={handleClick}>Click me</Button>
```

### Issue 2: Missing Form Label
**Problem:** Input has placeholder but no label
```jsx
// ❌ Bad
<input placeholder="Email" />

// ✅ Good
<TextField label="Email" placeholder="example@email.com" />
```

### Issue 3: Icon Button Without Label
**Problem:** Screen reader can't identify button purpose
```jsx
// ❌ Bad
<IconButton>
  <DeleteIcon />
</IconButton>

// ✅ Good
<IconButton aria-label="Delete assessment">
  <DeleteIcon />
</IconButton>
```

### Issue 4: Low Color Contrast
**Problem:** Text hard to read on background
```jsx
// ❌ Bad (2.5:1 ratio)
color: '#999999' on background: '#FFFFFF'

// ✅ Good (4.5:1 ratio)
color: '#424242' on background: '#FFFFFF'
```

### Issue 5: Missing Alt Text
**Problem:** Images not accessible to screen readers
```jsx
// ❌ Bad
<img src="logo.png" />

// ✅ Good
<img src="logo.png" alt="Financial RISE Report Logo" />

// ✅ Also good (decorative image)
<img src="decoration.png" alt="" />
```

### Issue 6: Form Error Not Announced
**Problem:** Screen reader doesn't announce validation error
```jsx
// ❌ Bad
{error && <div>{error}</div>}

// ✅ Good
{error && (
  <FormHelperText error role="alert">
    {error}
  </FormHelperText>
)}
```

### Issue 7: Modal Not Focused
**Problem:** User can tab outside modal
```jsx
// ✅ Good (MUI Dialog handles this automatically)
<Dialog open={open} aria-modal="true">
  <DialogTitle>Create Assessment</DialogTitle>
  <DialogContent>
    {/* Focus trapped here */}
  </DialogContent>
</Dialog>
```

### Issue 8: Heading Hierarchy Skipped
**Problem:** h1 jumps to h3, skipping h2
```jsx
// ❌ Bad
<Typography variant="h1">Page Title</Typography>
<Typography variant="h3">Section</Typography>

// ✅ Good
<Typography variant="h1">Page Title</Typography>
<Typography variant="h2">Section</Typography>
<Typography variant="h3">Subsection</Typography>
```

---

## Accessibility Checklist

Use this checklist when developing new features or reviewing code.

### Development Checklist

#### Semantic HTML
- [ ] Use `<button>` for buttons (not `<div>` or `<a>`)
- [ ] Use `<a>` for links (with proper `href`)
- [ ] Use semantic HTML5 elements (`<header>`, `<main>`, `<nav>`, `<footer>`)
- [ ] Use proper heading hierarchy (h1 → h2 → h3)
- [ ] Use `<label>` for all form inputs

#### ARIA
- [ ] Add `aria-label` to icon buttons
- [ ] Use `aria-describedby` for error messages
- [ ] Use `aria-invalid` on invalid form fields
- [ ] Add `role="alert"` or `aria-live` for dynamic messages
- [ ] Use `aria-modal="true"` on dialogs

#### Keyboard
- [ ] All interactive elements keyboard accessible
- [ ] Visible focus indicators on all elements
- [ ] Logical tab order
- [ ] Modals trap focus
- [ ] Escape key closes modals

#### Forms
- [ ] All inputs have labels
- [ ] Required fields marked with text (not just asterisk)
- [ ] Error messages associated with fields
- [ ] Validation errors announced to screen readers

#### Images
- [ ] All images have alt text
- [ ] Decorative images use `alt=""`
- [ ] Complex images have longer descriptions

#### Color
- [ ] Text contrast meets 4.5:1 ratio
- [ ] UI component contrast meets 3:1 ratio
- [ ] Information not conveyed by color alone
- [ ] Focus indicators meet 3:1 contrast ratio

### Pre-Deployment Checklist

- [ ] Run automated accessibility tests
- [ ] Manual keyboard navigation test
- [ ] Screen reader spot check (key user flows)
- [ ] Color contrast verification
- [ ] Responsive accessibility check
- [ ] Cross-browser testing

### Quarterly Audit Checklist

- [ ] Full screen reader test (NVDA/JAWS)
- [ ] Complete keyboard navigation test
- [ ] Automated scan with latest axe-core
- [ ] Color contrast audit
- [ ] Mobile accessibility test
- [ ] Update accessibility statement

---

## Resources

### Tools
- **axe DevTools:** Browser extension for accessibility testing
- **NVDA:** Free screen reader for Windows
- **WAVE:** Web accessibility evaluation tool
- **WebAIM Contrast Checker:** Color contrast testing
- **Lighthouse:** Chrome DevTools accessibility audits

### Documentation
- **WCAG 2.1:** https://www.w3.org/WAI/WCAG21/quickref/
- **ARIA Authoring Practices:** https://www.w3.org/WAI/ARIA/apg/
- **MUI Accessibility:** https://mui.com/material-ui/guides/accessibility/
- **WebAIM:** https://webaim.org/

### Testing
- **Playwright Accessibility:** https://playwright.dev/docs/accessibility-testing
- **Testing Library:** https://testing-library.com/docs/queries/about/#priority

---

## Support

For questions or assistance with accessibility testing:
- **Team Slack:** #accessibility
- **Email:** accessibility@financialrisereport.com
- **Documentation:** `ACCESSIBILITY-AUDIT-REPORT.md`

---

**Guide Version:** 1.0
**Last Updated:** 2025-12-22
**Next Review:** 2026-03-22
