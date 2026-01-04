# Financial RISE Report - Design System

**Version:** 1.0
**Last Updated:** 2026-01-03

This document defines the design system for the Financial RISE Report application, ensuring consistent branding, accessibility, and user experience across all interfaces.

---

## Brand Guidelines

### Brand Colors

#### Primary - Purple
- **Main:** `#4B006E`
- **Light:** `#7B2FA1`
- **Dark:** `#2E0043`
- **Contrast Text:** `#FFFFFF`

**Usage:** Primary actions, navigation, headers, key UI elements

#### Secondary - Metallic Gold
- **Main:** `#D4AF37`
- **Light:** `#E6C85C`
- **Dark:** `#B8941F`
- **Contrast Text:** `#000000`

**Usage:** Accents, highlights, success states, premium features

#### Semantic Colors

**Success:**
- Main: `#2E7D32` (Dark Green)
- Light: `#4CAF50`
- Dark: `#1B5E20`

**Warning:**
- Main: `#ED6C02` (Orange)
- Light: `#FF9800`
- Dark: `#E65100`

**Error:**
- Main: `#D32F2F` (Red)
- Light: `#EF5350`
- Dark: `#C62828`

**Info:**
- Main: `#0288D1` (Blue)
- Light: `#03A9F4`
- Dark: `#01579B`

#### Phase-Specific Colors

For visual differentiation of financial readiness phases:

- **Stabilize:** `#D32F2F` (Red) - Urgent, foundational
- **Organize:** `#ED6C02` (Orange) - Transitional
- **Build:** `#FBC02D` (Yellow) - Constructive
- **Grow:** `#388E3C` (Green) - Growth
- **Systemic:** `#0288D1` (Blue) - Strategic

#### Neutral Colors

- **White:** `#FFFFFF`
- **Black:** `#000000`
- **Gray 100:** `#F5F5F5` (Lightest)
- **Gray 200:** `#EEEEEE`
- **Gray 300:** `#E0E0E0`
- **Gray 400:** `#BDBDBD`
- **Gray 500:** `#9E9E9E` (Medium)
- **Gray 600:** `#757575`
- **Gray 700:** `#616161`
- **Gray 800:** `#424242`
- **Gray 900:** `#212121` (Darkest)

---

## Typography

### Font Family
**Primary:** Calibri
**Fallbacks:** Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif

**REQ-UI-003:** Minimum font size is 14px for accessibility and readability.

### Type Scale

| Style | Size | Weight | Line Height | Use Case |
|-------|------|--------|-------------|----------|
| **h1** | 40px (2.5rem) | 700 | 1.2 | Page titles |
| **h2** | 32px (2rem) | 700 | 1.3 | Section headers |
| **h3** | 28px (1.75rem) | 600 | 1.35 | Subsection headers |
| **h4** | 24px (1.5rem) | 600 | 1.4 | Card titles |
| **h5** | 20px (1.25rem) | 600 | 1.4 | Component headers |
| **h6** | 18px (1.125rem) | 600 | 1.5 | Small headers |
| **body1** | 16px (1rem) | 400 | 1.5 | Primary body text |
| **body2** | 14px (0.875rem) | 400 | 1.5 | Secondary text (minimum size) |
| **button** | 14px (0.875rem) | 600 | 1.75 | Button labels |
| **caption** | 14px (0.875rem) | 400 | 1.66 | Helper text, captions |
| **overline** | 14px (0.875rem) | 600 | 2.66 | Labels, tags |

### Typography Usage

```tsx
import { Typography } from '@mui/material';

// Page title
<Typography variant="h1">Assessment Dashboard</Typography>

// Section header
<Typography variant="h2">Client Assessments</Typography>

// Body text
<Typography variant="body1">Standard paragraph text</Typography>

// Helper text
<Typography variant="body2" color="text.secondary">
  Optional description text
</Typography>
```

---

## Spacing System

**Base Unit:** 8px

The application uses an 8px grid system for consistent spacing. All spacing values are multiples of 8px.

| Token | Value | Usage |
|-------|-------|-------|
| `spacing(0.5)` | 4px | Tight spacing (icon-text) |
| `spacing(1)` | 8px | Minimal spacing |
| `spacing(2)` | 16px | Default element spacing |
| `spacing(3)` | 24px | Section spacing |
| `spacing(4)` | 32px | Large spacing |
| `spacing(6)` | 48px | Extra-large spacing |
| `spacing(8)` | 64px | Page-level spacing |

### Spacing Usage

```tsx
import { Box } from '@mui/material';

// Using spacing prop
<Box sx={{ padding: 2, marginBottom: 3 }}>
  {/* 16px padding, 24px margin bottom */}
</Box>

// Using theme spacing function
<Box sx={{ padding: (theme) => theme.spacing(2, 4) }}>
  {/* 16px vertical, 32px horizontal */}
</Box>
```

---

## Breakpoints

Responsive design breakpoints for different screen sizes:

| Breakpoint | Min Width | Usage |
|------------|-----------|-------|
| **xs** | 0px | Mobile phones (portrait) |
| **sm** | 600px | Mobile phones (landscape), small tablets |
| **md** | 960px | Tablets, small laptops |
| **lg** | 1280px | Desktops, large laptops |
| **xl** | 1920px | Large desktops, external monitors |

### Responsive Usage

```tsx
import { Box } from '@mui/material';

<Box
  sx={{
    padding: { xs: 2, sm: 3, md: 4 },  // 16px → 24px → 32px
    fontSize: { xs: '0.875rem', md: '1rem' },  // 14px → 16px
    display: { xs: 'block', md: 'flex' },  // Stack on mobile, row on desktop
  }}
>
  Responsive content
</Box>
```

---

## Component Library

### Button

Located at: `src/components/common/Button/Button.tsx`

**Features:**
- Loading state with spinner
- Three variants: contained, outlined, text
- Three sizes: small, medium, large
- ARIA attributes for accessibility

**Usage:**

```tsx
import { Button } from '@components/common/Button/Button';

// Primary action
<Button variant="contained" color="primary">
  Save Assessment
</Button>

// Secondary action
<Button variant="outlined" color="secondary">
  Cancel
</Button>

// With loading state
<Button variant="contained" loading={isSubmitting}>
  Submit
</Button>

// Sizes
<Button size="small">Small</Button>
<Button size="medium">Medium (default)</Button>
<Button size="large">Large</Button>
```

---

### Card

Located at: `src/components/common/Card/Card.tsx`

**Features:**
- Optional title and subtitle
- Header action slot
- Footer actions slot
- Dividers between sections
- No-padding mode for custom layouts

**Usage:**

```tsx
import { Card } from '@components/common/Card/Card';
import { Button } from '@components/common/Button/Button';

<Card
  title="Assessment Details"
  subtitle="Client: Acme Corp"
  headerAction={<Button size="small">Edit</Button>}
  actions={
    <>
      <Button variant="outlined">Cancel</Button>
      <Button variant="contained">Save</Button>
    </>
  }
  divider
>
  Card content goes here
</Card>
```

---

### Input

Located at: `src/components/common/Input/Input.tsx`

**Features:**
- Password toggle for password fields
- Error states with helper text
- ARIA attributes for screen readers
- Built on Material-UI TextField

**Usage:**

```tsx
import { Input } from '@components/common/Input/Input';

// Basic input
<Input
  id="client-name"
  label="Client Name"
  placeholder="Enter client name"
  required
/>

// Password input with toggle
<Input
  id="password"
  label="Password"
  type="password"
  showPasswordToggle
  required
/>

// With error
<Input
  id="email"
  label="Email"
  type="email"
  error={!!errors.email}
  helperText={errors.email?.message}
/>
```

---

### Modal

Located at: `src/components/common/Modal/Modal.tsx`

**Features:**
- Accessible dialog with ARIA labels
- Optional close button
- Footer actions
- Dividers between sections
- Responsive sizing

**Usage:**

```tsx
import { Modal } from '@components/common/Modal/Modal';
import { Button } from '@components/common/Button/Button';

<Modal
  open={isOpen}
  onClose={handleClose}
  title="Confirm Deletion"
  actions={
    <>
      <Button variant="outlined" onClick={handleClose}>
        Cancel
      </Button>
      <Button variant="contained" color="error" onClick={handleDelete}>
        Delete
      </Button>
    </>
  }
  maxWidth="sm"
  divider
>
  Are you sure you want to delete this assessment? This action cannot be undone.
</Modal>
```

---

## Layout Components

### Header

Located at: `src/components/layout/Header/Header.tsx`

Navigation header with logo, user menu, and logout functionality.

### Footer

Located at: `src/components/layout/Footer/Footer.tsx`

Footer with privacy links and copyright information.

### Layout

Located at: `src/components/layout/Layout/Layout.tsx`

Main layout wrapper that includes Header and Footer.

---

## Accessibility Guidelines

**WCAG 2.1 Level AA Compliance Required (REQ-ACCESS-001)**

### Color Contrast

All text must meet WCAG 2.1 AA contrast ratios:
- **Normal text (< 18px):** Minimum 4.5:1
- **Large text (≥ 18px):** Minimum 3:1
- **Interactive elements:** Minimum 3:1

Our brand colors meet these requirements:
- Purple `#4B006E` on White: 10.8:1 ✅
- Gold `#D4AF37` on Black: 8.5:1 ✅

### Keyboard Navigation

- All interactive elements must be keyboard accessible
- Focus indicators must be visible
- Logical tab order required
- Support Escape key for closing modals/dialogs

### Screen Reader Support

- All images require `alt` text
- Forms must have proper labels
- Error messages announced with `role="alert"`
- Loading states announced with `aria-live="polite"`

### Form Accessibility

```tsx
<Input
  id="email"
  label="Email Address"
  type="email"
  required
  error={!!errors.email}
  helperText={errors.email?.message}
  inputProps={{
    'aria-required': 'true',
    'aria-invalid': !!errors.email ? 'true' : 'false',
    'aria-describedby': errors.email ? 'email-error' : undefined,
  }}
/>
```

---

## Mobile-First Responsive Design

All components must be mobile-responsive by default (REQ-UI-001).

### Mobile Patterns

**Stack on mobile, row on desktop:**
```tsx
<Box sx={{ display: { xs: 'block', md: 'flex' }, gap: 2 }}>
  <Box sx={{ flex: 1 }}>Content 1</Box>
  <Box sx={{ flex: 1 }}>Content 2</Box>
</Box>
```

**Adaptive padding:**
```tsx
<Box sx={{ padding: { xs: 2, sm: 3, md: 4 } }}>
  Content with responsive padding
</Box>
```

**Responsive tables to cards:**
- Use Material-UI Table on desktop (≥ md)
- Use Card grid on mobile (< md)

---

## Theme Customization

### Accessing Theme Values

```tsx
import { useTheme } from '@mui/material/styles';

const MyComponent = () => {
  const theme = useTheme();

  return (
    <Box sx={{
      backgroundColor: theme.palette.primary.main,
      padding: theme.spacing(2),
      borderRadius: theme.shape.borderRadius,
    }}>
      Content
    </Box>
  );
};
```

### Custom Colors

```tsx
// Using phase colors
<Chip
  label="Stabilize"
  sx={{ backgroundColor: (theme) => theme.palette.phases.stabilize }}
/>

// Using neutral colors
<Box sx={{ backgroundColor: (theme) => theme.palette.neutral.gray100 }}>
  Background content
</Box>
```

---

## Best Practices

### 1. Consistency
- Always use theme values instead of hardcoded colors
- Use spacing function for margins/padding
- Leverage existing components before creating new ones

### 2. Performance
- Use `React.lazy()` for code splitting
- Memoize expensive computations
- Avoid inline function definitions in render

### 3. Accessibility
- Test with keyboard navigation
- Test with screen readers (NVDA/JAWS)
- Run Lighthouse accessibility audits
- Use axe DevTools for automated testing

### 4. Responsive Design
- Design mobile-first
- Test on multiple screen sizes (320px-1920px)
- Use responsive breakpoints consistently

### 5. Error Handling
- Provide clear error messages
- Show loading states for async operations
- Handle network errors gracefully

---

## Component Development Checklist

When creating new components:

- [ ] Uses theme colors (no hardcoded hex values)
- [ ] Uses theme spacing (no hardcoded px values)
- [ ] Responsive on all breakpoints
- [ ] ARIA attributes included
- [ ] Keyboard accessible
- [ ] Loading states implemented
- [ ] Error states implemented
- [ ] TypeScript types defined
- [ ] PropTypes or interface documented
- [ ] Component documented in this file

---

## Resources

### Theme Files
- **Colors:** `src/theme/colors.ts`
- **Typography:** `src/theme/typography.ts`
- **Theme:** `src/theme/theme.ts`

### Component Library
- **Common Components:** `src/components/common/`
- **Layout Components:** `src/components/layout/`

### Testing
- **Test Utilities:** `src/test/test-utils.tsx`
- **Accessibility Testing:** Use axe DevTools browser extension

### External Documentation
- [Material-UI Documentation](https://mui.com/)
- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [React Accessibility](https://react.dev/learn/accessibility)

---

**For questions or updates to the design system, contact the frontend development team.**
