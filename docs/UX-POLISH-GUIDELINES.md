# UX Polish Guidelines - Financial RISE

**Version:** 1.0
**Date:** 2025-12-22
**Phase:** Pre-Launch Polish (Dependency Level 5)

## Table of Contents

1. [Overview](#overview)
2. [Error Message Standards](#error-message-standards)
3. [Loading State Best Practices](#loading-state-best-practices)
4. [Navigation Refinements](#navigation-refinements)
5. [Form Improvements](#form-improvements)
6. [Responsive Design Checklist](#responsive-design-checklist)
7. [Accessibility Enhancements](#accessibility-enhancements)
8. [Micro-Interactions](#micro-interactions)
9. [Cross-Browser Testing](#cross-browser-testing)

---

## Overview

### Purpose

This document provides standards and guidelines for polishing the user experience before production launch, based on UAT feedback and best practices.

### Guiding Principles

1. **Clarity:** Users should always know what's happening
2. **Feedback:** System responds to user actions immediately
3. **Forgiveness:** Easy to undo mistakes
4. **Efficiency:** Minimize clicks and cognitive load
5. **Consistency:** Patterns repeat throughout the app

---

## Error Message Standards

### Error Message Anatomy

Every error message must include:
1. **What went wrong** (clear description)
2. **Why it happened** (if helpful)
3. **How to fix it** (actionable steps)
4. **Error code** (for support)

### Error Message Templates

**Validation Errors:**
```
❌ Invalid email address

The email you entered (example@) is not valid.

✓ Enter a valid email like name@company.com

Error Code: VAL-001
```

**Network Errors:**
```
❌ Connection lost

We couldn't reach the server. This might be due to:
- Slow internet connection
- Server maintenance

✓ Check your connection and try again in a moment

[Retry] button

Error Code: NET-001
```

**Permission Errors:**
```
❌ Access denied

You don't have permission to access this page.
Admin accounts are required for user management.

✓ Contact your admin or return to dashboard

[Go to Dashboard] button

Error Code: AUTH-403
```

**Resource Not Found:**
```
❌ Assessment not found

The assessment you're looking for doesn't exist or has been deleted.

✓ Return to your assessments list

[View All Assessments] button

Error Code: RES-404
```

### Error Tone Guidelines

**Do:**
- Use plain language (not technical jargon)
- Be helpful and empathetic
- Offer solutions, not just problems
- Use "we" and "you" (not "the system")

**Don't:**
- Blame the user ("You did this wrong")
- Use vague messages ("An error occurred")
- Use technical stack traces (show to devs only)
- Use all caps or excessive punctuation

### Inline Validation

**When to Validate:**
- onBlur (when user leaves field) - Preferred
- onSubmit (when form submitted) - Always
- onChange (as user types) - Only for password strength, username availability

**Validation Feedback:**
```tsx
// Good: Helpful inline validation
<TextField
  label="Email"
  error={!!emailError}
  helperText={emailError || "We'll never share your email"}
/>

// Bad: Vague error
<TextField
  label="Email"
  error={true}
  helperText="Invalid"
/>
```

### Success Messages

**Format:**
```
✅ Assessment created!

John's assessment has been created and an invitation email has been sent.

[View Assessment] [Create Another]
```

**Display:**
- Show for 5 seconds, then auto-dismiss
- Allow manual dismissal (X button)
- Position: Top-right toast

---

## Loading State Best Practices

### Loading Indicators by Duration

| Duration | Indicator Type | Example |
|----------|---------------|---------|
| <500ms | None | Quick API calls |
| 500ms-2s | Spinner | Form submission |
| 2s-5s | Progress bar | Report generation |
| >5s | Progress + estimated time | Large data export |

### Skeleton Loaders

**Use for:**
- Initial page load
- Card lists
- Data tables
- User profile

**Example:**
```tsx
// Assessment List Skeleton
<Grid container spacing={2}>
  {[1, 2, 3].map(i => (
    <Grid item xs={12} md={6} key={i}>
      <Card>
        <Skeleton variant="text" width="60%" height={30} />
        <Skeleton variant="text" width="40%" height={20} />
        <Skeleton variant="rectangular" height={100} />
      </Card>
    </Grid>
  ))}
</Grid>
```

### Progress Indicators

**For Long Operations:**

```tsx
// Report Generation Progress
<Box>
  <LinearProgress variant="determinate" value={progress} />
  <Typography variant="caption">
    Generating report... {progress}%
    {estimatedTime && ` (${estimatedTime}s remaining)`}
  </Typography>
  <Button onClick={handleCancel}>Cancel</Button>
</Box>
```

**States:**
- Indeterminate: Unknown duration
- Determinate: Known progress
- With time estimate: >5 seconds
- Cancelable: >10 seconds

### Loading State Standards

**API Calls:**
```tsx
const { data, loading, error } = useQuery(GET_ASSESSMENTS);

if (loading) return <AssessmentListSkeleton />;
if (error) return <ErrorState error={error} />;
return <AssessmentList data={data} />;
```

**Button Loading:**
```tsx
<Button
  onClick={handleSubmit}
  disabled={loading}
  startIcon={loading ? <CircularProgress size={20} /> : <SaveIcon />}
>
  {loading ? 'Saving...' : 'Save'}
</Button>
```

---

## Navigation Refinements

### Breadcrumb Navigation

**Use when:** Page depth >2 levels

**Format:**
```
Dashboard > Assessments > John's Assessment > Edit
```

**Implementation:**
```tsx
<Breadcrumbs>
  <Link to="/dashboard">Dashboard</Link>
  <Link to="/assessments">Assessments</Link>
  <Link to={`/assessments/${id}`}>John's Assessment</Link>
  <Typography color="text.primary">Edit</Typography>
</Breadcrumbs>
```

### Back Button Behavior

**Standard:**
- Browser back button works correctly
- In-app back button where expected
- Preserves scroll position
- Preserves form state (with warning)

**Warning for Unsaved Changes:**
```tsx
usePrompt(
  "You have unsaved changes. Are you sure you want to leave?",
  formHasChanges
);
```

### Keyboard Shortcuts

**Global Shortcuts:**
| Shortcut | Action |
|----------|--------|
| `/` | Focus search |
| `?` | Show keyboard shortcuts help |
| `Esc` | Close modal/drawer |
| `Ctrl/Cmd + K` | Quick command palette |

**Context Shortcuts:**
| Shortcut | Action | Context |
|----------|--------|---------|
| `N` | New assessment | Assessments list |
| `Ctrl/Cmd + S` | Save | Editing forms |
| `Ctrl/Cmd + Enter` | Submit | Forms |
| Arrow keys | Navigate list | Lists/tables |

**Shortcut Help Modal:**
```tsx
<Modal open={showShortcuts}>
  <Typography variant="h6">Keyboard Shortcuts</Typography>
  <List>
    <ListItem>
      <Kbd>/</Kbd>
      <Typography>Focus search</Typography>
    </ListItem>
    {/* ... */}
  </List>
</Modal>
```

### Tab Navigation

**Best Practices:**
- Tab order follows visual order
- Skip navigation link for keyboard users
- Focus visible indicator (outline)
- Focus trap in modals
- Auto-focus first field in forms

---

## Form Improvements

### Form Field Standards

**Labels:**
- Always visible (not placeholder-only)
- Clear and concise
- Required indicator (*) if needed

**Placeholders:**
- Show example, not instructions
- Example: "john@company.com" not "Enter your email"

**Help Text:**
- Below field
- Gray, smaller font
- Explains format or purpose

**Example:**
```tsx
<TextField
  label="Email *"
  placeholder="john@company.com"
  helperText="We'll send assessment invitations to this email"
  required
  fullWidth
/>
```

### Form Validation

**Real-Time Validation:**
```tsx
// Password strength indicator
<TextField
  type="password"
  label="Password"
  onChange={handlePasswordChange}
  helperText={
    <Box>
      <LinearProgress
        variant="determinate"
        value={strength}
        color={strengthColor}
      />
      <Typography variant="caption">
        {strengthText}
      </Typography>
    </Box>
  }
/>
```

**Validation Timing:**
- Required fields: onBlur
- Format validation: onBlur
- Uniqueness check: onBlur (debounced API call)
- Password strength: onChange
- Form-level validation: onSubmit

### Form Submission

**Submit Button States:**
1. **Default:** Enabled, "Create Assessment"
2. **Loading:** Disabled, spinner, "Creating..."
3. **Success:** Brief checkmark, then redirect
4. **Error:** Re-enable, show error message

**After Successful Submit:**
```tsx
// Option 1: Toast + redirect
showToast("Assessment created successfully!");
navigate(`/assessments/${newId}`);

// Option 2: Inline success + actions
<Alert severity="success">
  Assessment created!
  <Button onClick={() => navigate(`/assessments/${newId}`)}>
    View
  </Button>
  <Button onClick={handleCreateAnother}>
    Create Another
  </Button>
</Alert>
```

### Auto-Save

**Requirements:**
- Save every 60 seconds (if changed)
- Save on field blur (debounced)
- Show "Saving..." indicator
- Show "All changes saved" when done
- Maintain save state across page refresh

**Implementation:**
```tsx
const { save, status } = useAutoSave(formData, 60000);

// status: 'idle' | 'saving' | 'saved' | 'error'

<Box>
  {status === 'saving' && <Typography>Saving...</Typography>}
  {status === 'saved' && <Typography>✓ All changes saved</Typography>}
  {status === 'error' && <Typography>❌ Save failed</Typography>}
</Box>
```

---

## Responsive Design Checklist

### Breakpoints

```css
xs: 0px      /* Mobile portrait */
sm: 600px    /* Mobile landscape, small tablet */
md: 960px    /* Tablet */
lg: 1280px   /* Desktop */
xl: 1920px   /* Large desktop */
```

### Mobile-First Design

**Priorities for Mobile:**
1. Core actions easily accessible
2. Readable text (14px minimum)
3. Touch targets 44x44px minimum
4. Minimal horizontal scrolling
5. Optimized images

### Component Adaptations

**Navigation:**
- Desktop: Persistent sidebar
- Tablet: Collapsible sidebar
- Mobile: Bottom tab bar or hamburger menu

**Data Tables:**
- Desktop: Full table
- Tablet: Scrollable table
- Mobile: Card layout

**Forms:**
- Desktop: Multi-column layout
- Tablet: 2-column where appropriate
- Mobile: Single column

**Example Responsive Component:**
```tsx
<Grid container spacing={2}>
  <Grid item xs={12} sm={6} md={4}>
    <AssessmentCard />
  </Grid>
</Grid>

// xs: 1 per row (mobile)
// sm: 2 per row (tablet)
// md: 3 per row (desktop)
```

### Testing Matrix

| Device | Screen Size | Orientation | Browser |
|--------|-------------|-------------|---------|
| iPhone 12 | 390x844 | Portrait | Safari |
| iPhone 12 | 844x390 | Landscape | Safari |
| iPad Pro | 1024x1366 | Portrait | Safari |
| iPad Pro | 1366x1024 | Landscape | Safari |
| Pixel 5 | 393x851 | Portrait | Chrome |
| Desktop | 1920x1080 | Landscape | Chrome |
| Laptop | 1366x768 | Landscape | Chrome |

---

## Accessibility Enhancements

### ARIA Labels

**Interactive Elements:**
```tsx
// Icon buttons need labels
<IconButton aria-label="Delete assessment">
  <DeleteIcon />
</IconButton>

// Links need descriptive text
<Link aria-label="View John's assessment details">
  View Details
</Link>
```

### Focus Management

**Modal Focus Trap:**
```tsx
<Modal
  open={open}
  onClose={handleClose}
  aria-labelledby="modal-title"
>
  <FocusTrap>
    <Box>
      <Typography id="modal-title">Confirm Delete</Typography>
      {/* ... */}
    </Box>
  </FocusTrap>
</Modal>
```

**Skip to Main Content:**
```tsx
<a href="#main-content" className="skip-link">
  Skip to main content
</a>

<main id="main-content">
  {/* Page content */}
</main>
```

### Color Contrast

**WCAG 2.1 Level AA:**
- Normal text (14-18px): 4.5:1
- Large text (18px+ or 14px+ bold): 3:1
- UI components: 3:1

**Check Tool:** WebAIM Contrast Checker

### Keyboard Navigation

**Checklist:**
- [ ] All interactive elements reachable via Tab
- [ ] Tab order logical
- [ ] Focus indicator visible
- [ ] Enter/Space activates buttons
- [ ] Escape closes modals
- [ ] Arrow keys navigate lists

---

## Micro-Interactions

### Button Hover States

```css
button:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 8px rgba(0,0,0,0.15);
  transition: all 0.2s ease;
}
```

### Card Hover

```css
.card:hover {
  box-shadow: 0 8px 16px rgba(0,0,0,0.1);
  transform: translateY(-4px);
  transition: all 0.3s ease;
}
```

### Input Focus

```css
input:focus {
  outline: 2px solid #4B006E;
  outline-offset: 2px;
  transition: outline 0.2s ease;
}
```

### Loading Animations

**Fade In:**
```css
@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.fade-in {
  animation: fadeIn 0.3s ease;
}
```

**Slide Up:**
```css
@keyframes slideUp {
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

.slide-up {
  animation: slideUp 0.4s ease;
}
```

### Success Checkmark Animation

```tsx
<CheckCircleIcon
  sx={{
    fontSize: 48,
    color: 'success.main',
    animation: 'scaleIn 0.3s ease',
    '@keyframes scaleIn': {
      from: { transform: 'scale(0)' },
      to: { transform: 'scale(1)' },
    },
  }}
/>
```

---

## Cross-Browser Testing

### Browser Support Matrix

| Browser | Version | Support Level |
|---------|---------|---------------|
| Chrome | Latest 2 | Full support |
| Firefox | Latest 2 | Full support |
| Safari | Latest 2 | Full support |
| Edge | Latest 2 | Full support |
| Chrome (mobile) | Latest | Full support |
| Safari (mobile) | Latest | Full support |

### Common Issues & Fixes

**Issue: Flexbox gaps in Safari <14.1**
```css
/* Instead of gap */
.container {
  gap: 16px;
}

/* Use margin */
.container > * {
  margin: 8px;
}
```

**Issue: CSS Grid in IE11**
```css
/* Fallback for old browsers */
@supports not (display: grid) {
  .grid {
    display: flex;
    flex-wrap: wrap;
  }
}
```

**Issue: Date input in Firefox**
```tsx
// Use custom date picker library
import DatePicker from '@mui/x-date-pickers';

<DatePicker
  label="Assessment Date"
  value={date}
  onChange={setDate}
/>
```

### Testing Checklist

**Per Browser:**
- [ ] Login/logout works
- [ ] Create assessment works
- [ ] Complete assessment works
- [ ] Generate reports works
- [ ] All forms submit correctly
- [ ] Navigation works
- [ ] Responsive design correct
- [ ] No console errors

---

## UX Polish Checklist

### Final Pre-Launch Review

**Visual Polish:**
- [ ] Consistent spacing throughout app
- [ ] Consistent font sizes
- [ ] Consistent button styles
- [ ] Consistent colors (match brand guide)
- [ ] All icons same style (outlined vs filled)
- [ ] Loading states on all async actions
- [ ] Empty states designed (no data scenarios)

**Interactions:**
- [ ] Hover states on all clickable elements
- [ ] Focus states visible
- [ ] Smooth transitions (not jarring)
- [ ] Animations subtle and purposeful
- [ ] No layout shifts on load

**Copy:**
- [ ] No lorem ipsum text
- [ ] No developer placeholders
- [ ] Consistent voice and tone
- [ ] Error messages helpful
- [ ] Success messages celebratory

**Forms:**
- [ ] Labels always visible
- [ ] Required fields marked
- [ ] Helpful placeholder examples
- [ ] Inline validation on blur
- [ ] Error messages actionable
- [ ] Auto-save where appropriate
- [ ] Confirmation before destructive actions

**Navigation:**
- [ ] Breadcrumbs on deep pages
- [ ] Back button works correctly
- [ ] Current page highlighted in nav
- [ ] Logout easily accessible
- [ ] Logo links to home

**Performance:**
- [ ] Images optimized
- [ ] Code split by route
- [ ] Lazy loading implemented
- [ ] No unnecessary re-renders
- [ ] Smooth scrolling

**Accessibility:**
- [ ] WCAG 2.1 Level AA compliant
- [ ] Keyboard navigation works
- [ ] Screen reader friendly
- [ ] Color contrast sufficient
- [ ] ARIA labels on interactive elements

**Mobile:**
- [ ] Touch targets 44x44px minimum
- [ ] Text readable (14px+)
- [ ] No horizontal scroll
- [ ] Bottom navigation accessible
- [ ] Tested on real devices

---

**UX Polish Guidelines Version:** 1.0
**Owner:** Frontend Lead + UX Designer
**Last Updated:** 2025-12-22
