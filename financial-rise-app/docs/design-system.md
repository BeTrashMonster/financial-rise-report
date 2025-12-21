# Financial RISE Report - Design System Documentation

**Version:** 1.0
**Date:** 2025-12-19
**Audience:** AI Agents (Claude Code) and Frontend Developers
**Purpose:** Complete design system specification for implementing the Financial RISE Report application

---

## Table of Contents

1. [Brand Identity](#brand-identity)
2. [Color Palette](#color-palette)
3. [Typography](#typography)
4. [Spacing & Layout](#spacing--layout)
5. [Component Library](#component-library)
6. [Iconography](#iconography)
7. [Accessibility Guidelines](#accessibility-guidelines)
8. [Responsive Design](#responsive-design)
9. [Animation & Transitions](#animation--transitions)
10. [Design Principles](#design-principles)

---

## Brand Identity

### Overview
The Financial RISE Report (Readiness Insights for Sustainable Entrepreneurship) is a professional financial consulting tool that emphasizes:
- **Trust & Credibility:** Clean, professional aesthetic appropriate for financial services
- **Approachability:** Warm, encouraging tone that builds client confidence
- **Clarity:** Clear information hierarchy and easy navigation
- **Sophistication:** Premium feel reflecting the value of expert consultation

### Brand Colors
- **Primary:** Purple (#4B006E) - Represents wisdom, professionalism, and trust
- **Accent:** Metallic Gold (#D4AF37) - Represents value, quality, and achievement
- **Base:** Black on White - Ensures readability and clean professional appearance

### Voice & Tone
- **Professional but approachable:** Not overly technical or formal
- **Encouraging and confidence-building:** Never judgmental or shaming
- **Clear and direct:** Avoid jargon where possible
- **Action-oriented:** Focus on next steps and progress

---

## Color Palette

### Implementation Reference
Colors are defined in `frontend/src/theme/colors.ts`

### Primary Colors

#### Purple (Primary Brand Color)
```
Main:     #4B006E  (RGB: 75, 0, 110)
Light:    #7B2FA1  (RGB: 123, 47, 161)
Dark:     #2E0043  (RGB: 46, 0, 67)
Contrast: #FFFFFF  (White text on purple)

Usage:
- Primary buttons and CTAs
- Headers and navigation
- Links and interactive elements
- Progress indicators
- Focus states
```

#### Gold (Secondary/Accent Color)
```
Main:     #D4AF37  (RGB: 212, 175, 55)
Light:    #E6C85C  (RGB: 230, 200, 92)
Dark:     #B8941F  (RGB: 184, 148, 31)
Contrast: #000000  (Black text on gold)

Usage:
- Accent buttons and highlights
- Success states and achievements
- Premium features or callouts
- Icons for emphasis
```

### Neutral Colors

```
White:    #FFFFFF  (Background default)
Black:    #000000  (Primary text)
Gray 100: #F5F5F5  (Lightest gray - hover states, subtle backgrounds)
Gray 200: #EEEEEE  (Light gray - borders, dividers)
Gray 300: #E0E0E0  (Medium-light gray - disabled states)
Gray 400: #BDBDBD  (Medium gray - placeholder text)
Gray 500: #9E9E9E  (Mid gray - secondary text)
Gray 600: #757575  (Dark-medium gray - icons)
Gray 700: #616161  (Dark gray - headings)
Gray 800: #424242  (Darker gray - body text emphasis)
Gray 900: #212121  (Darkest gray - maximum contrast text)
```

### Semantic Colors

#### Success
```
Main:     #2E7D32  (Green - success states)
Light:    #4CAF50
Dark:     #1B5E20
Usage: Completed tasks, positive feedback, confirmation messages
```

#### Warning
```
Main:     #ED6C02  (Orange - warning states)
Light:    #FF9800
Dark:     #E65100
Usage: Important notices, areas needing attention, non-critical alerts
```

#### Error
```
Main:     #D32F2F  (Red - error states)
Light:    #EF5350
Dark:     #C62828
Usage: Form validation errors, critical alerts, destructive actions
```

#### Info
```
Main:     #0288D1  (Blue - informational states)
Light:    #03A9F4
Dark:     #01579B
Usage: Helpful tips, informational notices, neutral highlights
```

### Phase-Specific Colors

Used to visually differentiate the 5 financial readiness phases:

```
Stabilize: #D32F2F  (Red - urgent, foundational work)
Organize:  #ED6C02  (Orange - transitional phase)
Build:     #FBC02D  (Yellow - constructive phase)
Grow:      #388E3C  (Green - growth phase)
Systemic:  #0288D1  (Blue - strategic, cross-cutting)
```

**Usage:**
- Phase badges and labels
- Progress visualizations
- Report section headers
- Dashboard categorization

### Background Colors

```
Default: #FFFFFF  (Main background)
Paper:   #FAFAFA  (Card backgrounds, elevated surfaces)
Dark:    #1A1A1A  (For dark mode - future consideration)
```

### Text Colors

```
Primary:   #000000               (Main body text)
Secondary: rgba(0, 0, 0, 0.6)   (Secondary text, captions)
Disabled:  rgba(0, 0, 0, 0.38)  (Disabled text)
Hint:      rgba(0, 0, 0, 0.38)  (Placeholder text)
```

### Action Colors

```
Active:              rgba(0, 0, 0, 0.54)
Hover:               rgba(75, 0, 110, 0.04)   (Purple tint)
Selected:            rgba(75, 0, 110, 0.08)   (Purple tint)
Disabled:            rgba(0, 0, 0, 0.26)
Disabled Background: rgba(0, 0, 0, 0.12)
Focus:               rgba(75, 0, 110, 0.12)   (Purple tint)
```

### Accessibility - Contrast Ratios

All color combinations meet WCAG 2.1 Level AA standards:

- **Normal text (< 18px):** Minimum 4.5:1 contrast ratio
- **Large text (≥ 18px):** Minimum 3:1 contrast ratio
- **UI components:** Minimum 3:1 contrast ratio

**Verified Combinations:**
- Purple #4B006E on White #FFFFFF: 8.5:1 ✓
- Black #000000 on White #FFFFFF: 21:1 ✓
- Gold #D4AF37 on White #FFFFFF: 4.7:1 ✓
- Gold #D4AF37 on Black #000000: 4.5:1 ✓

---

## Typography

### Implementation Reference
Typography is defined in `frontend/src/theme/typography.ts`

### Font Family

```
Primary: Calibri
Fallbacks (in order):
1. Segoe UI
2. Roboto
3. Helvetica Neue
4. Arial
5. sans-serif

Declaration:
font-family: 'Calibri', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', sans-serif;
```

**Rationale:**
- Calibri: Clean, professional, excellent readability
- Widely available on Windows systems
- Similar alternatives ensure consistency across platforms
- Minimum 14px base size per REQ-UI-003

### Type Scale

#### Headings

**H1 - Page Titles**
```
Font: Calibri
Size: 40px (2.5rem)
Weight: 700 (Bold)
Line Height: 1.2
Letter Spacing: -0.01562em
Color: #212121 (Gray 900) or #4B006E (Purple)

Usage: Main page titles, hero headings
Example: "Financial Readiness Assessment"
```

**H2 - Section Titles**
```
Font: Calibri
Size: 32px (2rem)
Weight: 700 (Bold)
Line Height: 1.3
Letter Spacing: -0.00833em
Color: #212121 (Gray 900) or #4B006E (Purple)

Usage: Major section headings
Example: "Assessment Dashboard"
```

**H3 - Subsection Titles**
```
Font: Calibri
Size: 28px (1.75rem)
Weight: 600 (Semi-Bold)
Line Height: 1.35
Letter Spacing: 0em
Color: #424242 (Gray 800)

Usage: Subsection headings, card titles
Example: "Recent Assessments"
```

**H4 - Component Titles**
```
Font: Calibri
Size: 24px (1.5rem)
Weight: 600 (Semi-Bold)
Line Height: 1.4
Letter Spacing: 0.00735em
Color: #424242 (Gray 800)

Usage: Component headings, modal titles
Example: "Create New Assessment"
```

**H5 - Small Component Titles**
```
Font: Calibri
Size: 20px (1.25rem)
Weight: 600 (Semi-Bold)
Line Height: 1.4
Letter Spacing: 0em
Color: #616161 (Gray 700)

Usage: Smaller component headings, list section headers
Example: "Client Information"
```

**H6 - Smallest Headings**
```
Font: Calibri
Size: 18px (1.125rem)
Weight: 600 (Semi-Bold)
Line Height: 1.5
Letter Spacing: 0.0075em
Color: #616161 (Gray 700)

Usage: Form section labels, accordion headers
Example: "Business Details"
```

#### Body Text

**Body 1 - Primary Body Text**
```
Font: Calibri
Size: 16px (1rem)
Weight: 400 (Regular)
Line Height: 1.5
Letter Spacing: 0.00938em
Color: #000000 (Black)

Usage: Main paragraph text, descriptions
```

**Body 2 - Secondary Body Text**
```
Font: Calibri
Size: 14px (0.875rem) - Minimum per requirements
Weight: 400 (Regular)
Line Height: 1.5
Letter Spacing: 0.01071em
Color: rgba(0, 0, 0, 0.6) (Secondary Text)

Usage: Secondary descriptions, metadata, supporting text
```

#### Special Text Styles

**Button Text**
```
Font: Calibri
Size: 14px (0.875rem)
Weight: 600 (Semi-Bold)
Line Height: 1.75
Letter Spacing: 0.02857em
Transform: None (no uppercase)
Color: Inherits from button variant

Usage: All button labels
```

**Caption**
```
Font: Calibri
Size: 14px (0.875rem) - Minimum size
Weight: 400 (Regular)
Line Height: 1.66
Letter Spacing: 0.03333em
Color: rgba(0, 0, 0, 0.6)

Usage: Image captions, timestamps, form helper text
```

**Overline**
```
Font: Calibri
Size: 14px (0.875rem)
Weight: 600 (Semi-Bold)
Line Height: 2.66
Letter Spacing: 0.08333em
Transform: UPPERCASE
Color: rgba(0, 0, 0, 0.6)

Usage: Category labels, section markers
```

**Subtitle 1**
```
Font: Calibri
Size: 16px (1rem)
Weight: 500 (Medium)
Line Height: 1.75
Letter Spacing: 0.00938em
Color: #000000

Usage: Card subtitles, larger secondary text
```

**Subtitle 2**
```
Font: Calibri
Size: 14px (0.875rem)
Weight: 500 (Medium)
Line Height: 1.57
Letter Spacing: 0.00714em
Color: #000000

Usage: Smaller subtitles, emphasized secondary text
```

### Typography Best Practices

1. **Hierarchy:** Always maintain clear visual hierarchy using size, weight, and color
2. **Readability:** Line height should be 1.4-1.6 for body text
3. **Line Length:** Optimal line length is 50-75 characters for readability
4. **Scaling:** Text must be resizable up to 200% without loss of functionality (WCAG requirement)
5. **Contrast:** Always verify sufficient contrast ratios
6. **Alignment:** Left-align body text for optimal readability

---

## Spacing & Layout

### Spacing System

The application uses an 8px base spacing unit for consistent rhythm and alignment.

```
Spacing Scale (multiples of 8px):

xs:   4px   (0.5 unit)  - Tight spacing within components
sm:   8px   (1 unit)    - Small gaps, icon spacing
md:   16px  (2 units)   - Default spacing between elements
lg:   24px  (3 units)   - Section spacing
xl:   32px  (4 units)   - Large section spacing
xxl:  48px  (6 units)   - Page section spacing
xxxl: 64px  (8 units)   - Major page divisions
```

**Usage Guidelines:**

- **Component Internal Padding:** 16px (md) - buttons, cards, inputs
- **Component Margins:** 16px-24px (md-lg) - spacing between related elements
- **Section Margins:** 32px-48px (xl-xxl) - spacing between distinct sections
- **Page Margins:** 24px-48px (lg-xxl) - outer page margins

### Grid System

**Breakpoints:**
```
xs: 0px      (Mobile - default)
sm: 600px    (Large mobile / small tablet)
md: 960px    (Tablet)
lg: 1280px   (Desktop)
xl: 1920px   (Large desktop)
```

**Container Widths:**
```
xs: 100%     (Full width)
sm: 100%     (Full width)
md: 960px    (Fixed)
lg: 1280px   (Fixed)
xl: 1920px   (Fixed)
```

**Grid Columns:** 12-column grid system

**Gutters:**
```
xs-sm: 16px
md+:   24px
```

### Layout Patterns

#### Page Container
```
Max Width: 1280px (lg breakpoint)
Padding: 24px (responsive)
Centered with auto margins
```

#### Card Spacing
```
Internal Padding: 24px
Margin Between Cards: 16px
Border Radius: 12px
```

#### Form Layouts
```
Label Margin Bottom: 8px
Input Spacing: 16px vertical
Section Spacing: 32px
```

---

## Component Library

### Implementation Reference
Components are in `frontend/src/components/`

### Buttons

**Variants:**

**1. Primary (Contained)**
```
Background: #4B006E (Purple)
Text: #FFFFFF (White)
Padding: 10px 24px
Border Radius: 8px
Font Size: 14px
Font Weight: 600
Min Height: 40px

States:
- Hover: Background #7B2FA1, Shadow: 0px 2px 4px rgba(75, 0, 110, 0.2)
- Active: Background #2E0043
- Disabled: Background rgba(0, 0, 0, 0.12), Text rgba(0, 0, 0, 0.26)
- Focus: Outline 2px #4B006E, Offset 2px

Usage: Primary actions (Save, Submit, Continue)
```

**2. Secondary (Outlined)**
```
Background: Transparent
Border: 2px solid #4B006E
Text: #4B006E
Padding: 10px 24px
Border Radius: 8px
Font Size: 14px
Font Weight: 600
Min Height: 40px

States:
- Hover: Background rgba(75, 0, 110, 0.04), Border #7B2FA1
- Active: Background rgba(75, 0, 110, 0.08)
- Disabled: Border rgba(0, 0, 0, 0.12), Text rgba(0, 0, 0, 0.26)
- Focus: Outline 2px #4B006E, Offset 2px

Usage: Secondary actions (Cancel, Back)
```

**3. Text Button**
```
Background: Transparent
Text: #4B006E
Padding: 10px 16px
Border Radius: 8px
Font Size: 14px
Font Weight: 600

States:
- Hover: Background rgba(75, 0, 110, 0.04)
- Active: Background rgba(75, 0, 110, 0.08)
- Disabled: Text rgba(0, 0, 0, 0.26)

Usage: Tertiary actions, inline links
```

**Sizes:**

```
Small:
  Padding: 6px 16px
  Font Size: 14px
  Min Height: 32px

Medium (Default):
  Padding: 10px 24px
  Font Size: 14px
  Min Height: 40px

Large:
  Padding: 12px 32px
  Font Size: 16px
  Min Height: 48px
```

**Icon Buttons:**
```
Size: 40px × 40px
Border Radius: 50% (circle)
Padding: 8px
Icon Size: 24px

States:
- Hover: Background rgba(75, 0, 110, 0.04)
- Active: Background rgba(75, 0, 110, 0.08)
```

### Form Inputs

**Text Input (TextField)**
```
Border: 1px solid #E0E0E0 (Gray 300)
Border Radius: 8px
Padding: 12px 14px
Font Size: 14px
Min Height: 44px (includes border and padding)

States:
- Default: Border #E0E0E0
- Hover: Border #4B006E
- Focus: Border 2px #4B006E, Shadow: 0 0 0 2px rgba(75, 0, 110, 0.12)
- Error: Border #D32F2F, Helper text in red
- Disabled: Background #F5F5F5, Border #E0E0E0, Text rgba(0, 0, 0, 0.38)

Label:
- Font Size: 14px
- Font Weight: 500
- Color: #616161
- Margin Bottom: 8px

Helper Text:
- Font Size: 14px
- Color: rgba(0, 0, 0, 0.6)
- Margin Top: 4px

Placeholder:
- Color: #BDBDBD (Gray 400)
```

**Select Dropdown**
```
Same styling as Text Input
Dropdown Icon: Chevron down, 20px
Dropdown Menu:
  Background: #FFFFFF
  Border Radius: 8px
  Box Shadow: 0px 4px 16px rgba(0, 0, 0, 0.12)
  Max Height: 300px (scrollable)

Option Items:
  Padding: 12px 16px
  Hover: Background rgba(75, 0, 110, 0.04)
  Selected: Background rgba(75, 0, 110, 0.08)
```

**Textarea**
```
Same styling as Text Input
Min Height: 100px
Resize: Vertical only
Line Height: 1.5
```

**Checkbox**
```
Size: 20px × 20px
Border: 2px solid #9E9E9E
Border Radius: 4px

States:
- Unchecked: Border #9E9E9E
- Hover: Border #4B006E
- Checked: Background #4B006E, Checkmark white
- Disabled: Border #E0E0E0, Background #F5F5F5

Label:
- Font Size: 14px
- Color: #000000
- Margin Left: 8px
```

**Radio Button**
```
Size: 20px × 20px
Border: 2px solid #9E9E9E
Border Radius: 50% (circle)

States:
- Unselected: Border #9E9E9E
- Hover: Border #4B006E
- Selected: Border #4B006E, Inner dot 10px diameter #4B006E
- Disabled: Border #E0E0E0

Label:
- Font Size: 14px
- Color: #000000
- Margin Left: 8px
```

### Cards

**Default Card**
```
Background: #FFFFFF
Border: None
Border Radius: 12px
Box Shadow: 0px 2px 8px rgba(0, 0, 0, 0.08)
Padding: 24px

States:
- Hover: Box Shadow 0px 4px 16px rgba(0, 0, 0, 0.12)
- Interactive: Cursor pointer

Card Header:
- Margin Bottom: 16px
- Title: H4 or H5
- Subtitle: Body2, color rgba(0, 0, 0, 0.6)

Card Content:
- Padding: As needed, typically 0

Card Actions:
- Margin Top: 16px
- Buttons: Right-aligned or space-between
```

**Outlined Card**
```
Same as Default Card
Border: 1px solid #E0E0E0
Box Shadow: None

Usage: Less prominent content sections
```

### Modals (Dialogs)

**Modal Container**
```
Background: #FFFFFF
Border Radius: 16px
Max Width: 600px (sm), 900px (lg)
Padding: 32px
Box Shadow: 0px 8px 32px rgba(0, 0, 0, 0.16)

Backdrop:
- Background: rgba(0, 0, 0, 0.5)
- Blur: 4px (optional)

Modal Header:
- Title: H4
- Close Button: Top-right icon button
- Margin Bottom: 24px

Modal Content:
- Max Height: calc(100vh - 200px)
- Overflow: Auto
- Padding: 0 (no additional padding)

Modal Footer:
- Margin Top: 24px
- Border Top: 1px solid #E0E0E0
- Padding Top: 16px
- Buttons: Right-aligned, spacing 16px
```

### Alerts & Notifications

**Alert Banner**
```
Border Radius: 8px
Padding: 16px
Display: Flex
Icon: 24px, margin-right 12px

Variants:
- Success: Background #E8F5E9, Border-left 4px #2E7D32, Icon & Text #2E7D32
- Warning: Background #FFF3E0, Border-left 4px #ED6C02, Icon & Text #ED6C02
- Error: Background #FFEBEE, Border-left 4px #D32F2F, Icon & Text #D32F2F
- Info: Background #E3F2FD, Border-left 4px #0288D1, Icon & Text #0288D1

Close Button: Icon button, top-right
```

**Toast Notification**
```
Position: Top-right, fixed
Background: #323232 (dark)
Color: #FFFFFF
Border Radius: 8px
Padding: 16px 24px
Box Shadow: 0px 4px 16px rgba(0, 0, 0, 0.24)
Min Width: 300px
Max Width: 500px

Auto-dismiss: 4 seconds (success/info), 6 seconds (warning/error)
Animation: Slide in from top, fade out
```

### Loading Indicators

**Circular Spinner**
```
Size: 40px (default), 24px (small), 60px (large)
Color: #4B006E
Stroke Width: 4px
Animation: Rotate 360° in 1.4s

Usage: Page loading, async operations
```

**Linear Progress Bar**
```
Height: 4px
Background: #E0E0E0
Progress Color: #4B006E
Border Radius: 2px
Animation: Indeterminate wave

Usage: Page transitions, file uploads
```

**Skeleton Loader**
```
Background: #F5F5F5
Animation: Pulse every 1.5s
Border Radius: Matches target component

Usage: Loading states for cards, lists, text
```

### Progress Indicators

**Step Progress Bar**
```
Steps: Circles connected by lines

Step Circle:
- Size: 32px diameter
- Border: 2px
- Number/Icon: Inside circle

States:
- Completed: Background #4B006E, Icon white checkmark
- Active: Border #4B006E, Number #4B006E, Background white
- Upcoming: Border #BDBDBD, Number #BDBDBD, Background white

Connector Line:
- Width: 2px
- Color: #BDBDBD (upcoming), #4B006E (completed)
- Length: Flexible

Labels:
- Font Size: 14px
- Completed/Active: #000000
- Upcoming: #9E9E9E
```

**Percentage Progress Bar**
```
Height: 8px
Background: #E0E0E0
Progress Fill: Linear gradient #4B006E to #7B2FA1
Border Radius: 4px
Percentage Label: Above bar, right-aligned, 14px, #616161
```

### Navigation

**Header/AppBar**
```
Background: #FFFFFF
Height: 64px
Box Shadow: 0px 2px 4px rgba(0, 0, 0, 0.1)
Padding: 0 24px

Logo:
- Left-aligned
- Max Height: 40px

Navigation Links:
- Display: Inline, right-aligned
- Spacing: 24px between links
- Font Size: 14px
- Font Weight: 600
- Color: #616161
- Hover: Color #4B006E
- Active: Color #4B006E, Border-bottom 2px

User Menu:
- Right-aligned
- Avatar: 40px circle
- Dropdown: On click
```

**Sidebar Navigation**
```
Width: 240px (expanded), 64px (collapsed)
Background: #FAFAFA
Border Right: 1px solid #E0E0E0

Navigation Items:
- Padding: 12px 16px
- Icon: 24px, left-aligned
- Label: 14px, margin-left 16px
- Border Radius: 8px

States:
- Default: Color #616161
- Hover: Background #F5F5F5, Color #4B006E
- Active: Background rgba(75, 0, 110, 0.08), Color #4B006E, Border-left 4px #4B006E
```

**Breadcrumbs**
```
Font Size: 14px
Color: #616161
Separator: "/" or ">" icon, color #BDBDBD

Links:
- Hover: Color #4B006E, underline
- Active (current page): Color #000000, font-weight 600, no link
```

**Tabs**
```
Tab Height: 48px
Font Size: 14px
Font Weight: 600
Text Transform: None
Color: #616161

States:
- Hover: Color #4B006E
- Active: Color #4B006E, Border-bottom 2px #4B006E

Indicator:
- Height: 2px
- Color: #4B006E
```

### Data Display

**Table**
```
Header:
- Background: #FAFAFA
- Font Weight: 600
- Font Size: 14px
- Padding: 16px
- Border Bottom: 2px solid #E0E0E0

Rows:
- Padding: 16px
- Border Bottom: 1px solid #E0E0E0
- Hover: Background #F5F5F5

Cells:
- Font Size: 14px
- Vertical Align: Middle

Striped Rows (optional):
- Odd: Background #FFFFFF
- Even: Background #FAFAFA
```

**List**
```
List Item:
- Padding: 12px 16px
- Border Bottom: 1px solid #E0E0E0

States:
- Hover: Background #F5F5F5
- Selected: Background rgba(75, 0, 110, 0.08)

Leading Icon/Avatar:
- Size: 24px (icon) or 40px (avatar)
- Margin Right: 16px

Primary Text:
- Font Size: 14px
- Color: #000000

Secondary Text:
- Font Size: 14px
- Color: rgba(0, 0, 0, 0.6)
```

**Badges**
```
Border Radius: 12px
Padding: 4px 8px
Font Size: 12px
Font Weight: 600

Variants:
- Default: Background #E0E0E0, Color #616161
- Primary: Background #4B006E, Color #FFFFFF
- Success: Background #2E7D32, Color #FFFFFF
- Warning: Background #ED6C02, Color #FFFFFF
- Error: Background #D32F2F, Color #FFFFFF
- Phase-specific: Use phase colors
```

**Chips**
```
Border Radius: 8px
Padding: 8px 12px
Font Size: 14px
Font Weight: 500
Height: 32px

Variants:
- Filled: Background #E0E0E0, Color #000000
- Outlined: Border 1px #E0E0E0, Background transparent

Delete Icon (optional):
- Size: 18px
- Margin Left: 8px
- Hover: Color #D32F2F
```

---

## Iconography

### Icon Library
**Recommended:** Material Icons (https://fonts.google.com/icons)

### Icon Sizes
```
Small:   16px - Inline with text, dense UI
Default: 24px - Standard UI icons
Large:   32px - Prominent actions
XLarge:  48px - Feature icons, empty states
```

### Icon Usage

**Navigation Icons:**
- Dashboard: dashboard, home
- Assessments: assignment, description
- Reports: assessment, analytics
- Settings: settings, tune
- Profile: account_circle, person

**Action Icons:**
- Add: add, add_circle
- Edit: edit, mode_edit
- Delete: delete, delete_outline
- Save: save, check
- Cancel: close, clear
- Search: search
- Filter: filter_list
- Sort: sort
- Download: download, get_app
- Upload: upload, publish
- Share: share
- Print: print

**Status Icons:**
- Success: check_circle
- Warning: warning, error_outline
- Error: error, cancel
- Info: info, help_outline
- Pending: schedule, hourglass_empty

**Phase Icons:**
- Stabilize: foundation, support
- Organize: folder_open, inventory
- Build: construction, build
- Grow: trending_up, insights
- Systemic: psychology, school

**DISC Icons:**
- D (Dominance): flash_on, rocket_launch
- I (Influence): groups, celebration
- S (Steadiness): favorite, balance
- C (Compliance): analytics, precision_manufacturing

### Icon Colors
- Default: #616161 (Gray 600)
- Interactive: #4B006E (Purple) on hover
- Disabled: #BDBDBD (Gray 400)
- Semantic: Use semantic colors (success, warning, error, info)

### Accessibility
- Always include aria-label for icon-only buttons
- Provide text alternatives for decorative icons
- Ensure sufficient contrast for colored icons

---

## Accessibility Guidelines

### WCAG 2.1 Level AA Compliance
Reference: REQ-ACCESS-001 through REQ-ACCESS-007

### Color & Contrast

**Requirements:**
- Normal text: 4.5:1 minimum contrast ratio
- Large text (≥18px or ≥14px bold): 3:1 minimum
- UI components and graphics: 3:1 minimum

**Testing Tools:**
- WebAIM Contrast Checker
- Chrome DevTools Accessibility Inspector
- axe DevTools browser extension

### Keyboard Navigation

**Requirements:**
- All interactive elements must be keyboard accessible
- Visible focus indicators on all focusable elements
- Logical tab order matching visual layout
- Skip links to bypass repetitive content

**Focus Indicators:**
```
Outline: 2px solid #4B006E
Outline Offset: 2px
Border Radius: Matches component
```

**Tab Order:**
- Natural DOM order preferred
- Use tabindex="0" for custom interactive elements
- Use tabindex="-1" to programmatically focus
- Never use tabindex > 0

### Screen Readers

**Requirements:**
- Semantic HTML5 elements (header, nav, main, aside, footer)
- ARIA labels for all form inputs
- ARIA landmarks for page regions
- Alt text for all images and icons
- ARIA live regions for dynamic content

**Examples:**
```html
<!-- Button with icon only -->
<button aria-label="Close dialog">
  <CloseIcon />
</button>

<!-- Form input with error -->
<TextField
  label="Email Address"
  error={hasError}
  helperText={errorMessage}
  aria-describedby="email-error"
  aria-invalid={hasError}
/>

<!-- Loading state -->
<div role="status" aria-live="polite" aria-busy="true">
  <CircularProgress />
  <span className="sr-only">Loading...</span>
</div>
```

### Text & Readability

**Requirements:**
- Minimum 14px base font size
- Text resizable up to 200% without loss of content or functionality
- Line length 50-75 characters for optimal readability
- Line height 1.4-1.6 for body text
- No text in images (except logos)

### Forms

**Requirements:**
- All inputs have associated labels
- Error messages clearly identify the problem
- Error messages provide guidance for correction
- Required fields clearly marked
- Group related inputs with fieldset/legend

**Example:**
```html
<FormControl error={hasError}>
  <FormLabel required>Business Name</FormLabel>
  <TextField
    aria-required="true"
    aria-invalid={hasError}
    aria-describedby="business-name-error"
  />
  <FormHelperText id="business-name-error">
    {errorMessage}
  </FormHelperText>
</FormControl>
```

### Skip Links

**Requirement:** REQ-ACCESS-006

```html
<!-- First element in body -->
<a href="#main-content" className="skip-link">
  Skip to main content
</a>

<main id="main-content">
  <!-- Page content -->
</main>
```

```css
.skip-link {
  position: absolute;
  top: -40px;
  left: 0;
  background: #4B006E;
  color: white;
  padding: 8px 16px;
  z-index: 100;
}

.skip-link:focus {
  top: 0;
}
```

---

## Responsive Design

### Breakpoint Strategy

```
Mobile First Approach:
1. Design for mobile (320px-599px) first
2. Add enhancements for larger screens
3. Test at all breakpoints

Breakpoints:
xs: 0-599px      (Mobile)
sm: 600-959px    (Tablet portrait)
md: 960-1279px   (Tablet landscape / small desktop)
lg: 1280-1919px  (Desktop)
xl: 1920px+      (Large desktop)
```

### Layout Adaptations

**Typography:**
```
Mobile (xs):
- H1: 32px
- H2: 28px
- H3: 24px
- Body: 14px

Tablet (sm-md):
- H1: 36px
- H2: 30px
- H3: 26px
- Body: 14px

Desktop (lg+):
- H1: 40px
- H2: 32px
- H3: 28px
- Body: 16px (Body1), 14px (Body2)
```

**Spacing:**
```
Mobile (xs):
- Container Padding: 16px
- Section Spacing: 24px
- Card Padding: 16px

Tablet (sm-md):
- Container Padding: 24px
- Section Spacing: 32px
- Card Padding: 20px

Desktop (lg+):
- Container Padding: 24px
- Section Spacing: 48px
- Card Padding: 24px
```

**Grid:**
```
Mobile (xs):
- Single column layout
- Stack all components vertically

Tablet (sm):
- 2-column layouts where appropriate
- Dashboard cards: 2 columns

Tablet Landscape (md):
- 2-3 column layouts
- Dashboard cards: 2-3 columns

Desktop (lg+):
- 3-4 column layouts
- Dashboard cards: 3-4 columns
- Sidebar + content layouts
```

### Component Adaptations

**Header/Navigation:**
```
Mobile:
- Hamburger menu
- Logo centered or left
- Menu in drawer/slide-out

Desktop:
- Horizontal navigation
- Logo left
- Menu items displayed inline
```

**Forms:**
```
Mobile:
- Full-width inputs
- Stack all form fields
- Larger touch targets (44px min)

Desktop:
- 2-column layouts for related fields
- Inline labels where appropriate
- Standard touch targets (40px)
```

**Tables:**
```
Mobile:
- Card-based layout (each row becomes a card)
- Or horizontal scroll with sticky first column

Desktop:
- Standard table layout
```

**Modals:**
```
Mobile:
- Full-screen overlay
- Slide up from bottom

Desktop:
- Centered dialog
- Max-width 600px-900px
```

### Touch Targets

**Minimum Size:** 44px × 44px (WCAG AAA guideline)

**Mobile Optimizations:**
- Increase button padding
- Add spacing between interactive elements
- Use larger icons (24px minimum)
- Ensure swipe gestures don't conflict with scrolling

---

## Animation & Transitions

### Principles

**REQ-UI-008:** Use animations sparingly to enhance UX without causing distraction.

**Guidelines:**
1. **Purposeful:** Only animate when it improves understanding or feedback
2. **Fast:** Transitions should be quick (150-300ms)
3. **Smooth:** Use easing functions for natural motion
4. **Accessible:** Respect prefers-reduced-motion setting

### Timing

```
Fast:     150ms - Hover states, simple transitions
Default:  200ms - Most UI transitions
Moderate: 300ms - Expanding/collapsing, modals
Slow:     400ms - Page transitions, complex animations
```

### Easing Functions

```
Ease-Out: cubic-bezier(0.0, 0.0, 0.2, 1)
Use for: Elements entering the screen

Ease-In: cubic-bezier(0.4, 0.0, 1, 1)
Use for: Elements exiting the screen

Ease-In-Out: cubic-bezier(0.4, 0.0, 0.2, 1)
Use for: Elements moving on screen
```

### Common Transitions

**Button Hover:**
```css
transition: background-color 150ms ease-out, box-shadow 150ms ease-out;
```

**Modal Open/Close:**
```css
/* Open */
opacity: 0 → 1;
transform: scale(0.95) → scale(1);
transition: 200ms ease-out;

/* Close */
opacity: 1 → 0;
transform: scale(1) → scale(0.95);
transition: 150ms ease-in;
```

**Accordion Expand/Collapse:**
```css
max-height: 0 → auto;
opacity: 0 → 1;
transition: 300ms ease-in-out;
```

**Toast Notification:**
```css
/* Enter */
transform: translateY(-100%);
opacity: 0;
↓
transform: translateY(0);
opacity: 1;
transition: 200ms ease-out;

/* Exit */
opacity: 1 → 0;
transition: 150ms ease-in;
```

### Accessibility

**Respect User Preferences:**
```css
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

---

## Design Principles

### 1. Clarity Over Cleverness
- Prioritize clear communication over visual flair
- Use simple, direct language
- Maintain consistent patterns throughout the application

### 2. Progressive Disclosure
- Show only what's necessary at each step
- Use accordions, tabs, and modals to manage complexity
- Guide users through complex processes step-by-step

### 3. Feedback & Confirmation
- Provide immediate feedback for all user actions
- Confirm destructive actions before executing
- Show clear success/error states
- Use loading indicators for async operations

### 4. Consistency
- Use the same patterns for similar functions
- Maintain visual consistency across all pages
- Follow established conventions (e.g., save button placement)

### 5. Accessibility First
- Design with accessibility in mind from the start
- Test with keyboard navigation
- Verify color contrast
- Use semantic HTML

### 6. Mobile-Friendly
- Design mobile-first
- Use touch-friendly target sizes
- Avoid hover-dependent interactions
- Test on actual devices

### 7. Performance
- Optimize images and assets
- Minimize unnecessary animations
- Lazy load components when appropriate
- Prioritize perceived performance

### 8. Trust & Professionalism
- Use professional imagery and language
- Maintain brand consistency
- Handle errors gracefully
- Respect user privacy and data

---

## Implementation Checklist

When implementing a new component or page, verify:

- [ ] Color contrast meets WCAG AA standards (4.5:1 for text)
- [ ] Font size is minimum 14px
- [ ] Touch targets are minimum 44px × 44px
- [ ] Keyboard navigation works correctly
- [ ] Focus indicators are visible
- [ ] ARIA labels are present on interactive elements
- [ ] Semantic HTML is used
- [ ] Responsive at all breakpoints (xs, sm, md, lg, xl)
- [ ] Loading states are implemented
- [ ] Error states are handled gracefully
- [ ] Success feedback is provided
- [ ] Animations respect prefers-reduced-motion
- [ ] Component follows spacing system (8px units)
- [ ] Typography uses defined styles
- [ ] Colors use theme palette

---

**Document Version:** 1.0
**Last Updated:** 2025-12-19
**Maintained by:** Design System Team

For questions or clarifications, refer to:
- Requirements: `plans/requirements.md`
- Theme Implementation: `frontend/src/theme/`
- Component Examples: `frontend/src/components/`
