# Financial RISE Report - Wireframes & Screen Specifications

**Version:** 1.0
**Date:** 2025-12-19
**Audience:** AI Agents (Claude Code) and Frontend Developers
**Purpose:** Detailed wireframes and layout specifications for all application screens

---

## Table of Contents

1. [Authentication Screens](#authentication-screens)
2. [Dashboard](#dashboard)
3. [Assessment Workflow](#assessment-workflow)
4. [Reports](#reports)
5. [Admin Interface](#admin-interface)
6. [Common Layouts](#common-layouts)

---

## Authentication Screens

### 1.1 Login Page

**Route:** `/login`
**Layout:** Centered, no header/footer

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                     [RISE Logo - Purple]                    │
│                                                             │
│              Financial RISE Report                          │
│         Readiness Insights for Sustainable                  │
│                 Entrepreneurship                            │
│                                                             │
│    ┌─────────────────────────────────────────────┐        │
│    │                                             │        │
│    │  Email Address                              │        │
│    │  ┌───────────────────────────────────────┐ │        │
│    │  │ email@example.com                     │ │        │
│    │  └───────────────────────────────────────┘ │        │
│    │                                             │        │
│    │  Password                                   │        │
│    │  ┌───────────────────────────────────────┐ │        │
│    │  │ ••••••••••                            │ │        │
│    │  └───────────────────────────────────────┘ │        │
│    │                                             │        │
│    │  ☐ Remember me                              │        │
│    │                                             │        │
│    │  [    Sign In    ]                          │        │
│    │        (Purple button, full width)          │        │
│    │                                             │        │
│    │  Forgot Password?                           │        │
│    │                                             │        │
│    └─────────────────────────────────────────────┘        │
│                                                             │
│         Don't have an account? Contact Admin                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Container:**
- Max Width: 400px
- Centered vertically and horizontally
- Background: White card on light gray background (#FAFAFA)
- Card Padding: 48px 32px
- Card Border Radius: 16px
- Card Box Shadow: 0px 4px 16px rgba(0, 0, 0, 0.12)

**Logo:**
- Centered
- Max Width: 200px
- Margin Bottom: 32px

**Heading:**
- Font Size: 28px (H3)
- Font Weight: 700
- Color: #4B006E
- Text Align: Center
- Margin Bottom: 8px

**Subheading:**
- Font Size: 14px
- Color: rgba(0, 0, 0, 0.6)
- Text Align: Center
- Margin Bottom: 32px

**Form Fields:**
- Spacing: 24px between fields
- Input Width: 100%
- Input Height: 44px
- Labels: 14px, #616161, margin-bottom 8px

**Remember Me Checkbox:**
- Margin: 16px 0

**Sign In Button:**
- Full width
- Primary button style (purple)
- Height: 48px
- Margin Top: 24px

**Forgot Password Link:**
- Font Size: 14px
- Color: #4B006E
- Text Align: Center
- Margin Top: 16px

**Footer Text:**
- Font Size: 14px
- Color: rgba(0, 0, 0, 0.6)
- Text Align: Center
- Margin Top: 32px

**States:**
- Loading: Disable form, show spinner in button
- Error: Show alert banner above form
- Success: Redirect to dashboard

---

### 1.2 Forgot Password Page

**Route:** `/forgot-password`
**Layout:** Similar to Login

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                     [RISE Logo]                             │
│                                                             │
│                  Reset Your Password                        │
│                                                             │
│    Enter your email address and we'll send you             │
│    instructions to reset your password.                     │
│                                                             │
│    ┌─────────────────────────────────────────────┐        │
│    │                                             │        │
│    │  Email Address                              │        │
│    │  ┌───────────────────────────────────────┐ │        │
│    │  │ email@example.com                     │ │        │
│    │  └───────────────────────────────────────┘ │        │
│    │                                             │        │
│    │  [  Send Reset Instructions  ]              │        │
│    │                                             │        │
│    │  Back to Sign In                            │        │
│    │                                             │        │
│    └─────────────────────────────────────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Same container as Login
- Heading: "Reset Your Password"
- Description text: 14px, rgba(0, 0, 0, 0.6), centered
- Single email input
- Primary button: "Send Reset Instructions"
- Link: "Back to Sign In" → /login

**Success State:**
- Show success alert: "Check your email for reset instructions"
- Hide form, show confirmation message

---

### 1.3 Reset Password Page

**Route:** `/reset-password?token=xxx`
**Layout:** Similar to Login

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                     [RISE Logo]                             │
│                                                             │
│                  Create New Password                        │
│                                                             │
│    ┌─────────────────────────────────────────────┐        │
│    │                                             │        │
│    │  New Password                               │        │
│    │  ┌───────────────────────────────────────┐ │        │
│    │  │ ••••••••••                            │ │        │
│    │  └───────────────────────────────────────┘ │        │
│    │  Must be at least 12 characters             │        │
│    │                                             │        │
│    │  Confirm New Password                       │        │
│    │  ┌───────────────────────────────────────┐ │        │
│    │  │ ••••••••••                            │ │        │
│    │  └───────────────────────────────────────┘ │        │
│    │                                             │        │
│    │  [   Reset Password   ]                     │        │
│    │                                             │        │
│    └─────────────────────────────────────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Two password fields
- Helper text: "Must be at least 12 characters with uppercase, lowercase, number, and special character"
- Validation: Passwords must match
- On success: Redirect to login with success message

---

## Dashboard

### 2.1 Dashboard - Main View

**Route:** `/dashboard`
**Layout:** Header + Sidebar + Content

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Logo] Financial RISE Report           [User Avatar] John Doe ▼       │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
┌──────────────┬─────────────────────────────────────────────────────────┐
│              │                                                         │
│ ☰ Dashboard  │  Dashboard                                              │
│              │  ─────────────                                          │
│ 📋 Assessments│                                                        │
│              │  ┌─────────────────┐  ┌─────────────────┐              │
│ 📊 Reports    │  │  Total          │  │  In Progress    │              │
│              │  │  Assessments    │  │  Assessments    │              │
│ ⚙️ Settings   │  │                 │  │                 │              │
│              │  │      42         │  │       3         │              │
│              │  │                 │  │                 │              │
│              │  └─────────────────┘  └─────────────────┘              │
│              │                                                         │
│              │  ┌─────────────────┐  ┌─────────────────┐              │
│              │  │  Completed      │  │  This Month     │              │
│              │  │  This Month     │  │  Completed      │              │
│              │  │                 │  │                 │              │
│              │  │       8         │  │      12         │              │
│              │  │                 │  │                 │              │
│              │  └─────────────────┘  └─────────────────┘              │
│              │                                                         │
│              │  Recent Assessments           [+ New Assessment]        │
│              │  ────────────────────────────────────────────          │
│              │                                                         │
│              │  ┌──────────────────────────────────────────────────┐ │
│              │  │ Acme Corp - Jane Smith          In Progress      │ │
│              │  │ Started: Dec 15, 2025                            │ │
│              │  │ Progress: ████████░░░░░░░░ 60%                   │ │
│              │  │ [Continue] [Delete]                              │ │
│              │  └──────────────────────────────────────────────────┘ │
│              │                                                         │
│              │  ┌──────────────────────────────────────────────────┐ │
│              │  │ TechStart Inc - Mike Johnson    Completed ✓      │ │
│              │  │ Completed: Dec 18, 2025                          │ │
│              │  │ Phase: Organize | DISC: D                        │ │
│              │  │ [View Reports] [Regenerate]                      │ │
│              │  └──────────────────────────────────────────────────┘ │
│              │                                                         │
│              │  ┌──────────────────────────────────────────────────┐ │
│              │  │ Bakery LLC - Sarah Williams     Completed ✓      │ │
│              │  │ Completed: Dec 17, 2025                          │ │
│              │  │ Phase: Stabilize | DISC: S                       │ │
│              │  │ [View Reports] [Regenerate]                      │ │
│              │  └──────────────────────────────────────────────────┘ │
│              │                                                         │
│              │  [View All Assessments →]                               │
│              │                                                         │
└──────────────┴─────────────────────────────────────────────────────────┘
```

**Specifications:**

**Header (AppBar):**
- Height: 64px
- Background: #FFFFFF
- Box Shadow: 0px 2px 4px rgba(0, 0, 0, 0.1)
- Logo: Left, max height 40px
- User Menu: Right, avatar 40px circle
- Padding: 0 24px

**Sidebar:**
- Width: 240px (can collapse to 64px)
- Background: #FAFAFA
- Border Right: 1px solid #E0E0E0
- Navigation items: 48px height
- Active item: Purple background, left border

**Content Area:**
- Padding: 32px
- Background: #FFFFFF
- Max Width: 1280px

**Page Title:**
- Font: H2 (32px, bold)
- Color: #212121
- Margin Bottom: 32px

**Stats Cards (2x2 Grid):**
- Grid: 2 columns on desktop, 1 on mobile
- Gap: 16px
- Card Padding: 24px
- Card Border Radius: 12px
- Card Box Shadow: 0px 2px 8px rgba(0, 0, 0, 0.08)
- Stat Number: 48px, bold, purple
- Stat Label: 14px, gray

**Section Header:**
- Font: H4 (24px, semi-bold)
- Color: #424242
- Margin: 32px 0 16px
- Display: Flex, space-between
- Button: Primary, "New Assessment"

**Assessment List Items:**
- Card format
- Padding: 20px
- Margin Bottom: 16px
- Border Radius: 12px
- Box Shadow: 0px 2px 8px rgba(0, 0, 0, 0.08)
- Hover: Elevate shadow

**Assessment Card Content:**
- Line 1: Business Name - Client Name | Status Badge
- Line 2: Date (Started/Completed)
- Line 3: Progress bar OR Phase/DISC info
- Line 4: Action buttons

**Status Badges:**
- Draft: Gray background, gray text
- In Progress: Orange background, white text
- Completed: Green background, white text, checkmark icon

**Progress Bar:**
- Height: 8px
- Background: #E0E0E0
- Fill: Purple gradient
- Border Radius: 4px
- Percentage label: Right of bar

**Action Buttons:**
- Small size
- Spacing: 12px between buttons
- Primary actions: Purple outlined
- Destructive: Red text button

---

### 2.2 Dashboard - Empty State

**When no assessments exist:**

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│                    [Illustration]                          │
│                  (Empty state graphic)                     │
│                                                            │
│              No Assessments Yet                            │
│                                                            │
│    Get started by creating your first client               │
│    financial readiness assessment.                         │
│                                                            │
│              [+ Create First Assessment]                   │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Centered content
- Icon: 120px, purple
- Heading: H3, #212121
- Description: Body1, rgba(0, 0, 0, 0.6)
- Button: Large primary button
- Vertical spacing: 24px between elements

---

## Assessment Workflow

### 3.1 Create Assessment Modal

**Trigger:** Click "New Assessment" button
**Type:** Modal Dialog

```
┌─────────────────────────────────────────────────────────────┐
│ Create New Assessment                                   [X] │
│─────────────────────────────────────────────────────────────│
│                                                             │
│  Client Information                                         │
│  ──────────────────                                         │
│                                                             │
│  Client Name *                                              │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ John Doe                                              │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  Business Name *                                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ Acme Corporation                                      │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  Email Address *                                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ john@acmecorp.com                                     │ │
│  └───────────────────────────────────────────────────────┘ │
│  Report will be sent to this email                          │
│                                                             │
│  Phone (Optional)                                           │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ (555) 123-4567                                        │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│─────────────────────────────────────────────────────────────│
│                                      [Cancel] [Create]      │
└─────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Modal:**
- Max Width: 600px
- Padding: 32px
- Border Radius: 16px
- Box Shadow: 0px 8px 32px rgba(0, 0, 0, 0.16)

**Header:**
- Title: H4 (24px)
- Close button: Top-right icon button
- Border Bottom: 1px solid #E0E0E0
- Padding Bottom: 16px
- Margin Bottom: 24px

**Form Fields:**
- Spacing: 24px between fields
- Required indicator: Red asterisk
- Label: 14px, #616161, margin-bottom 8px
- Input: Full width, 44px height
- Helper text: 14px, rgba(0, 0, 0, 0.6), margin-top 4px

**Footer:**
- Border Top: 1px solid #E0E0E0
- Padding Top: 16px
- Margin Top: 24px
- Buttons: Right-aligned
- Cancel: Text button
- Create: Primary button
- Spacing: 16px between buttons

**Validation:**
- Required fields: Show error if empty on submit
- Email: Validate format
- On success: Close modal, navigate to assessment

---

### 3.2 Assessment Questionnaire

**Route:** `/assessments/:id`
**Layout:** Full-width, centered questionnaire

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Logo] Financial RISE Report                               [Save & Exit]│
└────────────────────────────────────────────────────────────────────────┘
│                                                                        │
│  Acme Corporation - John Doe                                           │
│  ──────────────────────────────                                        │
│                                                                        │
│  Progress: ████████████░░░░░░░░░░░░ 45% (18 of 40 questions)          │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                                                                  │ │
│  │  Section 1: Stabilize - Financial Foundation                     │ │
│  │  ─────────────────────────────────────────────                  │ │
│  │                                                                  │ │
│  │  Question 8 of 10                                                │ │
│  │                                                                  │ │
│  │  How confident do you feel about your current                    │ │
│  │  accounting processes?                                           │ │
│  │                                                                  │ │
│  │  ⚪ Very Confident                                               │ │
│  │  ⚪ Somewhat Confident                                           │ │
│  │  ◉ Neutral                                                       │ │
│  │  ⚪ Somewhat Uncertain                                           │ │
│  │  ⚪ Very Uncertain                                               │ │
│  │  ☐ Not Applicable                                                │ │
│  │                                                                  │ │
│  │  Consultant Notes (Optional)                                     │ │
│  │  ┌────────────────────────────────────────────────────────────┐ │ │
│  │  │ Client mentioned they use QuickBooks but don't              │ │
│  │  │ reconcile monthly...                                        │ │
│  │  └────────────────────────────────────────────────────────────┘ │ │
│  │                                                                  │ │
│  │  Last saved: 2 minutes ago                                       │ │
│  │                                                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  [← Previous Question]              [Next Question →]                  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Header:**
- Simplified header with logo and "Save & Exit" button
- Background: White
- Border Bottom: 1px solid #E0E0E0

**Assessment Header:**
- Business Name - Client Name: H4, #212121
- Margin Bottom: 16px

**Progress Bar:**
- Full width
- Height: 8px
- Background: #E0E0E0
- Fill: Purple
- Percentage and count: 14px, above bar
- Margin Bottom: 32px

**Question Card:**
- Max Width: 800px
- Centered
- Padding: 32px
- Border Radius: 12px
- Box Shadow: 0px 4px 16px rgba(0, 0, 0, 0.12)
- Background: White

**Section Header:**
- Font: H5 (20px), semi-bold
- Color: Purple for Stabilize phase
- Border Bottom: 2px solid (phase color)
- Padding Bottom: 8px
- Margin Bottom: 24px

**Question Number:**
- Font: 14px
- Color: rgba(0, 0, 0, 0.6)
- Margin Bottom: 16px

**Question Text:**
- Font: H5 or H6 (18-20px)
- Color: #000000
- Line Height: 1.5
- Margin Bottom: 24px

**Answer Options:**

*Radio Buttons:*
- Size: 20px
- Spacing: 16px vertical between options
- Label: 16px, clickable
- Selected: Purple fill

*Checkboxes:*
- Same as radio for multiple choice

*Rating Scale:*
- 5 or 10 point scale
- Display as radio buttons or slider
- Labels at extremes

*Text Input:*
- Full width
- Min height: 100px for textarea
- Border: 1px solid #E0E0E0
- Border Radius: 8px

**Not Applicable:**
- Checkbox below answer options
- 14px font
- Lighter color
- When checked, disable answer options

**Consultant Notes:**
- Label: 14px, margin-top 24px
- Textarea: Full width, 100px min height
- Placeholder: "Add private notes (only visible in consultant report)"
- Background: #FAFAFA (subtle distinction)

**Auto-save Indicator:**
- Font: 12px
- Color: rgba(0, 0, 0, 0.6)
- Icon: Green checkmark
- Position: Bottom of card
- Message: "Last saved: X minutes ago" or "Saving..."

**Navigation Buttons:**
- Bottom of page
- Left: "Previous Question" (outlined)
- Right: "Next Question" (primary)
- On last question: "Review & Submit" (primary)
- Spacing: Auto (space-between)

**Responsive:**
- Mobile: Stack buttons, full width
- Reduce card padding to 20px

---

### 3.3 Assessment Review & Submit

**Route:** `/assessments/:id/review`
**Layout:** Scrollable review page

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Logo] Financial RISE Report                               [Save & Exit]│
└────────────────────────────────────────────────────────────────────────┘
│                                                                        │
│  Review Your Assessment                                                │
│  ──────────────────────────                                            │
│                                                                        │
│  Acme Corporation - John Doe                                           │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  Assessment Summary                                              │ │
│  │  ──────────────────                                              │ │
│  │                                                                  │ │
│  │  Total Questions: 40                                             │ │
│  │  Answered: 38                                                    │ │
│  │  Marked N/A: 2                                                   │ │
│  │  Unanswered: 0                                                   │ │
│  │                                                                  │ │
│  │  ✓ All required questions answered                               │ │
│  │                                                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  Section Summary                                                       │
│  ────────────────                                                      │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  ▼ Section 1: Stabilize (8/10 answered, 2 N/A)          [Edit] │ │
│  │  ──────────────────────────────────────────────────────         │ │
│  │  Q1: How often do you reconcile...                      ✓       │ │
│  │  Q2: Do you have a dedicated...                         ✓       │ │
│  │  Q3: Are your financial records...                      ✓       │ │
│  │  [Show 5 more...]                                                │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  ► Section 2: Organize (10/10 answered)                 [Edit]  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  ► Section 3: Build (10/10 answered)                    [Edit]  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  ► Section 4: Grow (8/8 answered)                       [Edit]  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  ► Section 5: Systemic (2/2 answered)                   [Edit]  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  [← Back to Questions]                    [Submit Assessment →]        │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Page Title:**
- H2 (32px), #212121
- Margin Bottom: 8px

**Client Info:**
- Font: 16px
- Color: rgba(0, 0, 0, 0.6)
- Margin Bottom: 32px

**Summary Card:**
- Background: #F5F5F5 (light gray)
- Border Left: 4px solid #4B006E
- Padding: 24px
- Border Radius: 8px
- Margin Bottom: 32px

**Summary Stats:**
- Line height: 1.8
- Font: 14px
- Stats label: Bold
- Completeness check: Green text with checkmark icon

**Section Summary Cards:**
- Accordion style
- Header: Clickable to expand/collapse
- Arrow icon: Changes direction on expand
- Section title: H6 (18px), semi-bold
- Question count: 14px, rgba(0, 0, 0, 0.6)
- Edit button: Small text button, right-aligned
- Margin Bottom: 12px between sections

**Expanded Section:**
- Show list of questions with checkmarks
- Truncate long questions
- "Show X more..." link if > 3 questions
- Clicking question navigates to that question

**Navigation Buttons:**
- Bottom of page
- Left: "Back to Questions" (outlined)
- Right: "Submit Assessment" (primary, large)
- Spacing: Space-between

**Submit Confirmation:**
- Show modal dialog before submitting
- Confirm action
- Explain what happens next (reports generated)

---

### 3.4 Assessment Complete / Reports Ready

**Route:** `/assessments/:id/complete`
**Layout:** Success page

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Logo] Financial RISE Report                          [Back to Dashboard]│
└────────────────────────────────────────────────────────────────────────┘
│                                                                        │
│                                                                        │
│                        ✓ Assessment Complete!                          │
│                                                                        │
│               Your reports have been generated successfully.            │
│                                                                        │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                                                                  │ │
│  │  Acme Corporation - John Doe                                     │ │
│  │  Completed: December 19, 2025 at 2:30 PM                         │ │
│  │                                                                  │ │
│  │  Primary Phase: Organize                                         │ │
│  │  DISC Profile: D (Dominance)                                     │ │
│  │                                                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  Available Reports                                                     │
│  ────────────────                                                      │
│                                                                        │
│  ┌────────────────────────────────┐  ┌────────────────────────────┐  │
│  │  📄 Consultant Report          │  │  📄 Client Report          │  │
│  │                                │  │                            │  │
│  │  Internal report with DISC     │  │  Client-facing report      │  │
│  │  analysis and communication    │  │  with roadmap and quick    │  │
│  │  strategies.                   │  │  wins.                     │  │
│  │                                │  │                            │  │
│  │  [View Report] [Download PDF]  │  │  [View Report] [Download]  │  │
│  │                                │  │  [Email Client]            │  │
│  └────────────────────────────────┘  └────────────────────────────┘  │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │  Next Steps                                                      │ │
│  │  ──────────                                                      │ │
│  │  • Review the consultant report to understand the client's       │ │
│  │    personality profile and communication preferences             │ │
│  │  • Share the client report via email or download as PDF          │ │
│  │  • Schedule a follow-up meeting to discuss the findings          │ │
│  │  • Create a customized action plan based on the                  │ │
│  │    recommendations                                               │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│                      [Return to Dashboard]                             │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Success Header:**
- Icon: Large checkmark (60px), green
- Centered
- Heading: H2 (32px), #2E7D32 (success green)
- Subheading: 16px, rgba(0, 0, 0, 0.6)
- Vertical spacing: 16px
- Margin Bottom: 48px

**Assessment Summary Card:**
- Background: #F5F5F5
- Padding: 24px
- Border Radius: 12px
- Border Left: 4px solid (phase color - orange for Organize)
- Max Width: 600px
- Centered
- Margin Bottom: 32px

**Report Cards (Side by Side):**
- Grid: 2 columns on desktop, 1 on mobile
- Gap: 24px
- Card Padding: 24px
- Card Border Radius: 12px
- Card Box Shadow: 0px 2px 8px rgba(0, 0, 0, 0.08)
- Icon: 48px, purple
- Title: H5 (20px), semi-bold
- Description: 14px, rgba(0, 0, 0, 0.6)
- Buttons: Stacked, full width, spacing 12px

**Next Steps Card:**
- Background: #E3F2FD (light info blue)
- Border Left: 4px solid #0288D1
- Padding: 24px
- Border Radius: 8px
- Title: H6 (18px), semi-bold
- List: Bullet points, 14px, line-height 1.8
- Margin Top: 32px

**Return Button:**
- Centered
- Text button
- Margin Top: 24px

---

## Reports

### 4.1 Consultant Report View

**Route:** `/reports/:id/consultant`
**Layout:** Full-width document view

```
┌────────────────────────────────────────────────────────────────────────┐
│ [← Back]    Consultant Report - Acme Corp        [Download PDF] [Email]│
└────────────────────────────────────────────────────────────────────────┘
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                                                                  │ │
│  │                   CONSULTANT REPORT                              │ │
│  │                   Financial RISE Assessment                      │ │
│  │                                                                  │ │
│  │                   Acme Corporation                               │ │
│  │                   Prepared for: John Doe, Consultant             │ │
│  │                   Date: December 19, 2025                        │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Executive Summary                                               │ │
│  │  ─────────────────                                               │ │
│  │                                                                  │ │
│  │  Primary Phase: Organize                                         │ │
│  │  Client has established basic accounting processes but           │ │
│  │  lacks integration and systematic workflows...                   │ │
│  │                                                                  │ │
│  │  DISC Profile: D (Dominance) - High                              │ │
│  │  Communication Strategy: Direct, results-focused,                │ │
│  │  emphasize ROI and efficiency gains...                           │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  DISC Personality Analysis                                       │ │
│  │  ─────────────────────────                                       │ │
│  │                                                                  │ │
│  │  D (Dominance):      ████████████████░░ 85%                      │ │
│  │  I (Influence):      ██████░░░░░░░░░░ 40%                        │ │
│  │  S (Steadiness):     ████░░░░░░░░░░░░ 25%                        │ │
│  │  C (Compliance):     ██████████░░░░░░ 55%                        │ │
│  │                                                                  │ │
│  │  Profile Interpretation:                                         │ │
│  │  This client exhibits strong Dominance traits, indicating       │ │
│  │  they are results-oriented, direct, and decisive...              │ │
│  │                                                                  │ │
│  │  Communication Recommendations:                                  │ │
│  │  • Be direct and concise - avoid excessive details              │ │
│  │  • Focus on results and ROI                                      │ │
│  │  • Present options with clear pros/cons                          │ │
│  │  • Move quickly through implementation                           │ │
│  │  • Emphasize control and autonomy                                │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Financial Readiness Phase Assessment                            │ │
│  │  ────────────────────────────────────                            │ │
│  │                                                                  │ │
│  │  [Stabilize] ──── [ORGANIZE] ──── [Build] ──── [Grow]           │ │
│  │                       ▲                                          │ │
│  │                   Current Focus                                  │ │
│  │                                                                  │ │
│  │  Phase Scores:                                                   │ │
│  │  • Stabilize:  ████████████░░ 70% - Mostly complete              │ │
│  │  • Organize:   ██████░░░░░░░░ 45% - Primary focus                │ │
│  │  • Build:      ████░░░░░░░░░░ 25% - Future work                  │ │
│  │  • Grow:       ██░░░░░░░░░░░░ 15% - Not ready                    │ │
│  │                                                                  │ │
│  │  Recommended Starting Point: Chart of Accounts                   │ │
│  │  Restructuring and System Integration                            │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Priority Action Items                                           │ │
│  │  ────────────────────                                            │ │
│  │                                                                  │ │
│  │  1. Chart of Accounts Cleanup (HIGH PRIORITY)                    │ │
│  │     • Current COA is disorganized with duplicate accounts        │ │
│  │     • Recommend full restructure following industry standards    │ │
│  │     • Estimated effort: 4-6 hours                                │ │
│  │     • ROI: Improved reporting accuracy, faster month-end         │ │
│  │                                                                  │ │
│  │  2. Integrate Inventory Management (MEDIUM PRIORITY)             │ │
│  │     • Currently tracking inventory in spreadsheets               │ │
│  │     • Recommend integration with accounting system               │ │
│  │     • Estimated effort: 8-10 hours                               │ │
│  │                                                                  │ │
│  │  [Continue with more items...]                                   │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Areas of Concern                                                │ │
│  │  ────────────────                                                │ │
│  │                                                                  │ │
│  │  ⚠️ S-Corp Payroll Compliance                                   │ │
│  │  Client is structured as S-Corp but not on payroll. This         │ │
│  │  creates significant tax compliance risk...                      │ │
│  │                                                                  │ │
│  │  ⚠️ No Monthly Reconciliation                                   │ │
│  │  Bank accounts not reconciled in 4+ months...                    │ │
│  │                                                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
│  [Detailed Response Summary - Click to Expand]                        │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Header:**
- Back button: Left
- Title: H3 (28px), centered or left
- Actions: Right (Download PDF, Email)
- Background: White
- Border Bottom: 1px solid #E0E0E0
- Padding: 16px 24px

**Report Container:**
- Max Width: 900px
- Centered
- Background: White
- Padding: 48px
- Box Shadow: 0px 2px 8px rgba(0, 0, 0, 0.08)
- Print-friendly styles

**Report Header:**
- Centered
- Purple branding
- Logo at top
- Title: H2
- Client info: 14px
- Border Bottom: 2px solid #4B006E
- Padding Bottom: 24px
- Margin Bottom: 32px

**Section Headings:**
- H4 or H5
- Color: #4B006E
- Border Bottom: 1px solid #E0E0E0
- Padding Bottom: 8px
- Margin: 32px 0 16px

**DISC Bars:**
- Horizontal bars
- Height: 24px
- Border Radius: 4px
- Background: #E0E0E0
- Fill: Purple gradient
- Label: Left, 14px, semi-bold
- Percentage: Right, 14px
- Spacing: 12px between bars

**Phase Journey Visual:**
- Horizontal timeline
- Circles for each phase
- Active phase: Filled, larger, with arrow
- Line connecting phases
- Labels below circles
- Use phase colors

**Phase Scores:**
- Similar to DISC bars
- Use phase-specific colors
- Include text labels (Complete, Primary focus, Future work, Not ready)

**Action Items:**
- Numbered list
- Title: Semi-bold, 16px
- Priority badge: Color-coded (High=red, Medium=orange, Low=blue)
- Bullet points for details
- Indented content
- Spacing: 24px between items

**Areas of Concern:**
- Warning icon (yellow/red)
- Background: Light yellow (#FFF3E0)
- Border Left: 4px solid #ED6C02
- Padding: 16px
- Border Radius: 8px
- Spacing: 16px between items

**Collapsible Sections:**
- Accordion style
- Click to expand/collapse
- Arrow icon indicator
- Detailed response data hidden by default

**Print Styles:**
- Remove interactive elements
- Expand all sections
- Page breaks at section boundaries
- Header/footer with page numbers

---

### 4.2 Client Report View

**Route:** `/reports/:id/client`
**Layout:** Similar to Consultant Report but client-friendly language

```
┌────────────────────────────────────────────────────────────────────────┐
│ [← Back]    Client Report - Acme Corp           [Download PDF] [Email] │
└────────────────────────────────────────────────────────────────────────┘
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐ │
│  │                                                                  │ │
│  │              YOUR FINANCIAL READINESS REPORT                     │ │
│  │                   Financial RISE Assessment                      │ │
│  │                                                                  │ │
│  │                   Acme Corporation                               │ │
│  │                   Prepared for: Jane Smith, Owner                │ │
│  │                   Date: December 19, 2025                        │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Welcome!                                                        │ │
│  │  ────────                                                        │ │
│  │                                                                  │ │
│  │  Thank you for completing your Financial Readiness               │ │
│  │  Assessment. This report provides a personalized roadmap         │ │
│  │  for strengthening your business finances and building           │ │
│  │  confidence in your financial management.                        │ │
│  │                                                                  │ │
│  │  Your honest answers help us create a plan that's right          │ │
│  │  for where you are today and where you want to go.               │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Your Financial Journey                                          │ │
│  │  ──────────────────────                                          │ │
│  │                                                                  │ │
│  │  [Stabilize] ──── [ORGANIZE] ──── [Build] ──── [Grow]           │ │
│  │                       ▲                                          │ │
│  │                   You Are Here                                   │ │
│  │                                                                  │ │
│  │  Based on your assessment, you're in the Organize phase.         │ │
│  │  This means you've done great work establishing your             │ │
│  │  financial foundation, and now it's time to create systems       │ │
│  │  that make managing your finances easier and more efficient.     │ │
│  │                                                                  │ │
│  │  What This Means:                                                │ │
│  │  • Your basic accounting processes are in place ✓                │ │
│  │  • You're ready to integrate and streamline your systems         │ │
│  │  • Small improvements will have big impacts on efficiency        │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Quick Wins - Start Here!                                        │ │
│  │  ────────────────────────                                        │ │
│  │                                                                  │ │
│  │  These are the highest-impact actions you can take right         │ │
│  │  now to improve your financial health:                           │ │
│  │                                                                  │ │
│  │  1. ✓ Monthly Bank Reconciliation                               │ │
│  │     Why it matters: Catch errors early and know your true        │ │
│  │     cash position.                                               │ │
│  │     Next step: Block 30 minutes at the end of each month         │ │
│  │     to reconcile all accounts.                                   │ │
│  │                                                                  │ │
│  │  2. ✓ Clean Up Your Chart of Accounts                           │ │
│  │     Why it matters: Better organization = better insights        │ │
│  │     into where your money is going.                              │ │
│  │     Next step: Schedule time with your accountant to             │ │
│  │     review and restructure.                                      │ │
│  │                                                                  │ │
│  │  3. ✓ Connect Your Systems                                       │ │
│  │     Why it matters: Save time and reduce manual data entry.      │ │
│  │     Next step: Explore integrations between your inventory       │ │
│  │     and accounting software.                                     │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Your Personalized Roadmap                                       │ │
│  │  ─────────────────────────                                       │ │
│  │                                                                  │ │
│  │  Phase 1: Organize (Current Focus) - 3-6 Months                  │ │
│  │  • Restructure Chart of Accounts                                 │ │
│  │  • Integrate inventory management system                         │ │
│  │  • Establish monthly reconciliation routine                      │ │
│  │  • Document basic financial workflows                            │ │
│  │                                                                  │ │
│  │  Phase 2: Build - 6-12 Months                                    │ │
│  │  • Create Standard Operating Procedures (SOPs)                   │ │
│  │  • Implement automated workflows                                 │ │
│  │  • Develop custom reporting templates                            │ │
│  │                                                                  │ │
│  │  Phase 3: Grow - 12-18 Months                                    │ │
│  │  • Implement cash flow forecasting                               │ │
│  │  • Create 12-month financial projections                         │ │
│  │  • Develop scenario planning capabilities                        │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Building Your Confidence                                        │ │
│  │  ────────────────────────                                        │ │
│  │                                                                  │ │
│  │  At the start of this assessment, you rated your financial       │ │
│  │  confidence as 5/10. We're here to help you improve that!        │ │
│  │                                                                  │ │
│  │  Remember: Every business owner starts somewhere, and the        │ │
│  │  fact that you completed this assessment shows you're            │ │
│  │  committed to improvement.                                       │ │
│  │                                                                  │ │
│  ├──────────────────────────────────────────────────────────────────┤ │
│  │                                                                  │ │
│  │  Next Steps                                                      │ │
│  │  ──────────                                                      │ │
│  │                                                                  │ │
│  │  Your consultant will reach out to schedule a follow-up          │ │
│  │  meeting to discuss this report and create a detailed            │ │
│  │  action plan tailored to your business.                          │ │
│  │                                                                  │ │
│  │  In the meantime, pick one "Quick Win" from above and            │ │
│  │  take action this week!                                          │ │
│  │                                                                  │ │
│  │  [Schedule Follow-Up Meeting]                                    │ │
│  │                                                                  │ │
│  └──────────────────────────────────────────────────────────────────┘ │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Key Differences from Consultant Report:**

**Tone & Language:**
- Encouraging, never judgmental
- Second person ("you," "your")
- Avoid jargon, explain technical terms
- Emphasize progress and capability
- DISC analysis is hidden from client

**Visual Style:**
- More colorful, friendly
- Use icons and illustrations
- Larger fonts for readability
- More white space
- Checkmark icons for accomplishments

**Content Structure:**
- Welcome section with encouraging message
- Journey visualization (phases)
- Quick Wins (3-5 actionable items)
- Personalized roadmap with timeframes
- Confidence building section
- Clear next steps with CTA

**Quick Wins:**
- Numbered list (3-5 items)
- Checkmark icons
- "Why it matters" explanation
- "Next step" action item
- Simple, concrete language

**Personalized Roadmap:**
- Organized by phases
- Estimated timeframes (helpful, not prescriptive)
- Bullet points for each phase
- Build on previous phases
- Show progression

**Scheduler Integration:**
- CTA button: "Schedule Follow-Up Meeting"
- Link to consultant's calendar
- Embedded scheduler (Calendly, etc.)

---

## Admin Interface

### 5.1 Admin Dashboard

**Route:** `/admin`
**Access:** Admin role only
**Layout:** Header + Sidebar + Content

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Logo] Financial RISE Report - Admin               [User Avatar] ▼     │
└────────────────────────────────────────────────────────────────────────┘
┌──────────────┬─────────────────────────────────────────────────────────┐
│              │                                                         │
│ 🏠 Dashboard  │  Admin Dashboard                                        │
│              │  ───────────────                                        │
│ 👥 Users      │                                                         │
│              │  System Overview                                        │
│ 📊 Analytics  │  ─────────────────                                      │
│              │                                                         │
│ 📝 Activity   │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌──────┐  │
│   Logs       │  │ Total     │ │ Active    │ │ Total     │ │ This │  │
│              │  │ Users     │ │ Users     │ │ Assess.   │ │ Month│  │
│ ⚙️ Settings   │  │           │ │ (30 days) │ │           │ │      │  │
│              │  │    24     │ │    18     │ │   156     │ │  42  │  │
│              │  └───────────┘ └───────────┘ └───────────┘ └──────┘  │
│              │                                                         │
│              │  Recent Activity                                        │
│              │  ────────────────                                       │
│              │                                                         │
│              │  ┌──────────────────────────────────────────────────┐ │
│              │  │ 2:45 PM - john@consultant.com created assessment │ │
│              │  │ 2:30 PM - sarah@consultant.com logged in         │ │
│              │  │ 1:15 PM - mike@consultant.com generated report   │ │
│              │  │ 12:05 PM - admin@rise.com created user account   │ │
│              │  │ 11:30 AM - lisa@consultant.com logged in         │ │
│              │  └──────────────────────────────────────────────────┘ │
│              │                                                         │
│              │  System Health                                          │
│              │  ─────────────                                          │
│              │                                                         │
│              │  ✓ All systems operational                              │
│              │  ✓ Database: Connected                                  │
│              │  ✓ Email Service: Active                                │
│              │  ✓ PDF Generation: Functional                           │
│              │                                                         │
└──────────────┴─────────────────────────────────────────────────────────┘
```

**Specifications:**

**Similar to Consultant Dashboard:**
- Header, sidebar, content area
- Stats cards in grid
- Activity feed
- System status indicators

**Stats Cards:**
- Larger numbers (48px, bold)
- Icon for each stat
- Color-coded based on status

**Activity Log:**
- Chronological list
- Timestamp, user email, action
- 14px font
- Alternating row colors
- Scroll if > 5 items

**System Health:**
- Checkmarks for healthy systems
- Warning icons for issues
- Real-time status

---

### 5.2 User Management

**Route:** `/admin/users`
**Access:** Admin role only

```
┌────────────────────────────────────────────────────────────────────────┐
│ [Logo] Financial RISE Report - Admin               [User Avatar] ▼     │
└────────────────────────────────────────────────────────────────────────┘
┌──────────────┬─────────────────────────────────────────────────────────┐
│              │                                                         │
│ 🏠 Dashboard  │  User Management                  [+ Add New User]     │
│              │  ───────────────                                        │
│ 👥 Users      │                                                         │
│              │  [Search users...]  [Role: All ▼] [Status: All ▼]      │
│ 📊 Analytics  │                                                         │
│              │  ┌────────────────────────────────────────────────────┐│
│ 📝 Activity   │  │ Name          Email             Role    Status   │││
│   Logs       │  ├────────────────────────────────────────────────────┤│
│              │  │ John Doe      john@cons.com     Conslt  Active   │││
│ ⚙️ Settings   │  │               Last login: 2 hrs ago              │││
│              │  │               [Edit] [Reset PW] [Deactivate]     │││
│              │  ├────────────────────────────────────────────────────┤│
│              │  │ Sarah Smith   sarah@cons.com    Conslt  Active   │││
│              │  │               Last login: 1 day ago              │││
│              │  │               [Edit] [Reset PW] [Deactivate]     │││
│              │  ├────────────────────────────────────────────────────┤│
│              │  │ Mike Johnson  mike@cons.com     Admin   Active   │││
│              │  │               Last login: 5 mins ago             │││
│              │  │               [Edit] [Reset PW] [Deactivate]     │││
│              │  ├────────────────────────────────────────────────────┤│
│              │  │ Lisa Wong     lisa@cons.com     Conslt  Inactive │││
│              │  │               Last login: 30 days ago            │││
│              │  │               [Edit] [Reset PW] [Activate]       │││
│              │  └────────────────────────────────────────────────────┘│
│              │                                                         │
│              │  [1] 2 3 4 5 ... 10 →                                   │
│              │                                                         │
└──────────────┴─────────────────────────────────────────────────────────┘
```

**Specifications:**

**Header Actions:**
- Search input: Left
- Filter dropdowns: Right of search
- Add button: Primary, right-aligned

**Table:**
- Full width
- Striped rows
- Hover state
- Sortable columns (click header)

**Table Columns:**
- Name: 150px
- Email: 200px
- Role: 100px (badge)
- Status: 100px (badge)
- Actions: Flex

**Row Details:**
- Primary info: Bold
- Secondary info (last login): 14px, gray, below primary
- Actions: Text buttons, spacing 12px

**Status Badges:**
- Active: Green
- Inactive: Gray
- Locked: Red

**Pagination:**
- Bottom of table
- 10 items per page
- Previous/Next buttons
- Page numbers

---

### 5.3 Add/Edit User Modal

**Trigger:** Click "Add New User" or "Edit"

```
┌─────────────────────────────────────────────────────────────┐
│ Add New User                                            [X] │
│─────────────────────────────────────────────────────────────│
│                                                             │
│  Full Name *                                                │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ John Doe                                              │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  Email Address *                                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ john.doe@consultant.com                               │ │
│  └───────────────────────────────────────────────────────┘ │
│                                                             │
│  Role *                                                     │
│  ○ Consultant                                               │
│  ○ Administrator                                            │
│                                                             │
│  Initial Password *                                         │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ ••••••••••••                                          │ │
│  └───────────────────────────────────────────────────────┘ │
│  [Generate Random Password]                                 │
│  User will be required to change password on first login    │
│                                                             │
│  ☑ Send welcome email with login credentials               │
│                                                             │
│─────────────────────────────────────────────────────────────│
│                                      [Cancel] [Create User] │
└─────────────────────────────────────────────────────────────┘
```

**Specifications:**

**Form Fields:**
- Standard input styling
- Required indicators
- Radio buttons for role
- Checkbox for email notification

**Password:**
- Generate button: Text button
- Helper text about first-login password change

**Validation:**
- Email format
- Password complexity
- Required fields

---

## Common Layouts

### 6.1 Main Application Layout

**Structure:**

```
┌────────────────────────────────────────────────────────────────────────┐
│ Header (AppBar)                                                        │
│ - Logo (left)                                                          │
│ - Navigation links (center/right) - Desktop only                       │
│ - User menu (right)                                                    │
│ - Height: 64px                                                         │
└────────────────────────────────────────────────────────────────────────┘
┌──────────────┬─────────────────────────────────────────────────────────┐
│ Sidebar      │ Main Content Area                                       │
│ (optional)   │ - Max width: 1280px                                     │
│              │ - Padding: 32px                                         │
│ Width: 240px │ - Background: White or #FAFAFA                          │
│ (collapsible)│                                                         │
│              │                                                         │
│              │                                                         │
│              │                                                         │
│              │                                                         │
└──────────────┴─────────────────────────────────────────────────────────┘
```

**Responsive Behavior:**

**Desktop (lg+):**
- Header: Full navigation visible
- Sidebar: Expanded, pinned
- Content: Max-width 1280px, centered

**Tablet (md):**
- Header: Hamburger menu
- Sidebar: Collapsible drawer
- Content: Full width with padding

**Mobile (xs-sm):**
- Header: Hamburger menu, logo centered
- Sidebar: Slide-out drawer
- Content: Full width, reduced padding (16px)

---

### 6.2 Empty States

**Generic Empty State Pattern:**

```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│                      [Icon or Illustration]                │
│                         (120px)                            │
│                                                            │
│                    [Heading Text]                          │
│                                                            │
│              [Description / Helper Text]                   │
│                                                            │
│                  [Primary Action Button]                   │
│                                                            │
│                  [Secondary Action Link]                   │
│                  (optional)                                │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Examples:**

**No Assessments:**
- Icon: Clipboard or document icon
- Heading: "No Assessments Yet"
- Description: "Get started by creating your first client assessment."
- Button: "Create First Assessment"

**No Search Results:**
- Icon: Search icon with slash
- Heading: "No Results Found"
- Description: "Try adjusting your search or filters."
- Button: "Clear Filters"

**Error State:**
- Icon: Warning triangle or error icon
- Heading: "Something Went Wrong"
- Description: "We couldn't load this content. Please try again."
- Button: "Retry"

---

### 6.3 Loading States

**Page Loading:**
```
┌────────────────────────────────────────────────────────────┐
│                                                            │
│                   [Circular Spinner]                       │
│                      (40px, purple)                        │
│                                                            │
│                    Loading...                              │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Skeleton Loading (Cards):**
```
┌────────────────────────────────────────────────────────────┐
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░                              │
│                                                            │
│ ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░                         │
│ ▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░░                         │
│                                                            │
│ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░         │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Inline Loading (Buttons):**
- Disable button
- Show small spinner (20px) inside button
- Text: "Loading..." or keep original text

---

### 6.4 Error Handling

**Form Validation Errors:**
```
┌─────────────────────────────────────────────────────────────┐
│  Email Address *                                            │
│  ┌───────────────────────────────────────────────────────┐ │
│  │ invalid-email                                   [RED] │ │
│  └───────────────────────────────────────────────────────┘ │
│  ⚠️ Please enter a valid email address                     │
│     (RED TEXT, 14px)                                        │
└─────────────────────────────────────────────────────────────┘
```

**Error Specification:**
- Input border: 2px solid #D32F2F
- Error icon: Left of message
- Error text: #D32F2F, 14px
- Aria-invalid: true
- Aria-describedby: error message ID

**Global Error Banner:**
```
┌─────────────────────────────────────────────────────────────┐
│ ⚠️  Error: Unable to save assessment. Please try again.  [X]│
│     (RED BACKGROUND, WHITE TEXT)                            │
└─────────────────────────────────────────────────────────────┘
```

**Position:** Top of page, full width
**Dismissible:** X button
**Auto-dismiss:** No (requires user action)

---

### 6.5 Confirmation Dialogs

**Delete Confirmation:**

```
┌─────────────────────────────────────────────────────────────┐
│ Confirm Deletion                                        [X] │
│─────────────────────────────────────────────────────────────│
│                                                             │
│  Are you sure you want to delete this assessment?           │
│                                                             │
│  Client: Acme Corporation - John Doe                        │
│                                                             │
│  This action cannot be undone. All assessment data          │
│  and generated reports will be permanently deleted.         │
│                                                             │
│─────────────────────────────────────────────────────────────│
│                                      [Cancel] [Delete]      │
└─────────────────────────────────────────────────────────────┘
```

**Specifications:**
- Max Width: 500px
- Warning icon (optional)
- Clear explanation of consequences
- Affected item details (client name, etc.)
- Destructive action: Red button
- Cancel: Outlined button (default focus)

---

## Responsive Breakpoint Wireframes

### Mobile View (xs: 0-599px)

**Key Adaptations:**
- Single column layouts
- Hamburger menu for navigation
- Full-width buttons and inputs
- Larger touch targets (44px minimum)
- Reduced padding (16px instead of 24-32px)
- Stack cards vertically
- Hide sidebar, use drawer instead
- Modals become full-screen
- Tables become cards or horizontal scroll

### Tablet View (sm-md: 600-1279px)

**Key Adaptations:**
- 2-column layouts where appropriate
- Collapsible sidebar (drawer)
- Medium padding (20-24px)
- Dashboard: 2 stat cards per row
- Forms: 2 columns for related fields
- Tables: Scroll horizontally if needed

### Desktop View (lg+: 1280px+)

**Key Adaptations:**
- Full layouts as shown in wireframes above
- 3-4 column grids
- Expanded sidebar (pinned)
- Full padding (24-48px)
- Dashboard: 4 stat cards per row
- Tables: Full display with all columns

---

**Document Version:** 1.0
**Last Updated:** 2025-12-19
**Maintained by:** Design System Team

For implementation details, refer to:
- Design System: `docs/design-system.md`
- Requirements: `plans/requirements.md`
- Components: `frontend/src/components/`
