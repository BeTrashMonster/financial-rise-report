# Financial RISE Frontend Development Roadmap

**Created:** 2026-01-04
**Current Status:** Authentication working, Dashboard stub only
**Priority:** Build functional assessment workflow

---

## Current State Analysis

### ✅ What's Working
- User authentication (login/logout)
- JWT token management
- Protected routes
- Backend APIs are deployed and functional

### ❌ What's Missing (Critical)
- Assessment management pages
- Client management interface
- Questionnaire workflow
- DISC profile results display
- Phase results display
- Report generation UI
- Report viewing/download

### 🔧 Backend APIs Available (Ready to Use)
Based on logs, these endpoints exist:
```
POST   /api/v1/api/v1/assessments          - Create assessment
GET    /api/v1/api/v1/assessments          - List assessments
GET    /api/v1/api/v1/assessments/:id      - Get assessment
PATCH  /api/v1/api/v1/assessments/:id      - Update assessment
DELETE /api/v1/api/v1/assessments/:id      - Delete assessment
GET    /api/v1/api/v1/questionnaire/questions  - Get questions
POST   /api/v1/api/v1/questionnaire/responses  - Submit responses
POST   /api/v1/api/v1/assessments/:id/calculate  - Calculate results
GET    /api/v1/api/v1/assessments/:id/disc-profile  - Get DISC profile
GET    /api/v1/api/v1/assessments/:id/phase-results - Get phase results
POST   /api/v1/reports/generate/consultant   - Generate consultant report
POST   /api/v1/reports/generate/client       - Generate client report
GET    /api/v1/reports/download/:id          - Download report
```

---

## Phase 1: Core Assessment Workflow (Priority 1)

**Goal:** Enable consultants to create assessments and complete questionnaires

### Work Stream 1: Assessment List Page
**Effort:** Medium
**Dependencies:** None
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Assessments/AssessmentList.tsx`
- [ ] Create table component showing:
  - Client name
  - Business name
  - Status (draft/in_progress/completed)
  - Progress percentage
  - Created date
  - Actions (View, Edit, Delete)
- [ ] Add "New Assessment" button
- [ ] Integrate with `GET /api/v1/api/v1/assessments` endpoint
- [ ] Add loading states and error handling
- [ ] Add empty state for no assessments
- [ ] Update routes.tsx to include /assessments route

**Deliverables:**
- Working assessment list page
- Ability to see all assessments at a glance

---

### Work Stream 2: Create Assessment Form
**Effort:** Small
**Dependencies:** Work Stream 1
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Assessments/CreateAssessment.tsx`
- [ ] Build form with fields:
  - Client name (text input)
  - Business name (text input)
  - Client email (email input)
  - Notes (textarea, optional)
- [ ] Form validation using Formik or React Hook Form
- [ ] Integrate with `POST /api/v1/api/v1/assessments` endpoint
- [ ] Navigate to questionnaire page on success
- [ ] Add cancel button (return to list)

**Deliverables:**
- Modal or page to create new assessment
- Redirects to questionnaire after creation

---

### Work Stream 3: Questionnaire Workflow
**Effort:** Large
**Dependencies:** Work Stream 2
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Questionnaire/Questionnaire.tsx`
- [ ] Fetch questions from `GET /api/v1/api/v1/questionnaire/questions`
- [ ] Build question rendering based on type:
  - Single choice (radio buttons)
  - Multiple choice (checkboxes)
  - Rating scale (1-10 slider or buttons)
  - Text input (textarea)
- [ ] Implement progress tracking (show X of Y questions completed)
- [ ] Auto-save responses as user answers
- [ ] Submit responses via `POST /api/v1/api/v1/questionnaire/responses`
- [ ] Calculate results via `POST /api/v1/api/v1/assessments/:id/calculate`
- [ ] Navigate to results page on completion
- [ ] Handle incomplete questionnaires (resume later)

**Deliverables:**
- Multi-step questionnaire form
- Progress indicator
- Auto-save functionality
- Completion confirmation

---

### Work Stream 4: Results Display Page
**Effort:** Medium
**Dependencies:** Work Stream 3
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Results/Results.tsx`
- [ ] Fetch DISC profile via `GET /api/v1/api/v1/assessments/:id/disc-profile`
- [ ] Fetch phase results via `GET /api/v1/api/v1/assessments/:id/phase-results`
- [ ] Display DISC profile:
  - D, I, S, C scores (bar chart or radial chart)
  - Primary style indicator
  - Style description
- [ ] Display phase results:
  - Recommended phase (Stabilize/Organize/Build/Grow)
  - Scores for each phase (bar chart)
  - Phase description
- [ ] Add "Generate Reports" button
- [ ] Add "Back to Assessments" button

**Deliverables:**
- Visual display of DISC and phase results
- Clear indication of recommended phase
- Path to generate reports

---

## Phase 2: Report Generation (Priority 2)

### Work Stream 5: Report Generation Interface
**Effort:** Medium
**Dependencies:** Work Stream 4
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Reports/GenerateReports.tsx`
- [ ] Add buttons to generate:
  - Client report (`POST /api/v1/reports/generate/client`)
  - Consultant report (`POST /api/v1/reports/generate/consultant`)
- [ ] Show loading spinner during PDF generation
- [ ] Display success message with download link
- [ ] Handle errors (timeout, server error)
- [ ] Store report IDs in state for download

**Deliverables:**
- Interface to trigger report generation
- Loading states during generation
- Links to download generated reports

---

### Work Stream 6: Report Viewing & Download
**Effort:** Small
**Dependencies:** Work Stream 5
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Reports/ReportViewer.tsx`
- [ ] List generated reports for an assessment
- [ ] Add download buttons using `GET /api/v1/reports/download/:id`
- [ ] Show report metadata:
  - Report type (Client/Consultant)
  - Generation date
  - File size
- [ ] Add "Regenerate" option if needed

**Deliverables:**
- Report list for each assessment
- Download functionality
- Report metadata display

---

## Phase 3: Navigation & UX Polish (Priority 3)

### Work Stream 7: Navigation Bar & Menu
**Effort:** Small
**Dependencies:** Work Streams 1-6
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/components/Layout/Navigation.tsx`
- [ ] Add navigation menu with links:
  - Dashboard (/)
  - Assessments (/assessments)
  - Profile (/profile)
  - Logout
- [ ] Highlight active route
- [ ] Make responsive for mobile
- [ ] Add user info display (name, email)
- [ ] Integrate with all pages using Layout wrapper

**Deliverables:**
- Consistent navigation across all pages
- User profile display in nav
- Mobile-friendly menu

---

### Work Stream 8: Enhanced Dashboard
**Effort:** Medium
**Dependencies:** Work Streams 1-6
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Replace stub Dashboard.tsx with functional version
- [ ] Add dashboard widgets:
  - Total assessments count
  - In-progress assessments count
  - Completed assessments count
  - Recent assessments table (last 5)
- [ ] Add quick actions:
  - "New Assessment" button
  - "View All Assessments" button
- [ ] Fetch data from existing endpoints
- [ ] Add charts/visualizations if time permits

**Deliverables:**
- Functional dashboard with stats
- Quick access to common actions
- Recent activity display

---

### Work Stream 9: User Profile Page
**Effort:** Small
**Dependencies:** None
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Create `src/pages/Profile/Profile.tsx`
- [ ] Display user information:
  - Name
  - Email
  - Role
  - Account creation date
  - Last login
- [ ] Add "Change Password" form (if endpoint exists)
- [ ] Add GDPR controls:
  - Export my data button
  - Delete my account button
  - Processing restriction request

**Deliverables:**
- User profile page
- Account management options
- GDPR compliance features

---

## Phase 4: Quality & Polish (Priority 4)

### Work Stream 10: Error Handling & Loading States
**Effort:** Medium
**Dependencies:** All previous work streams
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Add error boundaries to catch React errors
- [ ] Implement toast notifications for success/error messages
- [ ] Add skeleton loaders for all data fetching
- [ ] Handle network errors gracefully
- [ ] Add retry logic for failed requests
- [ ] Create error pages (404, 500, 502)

**Deliverables:**
- Consistent error handling
- User-friendly error messages
- Loading skeletons everywhere

---

### Work Stream 11: Mobile Responsiveness
**Effort:** Medium
**Dependencies:** All previous work streams
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Test all pages on mobile viewports
- [ ] Fix layout issues for screens < 768px
- [ ] Make tables responsive (horizontal scroll or cards)
- [ ] Ensure forms are mobile-friendly
- [ ] Test navigation on mobile
- [ ] Add touch-friendly interactions

**Deliverables:**
- Mobile-responsive design
- Touch-friendly UI
- Tested on iOS and Android

---

### Work Stream 12: Accessibility (WCAG 2.1 AA)
**Effort:** Medium
**Dependencies:** All previous work streams
**Status:** ⚪ Not Started

**Tasks:**
- [ ] Add ARIA labels to all interactive elements
- [ ] Ensure keyboard navigation works everywhere
- [ ] Test with screen reader (NVDA or JAWS)
- [ ] Fix color contrast issues
- [ ] Add focus indicators
- [ ] Add skip links for navigation

**Deliverables:**
- WCAG 2.1 Level AA compliance
- Screen reader friendly
- Keyboard accessible

---

## Summary

**Total Work Streams:** 12

### Priority Breakdown
- **Priority 1 (Critical):** Work Streams 1-4 (Core workflow)
- **Priority 2 (High):** Work Streams 5-6 (Reports)
- **Priority 3 (Medium):** Work Streams 7-9 (Navigation & UX)
- **Priority 4 (Nice to have):** Work Streams 10-12 (Quality & Polish)

### Recommended Approach
1. Start with Work Streams 1-4 sequentially to get the core assessment workflow working
2. Once users can create assessments and see results, implement reports (Work Streams 5-6)
3. Improve navigation and dashboard (Work Streams 7-9)
4. Polish with error handling, mobile, and accessibility (Work Streams 10-12)

### Current Blocker
**None** - All backend APIs are ready. Frontend development can begin immediately.

---

## Next Steps

1. Begin Work Stream 1 (Assessment List Page)
2. Then Work Stream 2 (Create Assessment Form)
3. Then Work Stream 3 (Questionnaire Workflow)
4. Then Work Stream 4 (Results Display)
5. Continue with Work Streams 5-12 based on priority
