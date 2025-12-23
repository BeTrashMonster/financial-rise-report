# Phase 3 QA Testing Specification

**Work Stream:** 47
**Phase:** 3 - Advanced Features
**Dependency Level:** 2
**Created:** 2025-12-22
**Status:** Complete

## Overview

This specification defines the comprehensive Quality Assurance (QA) testing plan for Phase 3: Advanced Features. The testing scope includes all new features introduced in Phase 3 (Work Streams 41-46) as well as regression testing to ensure existing MVP and Phase 2 functionality remains intact.

### Phase 3 Features to Test

1. **Work Stream 41:** Conditional Questions Logic - Dynamic questionnaire with visibility rules
2. **Work Stream 42:** Multiple Phase Identification - Enhanced algorithm for multi-phase detection
3. **Work Stream 43:** CSV Export & Basic Analytics - Data export and analytics dashboard
4. **Work Stream 44:** Shareable Report Links - Token-based secure sharing
5. **Work Stream 45:** Admin Performance Monitoring - System health dashboard
6. **Work Stream 46:** Enhanced Activity Logging - Advanced log filtering and search

### Testing Objectives

- **Functionality:** Verify all Phase 3 features work as specified
- **Integration:** Ensure Phase 3 features integrate seamlessly with existing systems
- **Regression:** Confirm no breaking changes to MVP or Phase 2 features
- **Performance:** Validate system performance under increased complexity
- **Security:** Test new security features (shareable links, access control)
- **Usability:** Ensure new features are intuitive and accessible
- **Data Integrity:** Verify data accuracy in analytics and exports

---

## Test Plan Structure

### 1. Functional Testing (Phase 3 Features)

#### 1.1 Conditional Questions Logic

**Test Cases:**

| ID | Test Case | Steps | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| CQ-001 | Simple conditional question display | 1. Create question with condition "show if Q1 = Yes"<br>2. Answer Q1 with "Yes" | Q2 appears dynamically | P0 |
| CQ-002 | Question hides when condition not met | 1. Answer Q1 with "No" | Q2 remains hidden | P0 |
| CQ-003 | Multiple conditions (AND logic) | 1. Create Q3 with conditions: Q1=Yes AND Q2=Yes<br>2. Answer both correctly | Q3 appears | P0 |
| CQ-004 | Multiple conditions (OR logic) | 1. Create Q4 with conditions: Q1=Yes OR Q2=Yes<br>2. Answer one correctly | Q4 appears | P0 |
| CQ-005 | Nested conditional questions | 1. Q2 depends on Q1<br>2. Q3 depends on Q2<br>3. Answer Q1 and Q2 | Q3 appears correctly | P1 |
| CQ-006 | Changing answer hides dependent questions | 1. Answer Q1=Yes, Q2 appears<br>2. Change Q1=No | Q2 disappears and response cleared | P0 |
| CQ-007 | Progress calculation with conditionals | 1. Complete questionnaire with conditionals | Progress shows X of Y visible questions | P1 |
| CQ-008 | Greater than / Less than operators | 1. Create condition "revenue > 100000"<br>2. Enter 150000 | Dependent question appears | P1 |
| CQ-009 | Contains operator for text | 1. Create condition "industry contains 'tech'"<br>2. Enter "fintech" | Dependent question appears | P1 |
| CQ-010 | In / Not In operators for arrays | 1. Create condition "status in ['Active', 'Growing']"<br>2. Select "Active" | Dependent question appears | P1 |
| CQ-011 | Complex nested conditions | 1. Create deeply nested conditional tree (5+ levels) | All questions appear/hide correctly | P2 |
| CQ-012 | Conditional flow tracking | 1. Complete questionnaire with conditionals<br>2. Check `questionnaire_flow` table | Flow recorded correctly | P1 |

**Edge Cases:**
- Circular dependencies (should be prevented)
- Question depending on itself (should be prevented)
- All questions hidden by conditionals (show message)
- Invalid condition operators
- Missing target questions

#### 1.2 Multiple Phase Identification

**Test Cases:**

| ID | Test Case | Steps | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| MP-001 | Single phase identification | 1. Create assessment with clear single phase | Primary phase identified, no secondary | P0 |
| MP-002 | Transitioning phase (1 secondary) | 1. Create scores: Organize 40%, Build 35% | Primary: Organize, Secondary: Build | P0 |
| MP-003 | Multi-phase (2+ secondaries) | 1. Create scores: Build 35%, Grow 30%, Systemic 25% | Primary + 2 secondaries identified | P0 |
| MP-004 | Secondary phase threshold (≥20%) | 1. Create phase with 19% score | Not identified as secondary | P1 |
| MP-005 | Distance from primary threshold (≤15%) | 1. Create phase 18% below primary | Not identified as secondary | P1 |
| MP-006 | Distance from next threshold (≥10%) | 1. Create phase only 8% ahead of next | Not identified as secondary | P1 |
| MP-007 | Phase string format | 1. Create multi-phase assessment | phase_string = "Build/Grow/Systemic" | P1 |
| MP-008 | Transition status: single | 1. One phase >50% | transition_status = 'single' | P1 |
| MP-009 | Transition status: transitioning | 1. Two phases qualify | transition_status = 'transitioning' | P1 |
| MP-010 | Transition status: multi | 1. Three+ phases qualify | transition_status = 'multi' | P1 |
| MP-011 | Multi-phase report template | 1. Generate consultant report for multi-phase | Report shows all phases with context | P0 |
| MP-012 | Multi-phase client roadmap | 1. Generate client report for multi-phase | Roadmap addresses multiple phases | P0 |

**Edge Cases:**
- All phases equal (20% each)
- One phase at 100%, others at 0%
- Boundary testing at exact thresholds

#### 1.3 CSV Export & Analytics

**Test Cases:**

| ID | Test Case | Steps | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| CSV-001 | Export assessments to CSV | 1. Click "Export Assessments"<br>2. Download file | CSV contains all assessments with headers | P0 |
| CSV-002 | Export responses to CSV | 1. Click "Export Responses"<br>2. Download file | CSV contains all responses with question text | P0 |
| CSV-003 | Export analytics summary | 1. Click "Export Analytics"<br>2. Download file | CSV contains aggregated metrics | P1 |
| CSV-004 | CSV format validation | 1. Open exported CSV in Excel | Proper encoding, no broken characters | P0 |
| CSV-005 | Large dataset export (1000+ records) | 1. Export large dataset | Export completes within 30 seconds | P1 |
| CSV-006 | CSV headers correct | 1. Export any CSV | Headers match data columns exactly | P0 |
| CSV-007 | UTF-8 encoding for special chars | 1. Export data with emoji/accents | Characters display correctly | P1 |
| CSV-008 | Analytics dashboard display | 1. Navigate to analytics page | Charts load with real data | P0 |
| CSV-009 | Summary metrics accuracy | 1. Check total assessments metric | Matches actual count in database | P0 |
| CSV-010 | DISC distribution chart | 1. View DISC pie chart | Percentages add to 100%, colors correct | P1 |
| CSV-011 | Phase distribution chart | 1. View phase doughnut chart | All 5 phases represented | P1 |
| CSV-012 | Time series chart | 1. Select "Last 30 days"<br>2. View line chart | Data points for each day | P1 |
| CSV-013 | Average completion time | 1. Check avg completion time metric | Calculated correctly from timestamps | P1 |
| CSV-014 | Filter analytics by date range | 1. Select custom date range<br>2. Apply filter | Metrics update for selected range | P1 |

**Edge Cases:**
- Export with 0 records (empty CSV with headers)
- Very long text fields in CSV (escaped properly)
- Null/undefined values in export

#### 1.4 Shareable Report Links

**Test Cases:**

| ID | Test Case | Steps | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| SRL-001 | Generate shareable link | 1. Click "Share Report"<br>2. Generate link | Unique token-based URL created | P0 |
| SRL-002 | Access report via shareable link | 1. Open shareable link (not logged in) | Report displays without login | P0 |
| SRL-003 | Password-protected link | 1. Enable password protection<br>2. Generate link<br>3. Open link | Password prompt appears | P0 |
| SRL-004 | Correct password grants access | 1. Enter correct password | Report displays | P0 |
| SRL-005 | Incorrect password denies access | 1. Enter wrong password | Error message shown | P0 |
| SRL-006 | Expired link shows error | 1. Set expiration to past date<br>2. Open link | "Link expired" message shown | P0 |
| SRL-007 | View limit enforcement | 1. Set max_views = 3<br>2. Open link 4 times | 4th view denied with message | P0 |
| SRL-008 | Revoke link | 1. Revoke active link<br>2. Open link | "Link revoked" message shown | P0 |
| SRL-009 | Access tracking | 1. Open link 3 times from different IPs<br>2. Check access log | 3 access records logged | P1 |
| SRL-010 | Session token for password links | 1. Enter password once<br>2. Refresh page | No password prompt (session valid) | P1 |
| SRL-011 | Session expiration (30 min) | 1. Enter password<br>2. Wait 31 minutes<br>3. Refresh | Password prompt reappears | P2 |
| SRL-012 | Mobile-optimized viewer | 1. Open link on mobile device | Report displays correctly, readable | P1 |
| SRL-013 | Copy link button | 1. Click "Copy Link" | Link copied to clipboard | P1 |
| SRL-014 | Link preview before generating | 1. Configure link settings<br>2. View preview | Preview shows report as it will appear | P2 |
| SRL-015 | Multiple links for same report | 1. Generate 2 different links for same report | Both work independently | P1 |

**Edge Cases:**
- Link accessed after max_views reached
- Very long password (>100 chars)
- Special characters in password
- Link accessed from blocked IP/country

#### 1.5 Admin Performance Monitoring

**Test Cases:**

| ID | Test Case | Steps | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| APM-001 | System metrics display | 1. Navigate to Admin > Performance | CPU, Memory, Disk metrics shown | P0 |
| APM-002 | Real-time metrics update | 1. Watch dashboard for 30 seconds | Metrics update via WebSocket | P1 |
| APM-003 | Database connection monitoring | 1. Check DB connections metric | Shows current active connections | P1 |
| APM-004 | API response time tracking | 1. Check avg response time | Calculated from recent requests | P1 |
| APM-005 | Error rate monitoring | 1. Trigger some errors<br>2. Check error rate | Percentage increases | P1 |
| APM-006 | User activity metrics | 1. Check active users metric | Shows users active in last 24h | P1 |
| APM-007 | Session metrics | 1. Check avg session duration | Calculated correctly | P2 |
| APM-008 | Business KPIs | 1. Check assessment/report counts | Matches database totals | P0 |
| APM-009 | Metrics time series chart | 1. View CPU usage over time | Line chart shows last 24h | P1 |
| APM-010 | Alert threshold configuration | 1. Set CPU alert >80%<br>2. Trigger high CPU | Alert displayed on dashboard | P2 |
| APM-011 | Export metrics to CSV | 1. Click "Export Metrics" | CSV downloaded with historical data | P1 |
| APM-012 | Metrics retention (30 days) | 1. Check oldest metrics | Data from 30 days ago available | P2 |
| APM-013 | WebSocket reconnection | 1. Disable network<br>2. Re-enable network | Metrics resume updating | P1 |
| APM-014 | Responsive design | 1. View on mobile | Charts resize, readable | P1 |

**Edge Cases:**
- No metrics data (new installation)
- Metrics during system downtime
- Very high load (>100% CPU)

#### 1.6 Enhanced Activity Logging

**Test Cases:**

| ID | Test Case | Steps | Expected Result | Priority |
|----|-----------|-------|-----------------|----------|
| EAL-001 | View activity logs | 1. Navigate to Admin > Activity Logs | Table shows recent logs | P0 |
| EAL-002 | Filter by user | 1. Select user from dropdown<br>2. Apply filter | Shows only that user's logs | P0 |
| EAL-003 | Filter by action pattern | 1. Enter "auth.%"<br>2. Apply filter | Shows all auth-related logs | P0 |
| EAL-004 | Filter by date range | 1. Select date range<br>2. Apply filter | Shows logs within range | P0 |
| EAL-005 | Filter by status code range | 1. Set min=400, max=499<br>2. Apply filter | Shows only 4xx errors | P0 |
| EAL-006 | Full-text search | 1. Enter "failed login"<br>2. Search | Shows matching logs | P0 |
| EAL-007 | Pagination | 1. Navigate through pages | 50 logs per page, navigation works | P1 |
| EAL-008 | Expand log details | 1. Click expand icon | Shows request/response details | P1 |
| EAL-009 | View timeline for resource | 1. Click timeline icon<br>2. View modal | Shows chronological events | P1 |
| EAL-010 | Export logs to CSV | 1. Apply filters<br>2. Click "Export CSV" | Filtered logs exported | P0 |
| EAL-011 | CSV export custom columns | 1. Select specific columns<br>2. Export | CSV contains only selected columns | P1 |
| EAL-012 | Sensitive data redaction | 1. Check logs for password fields | Shows [REDACTED] | P0 |
| EAL-013 | IP address capture | 1. Make request<br>2. Check log | Correct IP address logged | P1 |
| EAL-014 | User agent logging | 1. Make request from Chrome<br>2. Check log | User agent string logged | P2 |
| EAL-015 | Response time tracking | 1. Check duration_ms field | Accurate response time logged | P1 |
| EAL-016 | Error message capture | 1. Trigger 500 error<br>2. Check log | Error message logged | P0 |
| EAL-017 | Retention policy application | 1. Create old logs (181 days)<br>2. Run archive job | Old logs archived/deleted | P1 |
| EAL-018 | Archive logs to S3 | 1. Archive logs<br>2. Check S3 bucket | JSON file uploaded | P1 |

**Edge Cases:**
- Search with special characters
- Filter with no matching results
- Export very large log set (100k+ records)

---

### 2. Regression Testing

**Objective:** Ensure Phase 3 changes don't break existing MVP and Phase 2 functionality.

#### 2.1 MVP Feature Regression

**Critical User Flows:**
1. **User Registration & Login** - Ensure auth still works
2. **Assessment Creation** - Create new assessment end-to-end
3. **Questionnaire Completion** - Complete full questionnaire without conditionals
4. **DISC Profiling** - Verify DISC calculation still accurate
5. **Phase Determination** - Verify single-phase logic still works
6. **Report Generation** - Generate both client and consultant reports
7. **PDF Export** - Download PDF reports successfully
8. **Dashboard View** - View assessments list

**Test Approach:**
- Re-run all MVP smoke tests
- Verify no UI regressions
- Check data integrity in database

#### 2.2 Phase 2 Feature Regression

**Features to Retest:**
1. **Action Item Checklist** - CRUD operations work
2. **Scheduler Integration** - Links display in reports
3. **Dashboard Enhancements** - Filters, search, archive work
4. **Email Delivery** - Send report via email
5. **Branding Customization** - Logo and colors apply
6. **Consultant Notes** - Notes save and appear in consultant report
7. **Secondary DISC Traits** - Secondary traits still calculated

**Test Approach:**
- Test each Phase 2 feature end-to-end
- Verify no performance degradation
- Check for UI/UX consistency

---

### 3. Integration Testing

**Phase 3 Feature Integrations:**

| Integration | Test Scenario | Expected Result |
|-------------|---------------|-----------------|
| Conditional Questions + DISC | DISC questions remain hidden from client | DISC calculation works with conditionals |
| Multi-Phase + Reports | Generate report for multi-phase client | Report template adapts correctly |
| Analytics + All Features | View analytics dashboard | All phases, DISC types, features represented |
| Shareable Links + Reports | Share multi-phase report | Shared report displays correctly |
| Activity Logging + All Features | Perform various actions | All logged with correct metadata |
| Performance Monitoring + Load | Run load tests | Metrics capture system under load |

---

### 4. Performance Testing

**Scenarios:**

| Test | Load | Metric | Acceptable Threshold |
|------|------|--------|----------------------|
| Conditional Question Evaluation | 100 concurrent users answering | Response time | <500ms per answer |
| Multi-Phase Calculation | 50 concurrent assessments | Calculation time | <2 seconds |
| CSV Export (Large) | 10,000 assessments | Export time | <30 seconds |
| Analytics Dashboard Load | 100 concurrent admin users | Page load time | <3 seconds |
| Shareable Link Access | 500 concurrent views | Response time | <1 second |
| Activity Log Search | 1M log records | Search time | <2 seconds |
| Log CSV Export | 100K log records | Export time | <60 seconds |

**Tools:**
- Apache JMeter or Locust for load testing
- Chrome DevTools for frontend performance
- PostgreSQL EXPLAIN ANALYZE for query optimization

---

### 5. Security Testing

**Test Cases:**

| ID | Security Test | Method | Pass Criteria |
|----|---------------|--------|---------------|
| SEC-001 | Shareable link token strength | Try to guess tokens | Cannot guess valid tokens |
| SEC-002 | Password hashing for links | Check database | Passwords stored as bcrypt hashes |
| SEC-003 | SQL injection in log search | Enter malicious queries | No SQL injection possible |
| SEC-004 | XSS in activity logs | Enter script tags in logs | Scripts escaped/sanitized |
| SEC-005 | CSRF protection on exports | Export without CSRF token | Request denied |
| SEC-006 | Rate limiting on shareable links | Access link 1000x in 1 minute | Rate limited after threshold |
| SEC-007 | Admin-only endpoints | Access admin APIs as non-admin | 403 Forbidden |
| SEC-008 | CSV injection | Export data with =cmd | Excel formula execution prevented |
| SEC-009 | Session fixation | Reuse old session token | Token invalidated |
| SEC-010 | Sensitive data in logs | Check raw logs | Passwords/tokens redacted |

---

### 6. Accessibility Testing

**WCAG 2.1 Level AA Compliance:**

| Component | Test | Tool | Pass Criteria |
|-----------|------|------|---------------|
| Analytics Dashboard | Keyboard navigation | Manual | All charts accessible via keyboard |
| Activity Logs Table | Screen reader | NVDA/JAWS | Table headers announced correctly |
| Shareable Link Modal | Color contrast | Axe DevTools | 4.5:1 contrast ratio met |
| CSV Export Button | Focus indicators | Manual | Visible focus state |
| Conditional Questions | ARIA labels | Axe DevTools | Dynamic questions announced |
| Performance Charts | Alt text | Manual | Chart data available in text form |

---

### 7. Cross-Browser & Responsive Testing

**Browsers:**
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile Safari (iOS)
- Mobile Chrome (Android)

**Devices/Breakpoints:**
- Desktop (1920x1080)
- Laptop (1366x768)
- Tablet Portrait (768x1024)
- Tablet Landscape (1024x768)
- Mobile (375x667)
- Large Mobile (414x896)

**Test Each Phase 3 Feature:**
- Conditional questions UI adapts on mobile
- Analytics charts responsive
- Activity logs table scrolls horizontally on mobile
- Shareable link viewer mobile-optimized
- Performance dashboard readable on tablet
- CSV export works on all browsers

---

### 8. Usability Testing

**User Scenarios:**

1. **Consultant creates conditional questionnaire**
   - Can they understand the conditional logic UI?
   - Is it clear how to add/edit conditions?
   - Are error messages helpful?

2. **Consultant views analytics dashboard**
   - Are charts easy to understand?
   - Can they find the export button?
   - Is data presentation clear?

3. **Consultant shares report with client**
   - Is the sharing flow intuitive?
   - Can they set password/expiration easily?
   - Is the preview helpful?

4. **Admin reviews activity logs**
   - Can they find specific events quickly?
   - Are filters easy to use?
   - Is the timeline view helpful?

**Success Criteria:**
- 90%+ task completion rate
- <5 seconds to find key features
- <3 clicks for common tasks
- 4.0+ usability rating (out of 5)

---

### 9. Data Integrity Testing

**Validation Tests:**

| Test | Verification | Method |
|------|--------------|--------|
| Conditional question flow | All responses match conditions | Database query |
| Multi-phase percentages | All percentages add to 100% | Calculation check |
| Analytics totals | Match raw database counts | SQL comparison |
| CSV export completeness | All records exported | Row count match |
| Activity log completeness | No missing HTTP requests | Log analysis |
| Shareable link access counts | Accurate view tracking | Database verification |

---

### 10. Bug Reporting & Tracking

**Bug Report Template:**

```markdown
**Bug ID:** [Auto-generated]
**Title:** [Brief description]
**Severity:** P0 (Critical) / P1 (High) / P2 (Medium) / P3 (Low)
**Phase:** Phase 3
**Work Stream:** [41-46]
**Component:** [Frontend/Backend/Database/Infrastructure]

**Description:**
[Detailed description of the bug]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Environment:**
- Browser: [e.g., Chrome 120]
- OS: [e.g., Windows 11]
- Screen Size: [e.g., 1920x1080]

**Screenshots/Videos:**
[Attach if applicable]

**Console Errors:**
[Paste any console errors]

**Additional Context:**
[Any other relevant information]
```

**Severity Definitions:**

- **P0 (Critical):** Blocks core functionality, data loss, security vulnerability
- **P1 (High):** Major feature broken, poor UX, affects many users
- **P2 (Medium):** Minor feature issue, workaround exists
- **P3 (Low):** Cosmetic issue, edge case, nice-to-have

**Bug Workflow:**
1. Tester discovers bug → Creates bug report
2. Product Manager triages → Assigns severity
3. Developer investigates → Confirms or rejects
4. Developer fixes → Creates PR
5. Tester verifies fix → Closes bug

---

## Test Execution Plan

### Week 1: Functional Testing
- Days 1-2: Conditional Questions (CQ-001 to CQ-012)
- Days 3-4: Multi-Phase + CSV Export (MP-001 to CSV-014)
- Day 5: Buffer for retests

### Week 2: Advanced Features Testing
- Days 1-2: Shareable Links (SRL-001 to SRL-015)
- Days 2-3: Admin Monitoring + Logging (APM-001 to EAL-018)
- Day 5: Regression testing

### Week 3: Non-Functional Testing
- Days 1-2: Performance testing
- Day 3: Security testing
- Day 4: Accessibility + Cross-browser
- Day 5: Usability testing

### Week 4: Integration & Finalization
- Days 1-2: Integration testing
- Days 3-4: Bug fixing and retesting
- Day 5: Final sign-off

---

## Test Environment

**Staging Environment:**
- URL: https://staging.financialrise.app
- Database: PostgreSQL (isolated from production)
- AWS S3: staging-bucket
- Redis: staging instance
- Test data: Seeded with realistic test cases

**Test Accounts:**
- Admin: admin-test@financialrise.app
- Consultant: consultant-test@financialrise.app
- Client: client-test@financialrise.app

---

## Acceptance Criteria

### Phase 3 Features
- ✅ All P0 and P1 test cases pass
- ✅ <5 P2 bugs remain open
- ✅ Zero P0 or P1 bugs in production

### Regression
- ✅ All MVP smoke tests pass
- ✅ All Phase 2 features work correctly
- ✅ No performance degradation from baseline

### Performance
- ✅ All performance thresholds met
- ✅ Load tests pass with 100 concurrent users
- ✅ Database queries optimized (<100ms avg)

### Security
- ✅ All security tests pass
- ✅ No OWASP Top 10 vulnerabilities
- ✅ Penetration test completed (if applicable)

### Accessibility
- ✅ WCAG 2.1 Level AA compliant
- ✅ Screen reader compatible
- ✅ Keyboard navigation works

### Cross-Browser
- ✅ Works on all major browsers
- ✅ Mobile-responsive on all breakpoints
- ✅ No browser-specific bugs

---

## Sign-Off

**QA Lead:** _____________________ Date: _____

**Product Manager:** _____________________ Date: _____

**Technical Lead:** _____________________ Date: _____

---

## Appendix: Test Data

### Sample Conditional Question Scenarios

**Scenario 1: S-Corp Payroll Follow-up**
```
Q1: What is your entity type?
- Options: Sole Proprietorship, LLC, S-Corp, C-Corp

Q2 (Conditional on Q1 = S-Corp): Do you have a formal payroll system?
- Condition: target_question_id = Q1, operator = 'equals', value = 'S-Corp'
```

**Scenario 2: Revenue-Based Questions**
```
Q5: What is your annual revenue?
- Type: Number

Q6 (Conditional on Q5 > 1000000): Do you have a dedicated CFO?
- Condition: target_question_id = Q5, operator = 'greater_than', value = 1000000
```

### Sample Multi-Phase Score Distributions

**Single Phase:**
```json
{
  "Stabilize": 10,
  "Organize": 5,
  "Build": 60,
  "Grow": 15,
  "Systemic": 10
}
```

**Transitioning (2 phases):**
```json
{
  "Stabilize": 5,
  "Organize": 42,
  "Build": 38,
  "Grow": 10,
  "Systemic": 5
}
```

**Multi-Phase (3+ phases):**
```json
{
  "Stabilize": 10,
  "Organize": 35,
  "Build": 30,
  "Grow": 20,
  "Systemic": 5
}
```

---

**Document Version:** 1.0
**Last Updated:** 2025-12-22
**Status:** Complete
