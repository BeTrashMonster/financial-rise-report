# Staging Environment Deployment Checklist

**Financial RISE Report - Pilot Testing Deployment**
**Version:** 1.0
**Created:** 2026-01-04
**Target Deployment Date:** [Set date 1 week before pilot starts]

---

## Overview

This checklist ensures the Financial RISE MVP is properly deployed to staging and ready for pilot testing with 3-5 real users.

**Environments:**
- **Development:** Local machines (completed)
- **Staging:** Public-facing test environment for pilot (this deployment)
- **Production:** Future public launch (post-pilot)

**Deployment Stack:**
- Backend: Google Cloud Platform (GCP) VM (already deployed)
- Frontend: Vercel or Netlify (recommended for quick deployment)
- Database: GCP Cloud SQL or VM-hosted PostgreSQL
- File Storage: GCP Cloud Storage (for PDF reports)

---

## Pre-Deployment Preparation

### 1. Backend Verification (GCP VM)

**Current Status Check:**
- [ ] SSH into GCP VM: `gcloud compute ssh financial-rise-vm --zone=us-central1-a`
- [ ] Verify backend is running: `pm2 status` or check process
- [ ] Verify API responds: `curl http://localhost:3000/api/v1/health`
- [ ] Check recent logs for errors: `pm2 logs` or `journalctl -u financial-rise-backend`

**API Endpoints Smoke Test:**
```bash
# Test health endpoint
curl https://api-staging.financial-rise.app/api/v1/health

# Test auth endpoints (expect 400/401, but should not 500)
curl -X POST https://api-staging.financial-rise.app/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test"}'

# Test questionnaire endpoints
curl https://api-staging.financial-rise.app/api/v1/questionnaire/questions
```

**Expected Results:**
- Health endpoint returns 200 OK
- Login endpoint returns structured error (not 500)
- Questions endpoint returns array of questions

---

**Database Verification:**
- [ ] Connect to staging database
- [ ] Verify migrations are up to date: Check `migrations` table
- [ ] Verify tables exist: `users`, `assessments`, `questions`, `responses`, `reports`
- [ ] Seed database with 2-3 test users for pilot participants

```sql
-- Verify database schema
\dt  -- List tables (PostgreSQL)
SELECT * FROM migrations ORDER BY id DESC LIMIT 5;  -- Check migrations
SELECT COUNT(*) FROM users;  -- Should have test users
SELECT COUNT(*) FROM questions;  -- Should have ~50+ questions
```

---

**PDF Generation Verification:**
- [ ] Verify Puppeteer dependencies installed on GCP VM
- [ ] Test PDF generation manually via API call:

```bash
# Create test assessment first, then:
curl -X POST https://api-staging.financial-rise.app/api/v1/reports/generate/consultant \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"assessmentId":"test-assessment-id"}'
```

- [ ] Verify PDF file created in storage
- [ ] Verify PDF downloads successfully

---

**Environment Variables Check:**
- [ ] Verify `.env` file on GCP VM has staging-appropriate values:

```bash
# View env file (sanitized - don't expose secrets)
cat /path/to/backend/.env | grep -v "PASSWORD\|SECRET\|KEY"
```

**Required Environment Variables:**
- `NODE_ENV=production` (or `staging`)
- `DATABASE_URL=postgresql://...` (staging database)
- `JWT_SECRET=...` (secure random string)
- `JWT_REFRESH_SECRET=...` (different from JWT_SECRET)
- `CORS_ORIGIN=https://staging.financial-rise.app` (frontend URL)
- `STORAGE_BUCKET=financial-rise-staging` (GCP bucket for PDFs)
- `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` (email for password resets)

---

### 2. Frontend Build & Preparation

**Build Production Frontend:**
```bash
cd financial-rise-app/frontend

# Install dependencies
npm install

# Run production build
npm run build

# Verify build succeeded
ls -lah dist/  # or build/ depending on config

# Test production build locally (optional)
npx serve -s dist -p 3001
# Open http://localhost:3001 and test
```

**Build Checklist:**
- [ ] Build completes without TypeScript errors
- [ ] Build completes without linting errors
- [ ] Build size is reasonable (<2MB total, <500KB JS bundle)
- [ ] No console warnings about missing environment variables

---

**Environment Variables for Frontend:**

Create `.env.production` file:
```bash
# Staging environment variables
VITE_API_URL=https://api-staging.financial-rise.app/api/v1
VITE_APP_NAME=Financial RISE Report
VITE_ENVIRONMENT=staging
```

**Rebuild with production env:**
```bash
npm run build
```

---

### 3. Frontend Deployment (Vercel)

**Option A: Deploy to Vercel (Recommended)**

1. **Install Vercel CLI:**
```bash
npm install -g vercel
```

2. **Login to Vercel:**
```bash
vercel login
```

3. **Deploy to Vercel:**
```bash
cd financial-rise-app/frontend

# First deployment (will prompt for project settings)
vercel --prod

# Follow prompts:
# - Set project name: financial-rise-staging
# - Link to existing project? No
# - Deploy to production? Yes
```

4. **Configure Environment Variables in Vercel Dashboard:**
   - Go to Vercel project settings → Environment Variables
   - Add `VITE_API_URL` = `https://api-staging.financial-rise.app/api/v1`
   - Add `VITE_ENVIRONMENT` = `staging`
   - Redeploy after adding env vars

5. **Custom Domain (Optional but Recommended):**
   - Go to Vercel project settings → Domains
   - Add domain: `staging.financial-rise.app`
   - Update DNS records as instructed by Vercel
   - Wait for SSL certificate provisioning (~a few minutes)

**Vercel Deployment Checklist:**
- [ ] Deployment succeeded (green checkmark in Vercel dashboard)
- [ ] Site is accessible at Vercel URL (e.g., `financial-rise-staging.vercel.app`)
- [ ] Custom domain configured (if using)
- [ ] SSL certificate active (https works)
- [ ] Environment variables set in Vercel dashboard
- [ ] Redeployed after setting env vars

---

**Option B: Deploy to Netlify (Alternative)**

1. **Install Netlify CLI:**
```bash
npm install -g netlify-cli
```

2. **Login to Netlify:**
```bash
netlify login
```

3. **Deploy to Netlify:**
```bash
cd financial-rise-app/frontend

# Deploy
netlify deploy --prod

# Follow prompts - select build directory (dist/ or build/)
```

4. **Configure Environment Variables:**
   - Go to Netlify site settings → Build & deploy → Environment
   - Add `VITE_API_URL`, `VITE_ENVIRONMENT`

---

### 4. CORS Configuration

**Update Backend CORS Settings:**

Edit backend `.env` on GCP VM:
```bash
CORS_ORIGIN=https://staging.financial-rise.app,https://financial-rise-staging.vercel.app
```

Or in backend code (`src/index.ts` or `src/app.ts`):
```typescript
app.use(cors({
  origin: [
    'https://staging.financial-rise.app',
    'https://financial-rise-staging.vercel.app',
    'http://localhost:3000'  // For local testing
  ],
  credentials: true
}));
```

**Restart Backend:**
```bash
# On GCP VM
pm2 restart financial-rise-backend
# or
systemctl restart financial-rise-backend
```

**Test CORS:**
```bash
curl -X OPTIONS https://api-staging.financial-rise.app/api/v1/auth/login \
  -H "Origin: https://staging.financial-rise.app" \
  -H "Access-Control-Request-Method: POST" \
  -v
```

Expected: `Access-Control-Allow-Origin` header in response

---

## Deployment Testing

### 5. Smoke Tests

**Test 1: Frontend Loads**
- [ ] Navigate to `https://staging.financial-rise.app`
- [ ] Verify page loads without errors
- [ ] Open browser console - verify no JavaScript errors
- [ ] Verify no CORS errors in console

**Test 2: Authentication Flow**
- [ ] Click "Login" or navigate to `/login`
- [ ] Enter test credentials
- [ ] Submit login form
- [ ] Verify successful login and redirect to dashboard
- [ ] Verify navigation bar appears
- [ ] Logout and verify redirect to login

**Test 3: Create Assessment**
- [ ] Login with test user
- [ ] Navigate to "New Assessment"
- [ ] Fill out assessment form
- [ ] Submit form
- [ ] Verify success message or redirect to questionnaire

**Test 4: Complete Questionnaire**
- [ ] Start questionnaire from assessment
- [ ] Answer at least 5 questions
- [ ] Verify auto-save works (check network tab for PATCH requests)
- [ ] Submit partial questionnaire (click "Save and Exit")
- [ ] Return to questionnaire - verify answers persisted
- [ ] Complete entire questionnaire
- [ ] Submit final questionnaire
- [ ] Verify redirect to results page

**Test 5: View Results**
- [ ] Navigate to results page for completed assessment
- [ ] Verify DISC profile displays
- [ ] Verify phase results display
- [ ] Verify charts render correctly

**Test 6: Generate Reports**
- [ ] On results page, click "Generate Consultant Report"
- [ ] Wait for generation (should be <5 seconds)
- [ ] Verify success message
- [ ] Click "Download" button
- [ ] Verify PDF downloads successfully
- [ ] Open PDF and verify content looks professional
- [ ] Repeat for Client Report

**Test 7: Dashboard**
- [ ] Navigate to dashboard
- [ ] Verify statistics cards display correct counts
- [ ] Verify recent assessments table populated
- [ ] Click "View Results" on an assessment
- [ ] Verify navigation works

**Test 8: User Profile**
- [ ] Navigate to user profile
- [ ] Edit profile information
- [ ] Save changes
- [ ] Verify success message
- [ ] Reload page - verify changes persisted

**Test 9: Mobile Responsiveness**
- [ ] Open staging site on mobile device (iPhone/Android)
- [ ] Navigate through same user journey
- [ ] Verify hamburger menu works
- [ ] Verify forms are mobile-friendly
- [ ] Verify reports download on mobile

---

### 6. Performance Testing

**Lighthouse Audit:**
```bash
# Install Lighthouse CLI
npm install -g lighthouse

# Run audit on staging site
lighthouse https://staging.financial-rise.app \
  --output html \
  --output-path ./lighthouse-staging-report.html \
  --preset desktop

# Open report
open lighthouse-staging-report.html  # macOS
start lighthouse-staging-report.html  # Windows
```

**Performance Targets:**
- [ ] Performance score: >80
- [ ] Accessibility score: >95 ✅ (critical for pilot)
- [ ] Best Practices score: >90
- [ ] SEO score: >80

**Page Load Times:**
- [ ] Homepage: <3 seconds
- [ ] Dashboard: <3 seconds
- [ ] Questionnaire: <3 seconds
- [ ] Results: <3 seconds

**API Response Times:**
- [ ] GET /questionnaire/questions: <1 second
- [ ] POST /questionnaire/responses: <500ms
- [ ] POST /assessments/:id/calculate: <2 seconds
- [ ] POST /reports/generate: <5 seconds ✅ (critical)

---

### 7. Accessibility Testing

**axe DevTools Audit:**
- [ ] Install axe DevTools browser extension
- [ ] Navigate to each page:
  - [ ] Login
  - [ ] Dashboard
  - [ ] Assessment List
  - [ ] Create Assessment
  - [ ] Questionnaire
  - [ ] Results
  - [ ] User Profile
- [ ] Run axe scan on each page
- [ ] Target: Zero violations ✅ (critical for legal compliance)
- [ ] Document any violations and fix before pilot

**Keyboard Navigation Test:**
- [ ] Disconnect mouse
- [ ] Complete full user journey using only keyboard (Tab, Enter, Esc, Arrow keys)
- [ ] Verify all interactive elements are reachable
- [ ] Verify skip link appears when pressing Tab on page load
- [ ] Verify focus indicators are visible
- [ ] Verify no keyboard traps

**Screen Reader Test (Optional but Recommended):**
- [ ] Install NVDA (Windows) or use VoiceOver (macOS)
- [ ] Navigate through login and create assessment flows
- [ ] Verify all buttons/links announce their purpose
- [ ] Verify form labels are read correctly

---

### 8. Browser Compatibility Testing

**Test on Multiple Browsers:**
- [ ] Chrome 90+ (Windows/macOS/Linux)
- [ ] Firefox 88+ (Windows/macOS/Linux)
- [ ] Safari 14+ (macOS/iOS)
- [ ] Edge 90+ (Windows)

**Cross-Browser Checklist for Each:**
- [ ] Login works
- [ ] Assessment creation works
- [ ] Questionnaire works (especially sliders and radio buttons)
- [ ] Reports generate and download
- [ ] No console errors
- [ ] UI renders correctly (no layout breaks)

---

### 9. Monitoring & Logging Setup

**Error Monitoring (Sentry):**

1. **Install Sentry (if not already):**
```bash
cd financial-rise-app/frontend
npm install @sentry/react @sentry/tracing
```

2. **Configure Sentry in Frontend:**

Edit `src/main.tsx` or `src/index.tsx`:
```typescript
import * as Sentry from "@sentry/react";
import { BrowserTracing } from "@sentry/tracing";

Sentry.init({
  dsn: "YOUR_SENTRY_DSN",
  environment: "staging",
  integrations: [new BrowserTracing()],
  tracesSampleRate: 1.0,  // 100% of transactions in staging
});
```

3. **Configure Sentry in Backend (if not already):**
```typescript
import * as Sentry from "@sentry/node";

Sentry.init({
  dsn: "YOUR_SENTRY_DSN",
  environment: "staging",
  tracesSampleRate: 1.0,
});
```

4. **Test Error Reporting:**
- [ ] Trigger test error in frontend (throw new Error("Test"))
- [ ] Verify error appears in Sentry dashboard
- [ ] Trigger test error in backend (500 endpoint)
- [ ] Verify error appears in Sentry dashboard

---

**Analytics (Google Analytics or Mixpanel):**

1. **Add Google Analytics 4:**

```bash
npm install react-ga4
```

Edit `src/App.tsx`:
```typescript
import ReactGA from 'react-ga4';

ReactGA.initialize('G-XXXXXXXXXX'); // Your GA4 Measurement ID

function App() {
  useEffect(() => {
    ReactGA.send({ hitType: "pageview", page: window.location.pathname });
  }, []);

  // rest of component
}
```

2. **Track Key Events:**
- Assessment created
- Questionnaire started
- Questionnaire completed
- Report generated
- Report downloaded

3. **Verify Analytics:**
- [ ] Open Google Analytics dashboard
- [ ] Navigate through staging site
- [ ] Verify events appear in real-time dashboard

---

**Uptime Monitoring:**

1. **Set up Uptime Robot (free tier):**
- Go to uptimerobot.com
- Create monitor for `https://staging.financial-rise.app`
- Create monitor for `https://api-staging.financial-rise.app/api/v1/health`
- Set check interval to a few minutes
- Add email alert for downtime

2. **Checklist:**
- [ ] Frontend monitor active
- [ ] Backend monitor active
- [ ] Alert email configured
- [ ] Test alert by taking backend offline briefly

---

### 10. Security Checks

**SSL Certificate:**
- [ ] Verify HTTPS works on staging frontend
- [ ] Verify HTTPS works on staging backend API
- [ ] Verify no mixed content warnings (HTTP resources on HTTPS page)
- [ ] Check SSL certificate validity: https://www.ssllabs.com/ssltest/

**API Security Headers:**
```bash
curl -I https://api-staging.financial-rise.app/api/v1/health
```

Verify headers include:
- [ ] `X-Content-Type-Options: nosniff`
- [ ] `X-Frame-Options: DENY` or `SAMEORIGIN`
- [ ] `Strict-Transport-Security: max-age=...` (if using HTTPS)
- [ ] `Content-Security-Policy: ...`

**Authentication:**
- [ ] Verify JWT tokens expire (check token expiry time)
- [ ] Verify refresh token rotation works
- [ ] Verify logout invalidates tokens
- [ ] Verify protected routes redirect to login when unauthenticated

**Input Validation:**
- [ ] Test XSS in form inputs (e.g., `<script>alert('xss')</script>`)
- [ ] Verify inputs are sanitized (no script execution)
- [ ] Test SQL injection in email field (e.g., `admin'--`)
- [ ] Verify database queries are parameterized (no SQL injection)

---

### 11. Data Privacy & GDPR Compliance

**Privacy Policy:**
- [ ] Privacy policy page accessible at `/privacy`
- [ ] Privacy policy mentions data collection (analytics, cookies)
- [ ] Privacy policy includes contact information

**Cookie Consent (if using cookies):**
- [ ] Cookie banner appears on first visit (if required for analytics)
- [ ] Users can opt out of analytics cookies

**Data Export/Deletion:**
- [ ] Ensure backend has endpoints for data export (GDPR right to access)
- [ ] Ensure backend has endpoints for account deletion (GDPR right to erasure)
- [ ] Document process for handling data requests

---

### 12. Pilot User Setup

**Create Pilot User Accounts:**
- [ ] Manually create 5 user accounts via backend API or database insert
- [ ] Use real email addresses for pilot participants
- [ ] Set temporary passwords
- [ ] Send welcome emails with login credentials

**Welcome Email Template:**
```
Subject: Welcome to Financial RISE Pilot - Your Login Credentials

Hi [Participant Name],

Welcome to the Financial RISE pilot program! We're excited to have you test our new assessment tool.

**Your Login Credentials:**
- URL: https://staging.financial-rise.app
- Email: [participant-email@example.com]
- Temporary Password: [TemporaryPassword123]

**Please change your password after first login** (go to Profile → Change Password)

**Next Steps:**
1. Log in and explore the dashboard
2. Create your first assessment (we recommend starting with a familiar client)
3. Complete the questionnaire (20-appropriate time)
4. Generate and review the reports

**Support:**
- Email: support@financial-rise.com (response within promptly during business hours)
- Phone: [Phone] (emergency only)

We've scheduled your onboarding call for [Date/Time]. Looking forward to hearing your feedback!

Thanks,
[Your Name]
```

---

### 13. Final Pre-Pilot Checklist

**24 Hours Before Pilot Starts:**
- [ ] All smoke tests passed
- [ ] Performance targets met (Lighthouse >80)
- [ ] Accessibility targets met (Lighthouse >95, axe zero violations)
- [ ] Browser compatibility verified
- [ ] Monitoring and logging active
- [ ] Error alerts configured
- [ ] Pilot user accounts created
- [ ] Welcome emails sent to all participants
- [ ] Onboarding calls scheduled
- [ ] Support process established (email, phone)
- [ ] Known issues documented
- [ ] FAQ document created
- [ ] Deployment rollback plan ready (if needed)

**Emergency Rollback Plan:**
- If critical issues discovered during pilot:
  1. Take staging site offline temporarily
  2. Fix issues on local development
  3. Redeploy to staging
  4. Re-run smoke tests
  5. Notify pilot participants of downtime and fixes

---

## Deployment Completion Sign-Off

**Deployed By:** _______________
**Date:** _______________
**Staging URLs:**
- Frontend: _______________
- Backend API: _______________

**Sign-Off:**
- [ ] All tests passed
- [ ] Monitoring active
- [ ] Pilot participants notified
- [ ] Ready for pilot testing

---

**Document Version:** 1.0
**Last Updated:** 2026-01-04
**Next Review:** After pilot testing completion
