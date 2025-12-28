# Backend Integration Guide

**Version:** 1.0
**Date:** 2025-12-27
**Status:** Production Ready

---

## Overview

This guide explains how the Financial RISE frontend integrates with the NestJS backend API. The frontend supports **both mock and real API modes** for flexible development.

## Quick Start

### 1. Switch to Real Backend

Edit `.env`:
```bash
# Change from mock to real
VITE_USE_MOCK_API=false
VITE_API_BASE_URL=http://localhost:3000/api/v1
```

### 2. Start Backend Server

Make sure the NestJS backend is running:
```bash
cd ../financial-rise-app/backend
npm run start:dev
```

Backend should be running at `http://localhost:3000`

### 3. Start Frontend

```bash
npm run dev
```

Frontend will connect to the real backend at `http://localhost:5173`

---

## Architecture

### API Client Structure

```
src/services/
├── apiClient.ts      # Facade - switches between mock/real
├── realApi.ts        # Real backend API client
├── mockApi.ts        # Mock data for development
├── apiErrors.ts      # Error handling utilities
└── api.ts            # DEPRECATED - use realApi.ts instead
```

### How It Works

**apiClient.ts** is the single entry point for all API calls:

```typescript
import { apiClient } from '@/services/apiClient';

// This automatically uses mock or real API based on VITE_USE_MOCK_API
const assessments = await apiClient.listAssessments();
```

**Environment Variable Toggle:**
- `VITE_USE_MOCK_API=true` → Uses `mockApi.ts` (in-memory mock data)
- `VITE_USE_MOCK_API=false` → Uses `realApi.ts` (connects to backend)

---

## Environment Configuration

### Development with Mock Data

`.env`:
```bash
VITE_USE_MOCK_API=true
VITE_API_BASE_URL=http://localhost:3000/api/v1  # Not used, but keep for consistency
```

**When to use:**
- Frontend development without backend running
- UI/UX iteration
- Component development
- Testing loading/error states

### Development with Real Backend

`.env`:
```bash
VITE_USE_MOCK_API=false
VITE_API_BASE_URL=http://localhost:3000/api/v1
```

**When to use:**
- Integration testing
- End-to-end workflow testing
- API contract validation
- Before deployment

### Production

`.env.production`:
```bash
VITE_USE_MOCK_API=false
VITE_API_BASE_URL=https://api.financial-rise.com/api/v1
NODE_ENV=production
```

**Production MUST always use real API** - mock data is for development only.

---

## Authentication Flow

The real API client handles authentication automatically:

### 1. Login

```typescript
import { realApi } from '@/services/apiClient';

// Login and get tokens
const response = await realApi.login(email, password);

// Tokens are automatically stored in localStorage:
// - accessToken (15 min expiry)
// - refreshToken (7 days expiry)
```

### 2. Authenticated Requests

All subsequent API calls automatically include the access token:

```typescript
// No need to manually add Authorization header
const assessments = await apiClient.listAssessments();
```

The request interceptor automatically adds:
```http
Authorization: Bearer {accessToken}
```

### 3. Token Refresh

When the access token expires (15 minutes), the API client automatically:

1. Detects 401 Unauthorized response
2. Uses refresh token to get new access token
3. Retries the original request
4. Queues any other pending requests

**You don't need to handle token refresh manually** - it's automatic!

### 4. Logout

```typescript
await realApi.logout();

// This:
// 1. Calls backend /auth/logout to revoke refresh token
// 2. Clears tokens from localStorage
// 3. Redirects to login page
```

### Token Storage

**Access Token:**
- Stored in: `localStorage.getItem('accessToken')`
- Lifetime: 15 minutes
- Used for: All authenticated API requests

**Refresh Token:**
- Stored in: `localStorage.getItem('refreshToken')`
- Lifetime: 7 days
- Used for: Obtaining new access tokens

**Security Note:**
- In production, consider using `httpOnly` cookies for refresh tokens
- See backend CSRF-IMPLEMENTATION.md for CSRF protection

---

## API Endpoints

The real API client implements all endpoints from `API-CONTRACT.md`:

### Authentication

```typescript
// Register
await realApi.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  firstName: 'John',
  lastName: 'Doe'
});

// Login
await realApi.login('user@example.com', 'SecurePass123!');

// Logout
await realApi.logout();

// Password reset flow
await realApi.forgotPassword('user@example.com');
await realApi.resetPassword(token, 'NewPass123!');

// Change password (authenticated)
await realApi.changePassword('OldPass123!', 'NewPass123!');
```

### Assessments

```typescript
// List with pagination and filters
const { data, meta } = await apiClient.listAssessments({
  page: 1,
  limit: 20,
  status: 'in_progress',
  search: 'acme',
  sortBy: 'updatedAt',
  sortOrder: 'desc'
});

// Get single assessment
const assessment = await apiClient.getAssessment(assessmentId);

// Create
const newAssessment = await apiClient.createAssessment({
  clientName: 'John Smith',
  businessName: 'Acme Corp',
  clientEmail: 'john@acme.com'
});

// Update
await apiClient.updateAssessment(assessmentId, {
  status: 'in_progress',
  responses: [
    { questionId: 'FIN-001', answer: 'monthly' }
  ]
});

// Delete (soft delete)
await apiClient.deleteAssessment(assessmentId);
```

### Questionnaire

```typescript
// Get questions
const questionnaire = await apiClient.getQuestionnaire();

// Get questions with user responses
const questionnaire = await realApi.getQuestionnaire(assessmentId);

// Submit response
await realApi.submitResponse({
  assessmentId,
  questionId: 'FIN-001',
  answer: { value: 'monthly', text: 'Monthly' },
  consultantNotes: 'Client uses QuickBooks'
});

// Update response
await realApi.updateResponse(responseId, {
  answer: { value: 'weekly', text: 'Weekly' },
  consultantNotes: 'Updated after follow-up'
});
```

### Reports

```typescript
// Generate both reports
const { consultantReport, clientReport } = await apiClient.generateBothReports(assessmentId);

// Generate single report
const consultantReport = await apiClient.generateConsultantReport(assessmentId);
const clientReport = await apiClient.generateClientReport(assessmentId);

// Download report
const { pdfUrl } = await apiClient.downloadReport(reportId);
window.open(pdfUrl, '_blank');
```

### User Management

```typescript
// Get current user
const user = await realApi.getCurrentUser();

// Update profile
await realApi.updateCurrentUser({
  firstName: 'Jane',
  email: 'jane@example.com'
});
```

---

## Error Handling

The API client provides comprehensive error handling:

### Error Types

All API errors are instances of `ApiException`:

```typescript
import { ApiException, getToastError, logError } from '@/services/apiErrors';

try {
  await apiClient.createAssessment(data);
} catch (error) {
  if (error instanceof ApiException) {
    // Error with status code and details
    console.log(error.statusCode);  // 400, 401, 404, etc.
    console.log(error.message);     // Human-readable message
    console.log(error.details);     // Validation errors array
  }
}
```

### Helper Methods

```typescript
// Check error type
if (error.isValidationError()) {
  const errors = error.getValidationErrors();
  // { email: 'Invalid email format', password: 'Too weak' }
}

if (error.isAuthError()) {
  // Redirect to login
}

if (error.isNotFound()) {
  // Show 404 message
}

if (error.isServerError()) {
  // Show generic error message
}
```

### Display Errors in UI

```typescript
import { getToastError } from '@/services/apiErrors';

try {
  await apiClient.createAssessment(data);
} catch (error) {
  const { title, message, variant } = getToastError(error);

  // Use with your toast/notification library
  toast({
    title,
    description: message,
    variant  // 'error' or 'warning'
  });
}
```

### Validation Errors

API returns detailed validation errors:

```typescript
try {
  await realApi.register({ email: 'invalid', password: 'weak' });
} catch (error) {
  if (error.isValidationError()) {
    const errors = error.getValidationErrors();
    // errors = {
    //   email: 'Email must be a valid email address',
    //   password: 'Password must be at least 8 characters long'
    // }

    // Show errors in form
    setFormErrors(errors);
  }
}
```

### Common Error Codes

| Code | Type | Meaning | Action |
|------|------|---------|--------|
| 400 | Bad Request | Validation error | Show validation messages |
| 401 | Unauthorized | Invalid/expired token | Redirect to login (automatic) |
| 403 | Forbidden | Insufficient permissions | Show access denied |
| 404 | Not Found | Resource doesn't exist | Show not found message |
| 409 | Conflict | Duplicate resource | Show conflict message |
| 423 | Locked | Account locked | Show locked message |
| 429 | Rate Limited | Too many requests | Ask user to wait |
| 500 | Server Error | Backend error | Show generic error |

---

## Testing Workflows

### 1. Authentication Workflow

**Test Steps:**
1. Open frontend at `http://localhost:5173`
2. Register new user (should redirect to dashboard)
3. Logout
4. Login with same credentials
5. Request password reset
6. Check email for reset link
7. Reset password
8. Login with new password

**Expected Backend Behavior:**
- Registration creates user in database
- Login returns access + refresh tokens
- Tokens stored in localStorage
- Password reset email sent
- Reset token validates and expires

### 2. Assessment Workflow

**Test Steps:**
1. Login as consultant
2. Create new assessment
3. View assessment list (should show new assessment)
4. Click on assessment to open
5. Start answering questions
6. Refresh page (progress should be saved)
7. Complete all questions
8. Mark assessment as complete

**Expected Backend Behavior:**
- Assessment created with status 'draft'
- Responses saved to database
- Progress percentage calculated
- Assessment status transitions: draft → in_progress → completed

### 3. Questionnaire Workflow

**Test Steps:**
1. Open assessment
2. Answer questions one by one
3. Use "Not Applicable" for some questions
4. Add consultant notes
5. Auto-save should trigger every 30 seconds
6. Manually save
7. Navigate away and back (responses should persist)

**Expected Backend Behavior:**
- Each response saved individually
- PATCH request updates existing responses
- Progress calculated automatically
- DISC/Phase scores updated

### 4. Report Generation Workflow

**Test Steps:**
1. Complete an assessment
2. Click "Generate Reports"
3. Wait for generation (should show progress)
4. Download consultant report PDF
5. Download client report PDF
6. Verify PDFs contain correct data

**Expected Backend Behavior:**
- Report generation queued (202 Accepted)
- Status endpoint returns progress
- PDF generated with Puppeteer
- PDF uploaded to Google Cloud Storage
- Signed URL returned (8 hour expiry)

### 5. Error Scenarios

**Test these error cases:**

- **Invalid Login:**
  ```
  Try login with wrong password
  → Should show "Invalid email or password"
  ```

- **Validation Error:**
  ```
  Try create assessment with missing fields
  → Should show field-specific errors
  ```

- **Not Found:**
  ```
  Try access non-existent assessment
  → Should show 404 message
  ```

- **Token Expiry:**
  ```
  Wait 15 minutes, make API call
  → Should auto-refresh token and retry
  ```

- **Network Error:**
  ```
  Stop backend, try API call
  → Should show "Unable to reach server"
  ```

---

## CSRF Protection

The backend may implement CSRF protection. The real API client is configured to support it:

```typescript
// In realApi.ts
this.client = axios.create({
  // ...
  withCredentials: true,  // Enables cookies for CSRF tokens
});
```

**If backend uses CSRF:**
1. Backend sends CSRF token in cookie
2. Frontend includes cookie in all requests
3. Backend validates CSRF token

**No frontend code changes needed** - it's automatic with `withCredentials: true`.

---

## Rate Limiting

The backend implements rate limiting per API-CONTRACT.md:

| Endpoint | Limit | Window |
|----------|-------|--------|
| Global | 100 req/min | Per IP |
| Login | 5 attempts | 15 minutes |
| Register | 3 attempts | 1 hour |
| Password Reset | 3 attempts | 1 hour |
| Report Generation | 10 requests | 1 hour |

**Headers Returned:**
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640625600
```

**When Rate Limited (429):**
```json
{
  "statusCode": 429,
  "message": "Too many requests. Please try again in 12 minutes.",
  "error": "Too Many Requests",
  "retryAfter": 720
}
```

**Frontend Handling:**
```typescript
try {
  await realApi.login(email, password);
} catch (error) {
  if (error.isRateLimited()) {
    toast({
      title: 'Too Many Attempts',
      description: 'Please wait a few minutes and try again.',
      variant: 'warning'
    });
  }
}
```

---

## Debugging

### Enable Debug Logging

Add to `.env`:
```bash
VITE_DEBUG_MODE=true
```

### Check API Calls in DevTools

Open browser DevTools → Network tab:
- Filter by `XHR` to see API calls
- Check request headers (Authorization should have token)
- Check response status codes
- Inspect request/response bodies

### Check Tokens

In browser console:
```javascript
// Check tokens
localStorage.getItem('accessToken');
localStorage.getItem('refreshToken');

// Clear tokens
localStorage.removeItem('accessToken');
localStorage.removeItem('refreshToken');
```

### API Client Logs

The API client logs to console:
```
[API Client] Using REAL API
[API Client] Base URL: http://localhost:3000/api/v1
```

---

## Common Issues

### Issue: "Network Error" on all requests

**Cause:** Backend not running or wrong URL

**Fix:**
1. Check backend is running: `curl http://localhost:3000/api/v1`
2. Check `VITE_API_BASE_URL` in `.env`
3. Check CORS settings on backend

### Issue: "401 Unauthorized" on every request

**Cause:** Invalid or missing access token

**Fix:**
1. Check localStorage has `accessToken`
2. Try logout and login again
3. Check token expiry (15 min)
4. Check backend JWT secret matches

### Issue: "CORS error"

**Cause:** Backend CORS not configured for frontend URL

**Fix:**
Backend must allow `http://localhost:5173` in CORS origins:

```typescript
// Backend main.ts
app.enableCors({
  origin: ['http://localhost:5173', 'http://localhost:3000'],
  credentials: true,
});
```

### Issue: Auto-refresh not working

**Cause:** Refresh token expired or invalid

**Fix:**
1. Check `refreshToken` in localStorage
2. Refresh token expires after 7 days
3. Logout and login again to get new tokens

### Issue: Mock data still showing after switching to real API

**Cause:** `.env` not reloaded

**Fix:**
1. Stop dev server (Ctrl+C)
2. Update `.env`: `VITE_USE_MOCK_API=false`
3. Restart dev server: `npm run dev`
4. Hard refresh browser (Ctrl+Shift+R)

---

## Migration from Mock to Real

### Step-by-Step

1. **Ensure backend is ready:**
   ```bash
   cd ../financial-rise-app/backend
   npm run start:dev
   ```

2. **Update environment:**
   ```bash
   # .env
   VITE_USE_MOCK_API=false
   ```

3. **Restart frontend:**
   ```bash
   npm run dev
   ```

4. **Test authentication:**
   - Register a test user
   - Login
   - Verify token in localStorage

5. **Test each workflow:**
   - Create assessment
   - Answer questions
   - Generate reports

### Rollback to Mock

If real backend has issues, quickly rollback:

```bash
# .env
VITE_USE_MOCK_API=true
```

Restart dev server. No code changes needed!

---

## Production Deployment

### Environment Variables

**Production `.env`:**
```bash
VITE_USE_MOCK_API=false
VITE_API_BASE_URL=https://api.financial-rise.com/api/v1
NODE_ENV=production
```

### Build

```bash
npm run build
```

This creates optimized production build in `dist/`:
- Minified JavaScript
- Environment variables baked in
- Production API URL configured

### Verify Production Build

```bash
npm run preview
```

Test at `http://localhost:4173` with production API configuration.

### Deploy

Deploy `dist/` folder to:
- **Netlify:** Auto-deploys from git
- **Vercel:** Auto-deploys from git
- **AWS S3 + CloudFront:** Upload dist folder
- **GCP Cloud Storage:** Upload dist folder

**Important:** Set environment variables in your hosting platform's dashboard.

---

## Additional Resources

- **API Contract:** See `API-CONTRACT.md` for complete endpoint specifications
- **Backend Docs:** See `financial-rise-app/backend/README.md`
- **CSRF Guide:** See `CSRF-IMPLEMENTATION.md` for CSRF protection details
- **NestJS Migration:** See `NESTJS-CONSOLIDATION-PLAN.md` for architecture details

---

## Support

If you encounter issues:

1. Check this guide first
2. Review `API-CONTRACT.md` for endpoint specifications
3. Check backend logs: `financial-rise-app/backend/logs`
4. Enable debug mode: `VITE_DEBUG_MODE=true`
5. Check browser DevTools Network tab

---

**Last Updated:** 2025-12-27
**Author:** Frontend Agent 1
**Status:** Production Ready
**Phase:** 4.1 Complete - Backend Integration Successful
