# CSRF Protection Implementation Guide

## Backend Implementation (NestJS) - COMPLETED

The backend implements CSRF protection using the **Double-Submit Cookie Pattern**, which is suitable for Single Page Applications (SPAs) with JWT authentication.

### How It Works

1. **CSRF Interceptor** (`src/common/interceptors/csrf.interceptor.ts`)
   - Automatically sets a `XSRF-TOKEN` cookie on all responses
   - Cookie is readable by client JavaScript (httpOnly=false)
   - Token is a random 32-byte hex string
   - Valid for 24 hours

2. **CSRF Guard** (`src/common/guards/csrf.guard.ts`)
   - Validates CSRF tokens on state-changing requests (POST, PUT, PATCH, DELETE)
   - Skips validation for read-only requests (GET, HEAD, OPTIONS)
   - Compares cookie value with `X-CSRF-Token` header value
   - Throws 403 Forbidden if tokens don't match or are missing

### Backend Configuration

To enable CSRF protection globally, add to `main.ts`:

```typescript
import { CsrfInterceptor } from './common/interceptors/csrf.interceptor';
import { CsrfGuard } from './common/guards/csrf.guard';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Enable cookie parser (required for CSRF)
  app.use(cookieParser());

  // Apply CSRF interceptor globally to set tokens
  app.useGlobalInterceptors(new CsrfInterceptor());

  // Apply CSRF guard globally to validate tokens
  // NOTE: This is optional - can also be applied per-route
  // app.useGlobalGuards(new CsrfGuard(app.get(Reflector)));

  await app.listen(3000);
}
```

**Important:** Installing `cookie-parser` is required:
```bash
npm install cookie-parser
npm install -D @types/cookie-parser
```

---

## Frontend Implementation (React) - REQUIRED

The frontend must read the CSRF cookie and include it in request headers.

### Step 1: Install Cookie Library (Optional)

```bash
npm install js-cookie
npm install -D @types/js-cookie
```

### Step 2: Create CSRF Utility

Create `src/utils/csrf.ts`:

```typescript
import Cookies from 'js-cookie';

const CSRF_COOKIE_NAME = 'XSRF-TOKEN';
const CSRF_HEADER_NAME = 'X-CSRF-Token';

/**
 * Gets the CSRF token from cookies
 */
export function getCsrfToken(): string | undefined {
  return Cookies.get(CSRF_COOKIE_NAME);
}

/**
 * Adds CSRF token to request headers
 */
export function addCsrfHeaders(headers: Record<string, string> = {}): Record<string, string> {
  const csrfToken = getCsrfToken();

  if (csrfToken) {
    headers[CSRF_HEADER_NAME] = csrfToken;
  }

  return headers;
}
```

### Step 3: Update API Client

Update your API client to include CSRF tokens in all state-changing requests:

#### Option A: Axios Interceptor

```typescript
import axios from 'axios';
import { addCsrfHeaders } from './utils/csrf';

const apiClient = axios.create({
  baseURL: process.env.REACT_APP_API_URL,
  withCredentials: true, // Required to send/receive cookies
});

// Add CSRF token to all requests
apiClient.interceptors.request.use((config) => {
  config.headers = addCsrfHeaders(config.headers);
  return config;
});

export default apiClient;
```

#### Option B: Fetch API Wrapper

```typescript
import { getCsrfToken } from './utils/csrf';

async function apiRequest(url: string, options: RequestInit = {}): Promise<Response> {
  const csrfToken = getCsrfToken();

  const headers = {
    'Content-Type': 'application/json',
    ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
    ...options.headers,
  };

  return fetch(url, {
    ...options,
    headers,
    credentials: 'include', // Required to send/receive cookies
  });
}

export default apiRequest;
```

### Step 4: Test CSRF Protection

1. **Initial Request:**
   - Frontend makes first API call (e.g., GET /api/v1/auth/me)
   - Backend sets `XSRF-TOKEN` cookie in response
   - Frontend stores cookie automatically

2. **Subsequent State-Changing Requests:**
   - Frontend reads `XSRF-TOKEN` cookie
   - Frontend includes token in `X-CSRF-Token` header
   - Backend validates cookie matches header
   - Request succeeds

3. **CSRF Attack Attempt:**
   - Attacker tries to make POST request from malicious site
   - Attacker CAN'T read victim's `XSRF-TOKEN` cookie (Same-Origin Policy)
   - Attacker CAN'T set custom headers on cross-origin request
   - Request fails with 403 Forbidden

---

## Testing CSRF Protection

### Manual Testing

1. **Test Valid Request:**
```bash
# Get CSRF token
curl -c cookies.txt http://localhost:3000/api/v1/auth/me

# Extract token from cookies
CSRF_TOKEN=$(grep XSRF-TOKEN cookies.txt | awk '{print $7}')

# Make request with token
curl -b cookies.txt \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -X POST http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{"clientName": "Test"}'

# Should succeed ✅
```

2. **Test Missing Token:**
```bash
# Request without X-CSRF-Token header
curl -b cookies.txt \
  -X POST http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{"clientName": "Test"}'

# Should fail with 403 Forbidden ❌
```

3. **Test Token Mismatch:**
```bash
# Request with wrong token
curl -b cookies.txt \
  -H "X-CSRF-Token: wrong-token" \
  -X POST http://localhost:3000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{"clientName": "Test"}'

# Should fail with 403 Forbidden ❌
```

### Automated Tests

```typescript
describe('CSRF Protection', () => {
  it('should set CSRF cookie on first request', async () => {
    const response = await request(app.getHttpServer())
      .get('/api/v1/auth/me');

    expect(response.headers['set-cookie']).toBeDefined();
    expect(response.headers['set-cookie'][0]).toContain('XSRF-TOKEN');
  });

  it('should reject POST without CSRF token', async () => {
    await request(app.getHttpServer())
      .post('/api/v1/assessments')
      .send({ clientName: 'Test' })
      .expect(403);
  });

  it('should accept POST with valid CSRF token', async () => {
    // Get token
    const getResponse = await request(app.getHttpServer())
      .get('/api/v1/auth/me');

    const cookies = getResponse.headers['set-cookie'];
    const csrfToken = cookies[0].match(/XSRF-TOKEN=([^;]+)/)[1];

    // Use token
    await request(app.getHttpServer())
      .post('/api/v1/assessments')
      .set('Cookie', cookies)
      .set('X-CSRF-Token', csrfToken)
      .send({ clientName: 'Test' })
      .expect(201);
  });
});
```

---

## Important Notes

### Why Not Traditional CSRF Tokens?

Traditional CSRF protection (like csurf package) uses:
- Server-side session storage
- Synchronizer tokens embedded in forms
- Works well for server-rendered HTML

Our SPA uses:
- JWT tokens (not session cookies)
- Client-side routing
- RESTful API (not form submissions)

**Double-submit cookie pattern is more appropriate for SPAs.**

### Is CSRF Protection Necessary for JWT?

**Technically, no** - if JWTs are stored in localStorage/sessionStorage:
- Browsers don't automatically send localStorage data
- CSRF attacks require automatic credential transmission
- JWT-based APIs are naturally resistant to CSRF

**However, defense-in-depth is good practice:**
- Protects against future architectural changes
- Protects if cookies are used for any reason
- Demonstrates security best practices
- Required for security compliance audits

### SameSite Cookie Attribute

The `sameSite: 'strict'` attribute provides additional CSRF protection:
- Prevents cookies from being sent on cross-site requests
- Modern browsers support this
- Acts as a second layer of defense

**Browser support:**
- Chrome 51+, Firefox 60+, Safari 12+
- Fully supported in all modern browsers

---

## Deployment Checklist

- [ ] Backend: Cookie parser installed and configured
- [ ] Backend: CSRF interceptor applied globally
- [ ] Backend: CSRF guard applied (globally or per-route)
- [ ] Frontend: CSRF utility functions created
- [ ] Frontend: API client configured to send CSRF headers
- [ ] Frontend: `withCredentials: true` set for Axios or `credentials: 'include'` for Fetch
- [ ] Testing: CSRF protection verified in development
- [ ] Testing: E2E tests include CSRF token handling
- [ ] Production: HTTPS enforced (`secure: true` for cookies)
- [ ] Production: CORS configured correctly
- [ ] Documentation: Frontend team aware of CSRF requirements

---

## Troubleshooting

### "CSRF token missing" error

**Cause:** Frontend not sending `X-CSRF-Token` header

**Solution:**
1. Verify cookie-parser is installed and configured
2. Check that `withCredentials: true` (Axios) or `credentials: 'include'` (Fetch)
3. Verify cookie is being set (check browser DevTools → Application → Cookies)
4. Ensure CSRF header is being added to requests

### "CSRF token mismatch" error

**Cause:** Cookie token doesn't match header token

**Solution:**
1. Check for typos in header name (should be `X-CSRF-Token`)
2. Verify cookie name matches (`XSRF-TOKEN`)
3. Clear cookies and get fresh token
4. Check for cookie domain/path issues

### CSRF cookie not being set

**Cause:** CORS or cookie configuration issue

**Solution:**
1. Verify CORS allows credentials: `credentials: true`
2. Check cookie SameSite attribute
3. Ensure frontend and backend on same domain (or properly configured CORS)
4. In development: Use `secure: false`; in production: Use `secure: true` with HTTPS

---

**Last Updated:** 2025-12-27
**Version:** 1.0
**Maintained By:** Backend Team
