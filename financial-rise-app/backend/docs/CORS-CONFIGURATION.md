# CORS Configuration Documentation

**Work Stream:** 59 (HIGH-010)
**Security Finding:** CORS misconfiguration risk
**OWASP Category:** A05:2021 - Security Misconfiguration
**CWE:** CWE-346 - Origin Validation Error
**Status:** Implemented
**Last Updated:** 2025-12-28

---

## Overview

The Financial RISE Report application implements a hardened CORS (Cross-Origin Resource Sharing) configuration to prevent unauthorized cross-origin requests while allowing legitimate frontend applications to communicate with the backend API.

## Security Objectives

1. **Origin Validation:** Only allow requests from explicitly whitelisted origins
2. **Logging:** Log all blocked CORS requests for security monitoring
3. **Explicit Configuration:** Define allowed methods and headers explicitly
4. **Credential Protection:** Ensure credentials are only sent to whitelisted origins
5. **Attack Prevention:** Prevent CORS-based attacks including CSRF and data exfiltration

## Configuration

### Location

- **Configuration File:** `src/config/cors.config.ts`
- **Applied In:** `src/main.ts` (bootstrap function)
- **Test Suite:** `src/security/cors-configuration.spec.ts`

### Whitelisted Origins

The application maintains a strict whitelist of allowed origins:

```typescript
const allowedOrigins = [
  'http://localhost:3001',           // Default frontend development server
  'http://localhost:5173',           // Vite development server
  process.env.FRONTEND_URL,          // Production frontend URL
  process.env.FRONTEND_URL_STAGING,  // Staging frontend URL
];
```

**Important:** Origins must match **exactly** including:
- Protocol (http vs https)
- Domain (case-sensitive)
- Port number

### Environment Variables

Configure production and staging URLs via environment variables:

```bash
# Production frontend URL
FRONTEND_URL=https://app.financialrise.com

# Staging frontend URL (optional)
FRONTEND_URL_STAGING=https://staging.financialrise.com
```

## Allowed Methods

Only the following HTTP methods are allowed:

- `GET` - Retrieve resources
- `POST` - Create resources
- `PUT` - Replace resources
- `PATCH` - Update resources
- `DELETE` - Delete resources
- `OPTIONS` - Preflight requests

**Blocked methods:** TRACE, CONNECT, and other dangerous methods are explicitly excluded.

## Allowed Request Headers

The following headers are allowed in cross-origin requests:

- `Content-Type` - Request content type
- `Authorization` - JWT tokens
- `X-CSRF-Token` - CSRF protection token
- `X-Requested-With` - AJAX request indicator
- `Accept` - Response content type preferences
- `Accept-Version` - API version negotiation
- `Content-Length` - Request body length
- `Content-MD5` - Request body checksum
- `Date` - Request timestamp
- `X-Api-Version` - API version header

## Exposed Response Headers

The following response headers are exposed to frontend JavaScript:

- `X-Total-Count` - Total number of items (pagination)
- `X-Page-Number` - Current page number
- `X-Page-Size` - Items per page
- `X-RateLimit-Limit` - Rate limit maximum
- `X-RateLimit-Remaining` - Rate limit remaining requests
- `X-RateLimit-Reset` - Rate limit reset timestamp

## Preflight Caching

Preflight OPTIONS requests are cached for **1 hour (3600 seconds)** to reduce overhead while maintaining security.

```typescript
maxAge: 3600, // Cache preflight for 1 hour
```

Adjust this value if origins change frequently or if stricter cache control is needed.

## Security Features

### 1. Origin Validation Callback

The configuration uses a custom validation function that:

```typescript
function validateOrigin(
  origin: string | undefined,
  callback: (err: Error | null, allow?: boolean) => void
) {
  // Allow requests with no origin (mobile apps, Postman)
  if (!origin) {
    return callback(null, true);
  }

  // Check whitelist
  if (allowedOrigins.includes(origin)) {
    return callback(null, true);
  }

  // Block and log unauthorized origins
  logger.warn(`🚫 CORS: Blocked request from unauthorized origin: ${origin}`);
  callback(new Error('Not allowed by CORS'));
}
```

### 2. Security Logging

All blocked CORS requests are logged with the following information:

```json
{
  "origin": "http://evil.com",
  "timestamp": "2025-12-28T10:30:00.000Z",
  "securityEvent": "CORS_ORIGIN_BLOCKED",
  "severity": "MEDIUM"
}
```

These logs can be ingested by SIEM systems for security monitoring.

### 3. Credentials Handling

The configuration enables credentials (cookies, authorization headers):

```typescript
credentials: true,
```

**Critical:** When `credentials: true`, the origin **MUST NOT** be a wildcard (`*`). Our implementation uses a strict whitelist to comply with this requirement.

### 4. No Origin Requests

Requests without an `Origin` header (e.g., from mobile apps, Postman, server-to-server) are currently **allowed**.

**Security Note:** If the API should only be accessible via web browsers, modify the configuration to reject requests without an origin:

```typescript
if (!origin) {
  logger.warn('CORS: Request with no origin header - rejecting');
  return callback(new Error('Origin header required'));
}
```

## Usage Examples

### Development Frontend (React/Vue)

```javascript
// Axios configuration
const api = axios.create({
  baseURL: 'http://localhost:3000/api/v1',
  withCredentials: true, // Include cookies
  headers: {
    'Content-Type': 'application/json',
  },
});
```

### Production Frontend

```javascript
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL, // https://api.financialrise.com/api/v1
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken(), // Include CSRF token
  },
});
```

## Testing

### Running CORS Tests

```bash
npm test -- src/security/cors-configuration.spec.ts
```

### Test Coverage

The test suite includes:

- ✅ Whitelisted origin validation
- ✅ Unauthorized origin blocking
- ✅ Null origin handling
- ✅ HTTP method validation
- ✅ Request header validation
- ✅ Response header exposure
- ✅ Credentials configuration
- ✅ Preflight caching
- ✅ End-to-end CORS workflows
- ✅ Security edge cases (injection, case sensitivity, subdomain attacks)

### Manual Testing

#### Test Allowed Origin

```bash
curl -X OPTIONS http://localhost:3000/api/v1/auth/login \
  -H "Origin: http://localhost:3001" \
  -H "Access-Control-Request-Method: POST" \
  -v
```

**Expected:** Status 200, `Access-Control-Allow-Origin: http://localhost:3001`

#### Test Blocked Origin

```bash
curl -X OPTIONS http://localhost:3000/api/v1/auth/login \
  -H "Origin: http://evil.com" \
  -H "Access-Control-Request-Method: POST" \
  -v
```

**Expected:** No `Access-Control-Allow-Origin` header, request blocked

## Deployment

### Environment-Specific Configuration

#### Development

```bash
# .env.development
FRONTEND_URL=http://localhost:3001
```

#### Staging

```bash
# .env.staging
FRONTEND_URL=https://staging-app.financialrise.com
FRONTEND_URL_STAGING=https://staging2-app.financialrise.com
```

#### Production

```bash
# .env.production
FRONTEND_URL=https://app.financialrise.com
```

**Critical:** Never commit `.env` files to version control. Use GCP Secret Manager for production secrets.

## Monitoring

### Log Queries

Monitor blocked CORS requests in your logging system:

```javascript
// GCP Logging Query
resource.type="cloud_run_revision"
jsonPayload.securityEvent="CORS_ORIGIN_BLOCKED"
severity>=WARNING
```

### Alerts

Set up alerts for unusual CORS blocking patterns:

- **Alert:** >10 blocked CORS requests from same origin in 5 minutes
- **Alert:** CORS blocks from unexpected geographic regions
- **Alert:** CORS blocks outside business hours

## Troubleshooting

### Common Issues

#### Issue: Legitimate requests being blocked

**Symptom:** `Access-Control-Allow-Origin` header missing
**Cause:** Origin not in whitelist or protocol/port mismatch

**Solution:**
1. Check origin matches exactly (including protocol and port)
2. Add origin to `allowedOrigins` in `cors.config.ts`
3. Or set `FRONTEND_URL` environment variable

#### Issue: Credentials not being sent

**Symptom:** Cookies or Authorization headers missing
**Cause:** Frontend not configured to send credentials

**Solution:**
```javascript
// Axios
axios.defaults.withCredentials = true;

// Fetch
fetch(url, { credentials: 'include' });
```

#### Issue: Custom headers being blocked

**Symptom:** Preflight failing for custom headers
**Cause:** Header not in `allowedHeaders` list

**Solution:** Add header to `allowedHeaders` in `cors.config.ts`

#### Issue: Response headers not accessible in JavaScript

**Symptom:** Cannot read header value in frontend
**Cause:** Header not in `exposedHeaders` list

**Solution:** Add header to `exposedHeaders` in `cors.config.ts`

## Security Best Practices

### 1. Keep Whitelist Minimal

Only add origins that absolutely need API access. Remove origins that are no longer in use.

### 2. Use HTTPS in Production

**Development:** `http://localhost:3001` (acceptable)
**Production:** `https://app.financialrise.com` (required)

Never allow HTTP origins in production.

### 3. Monitor CORS Logs

Regularly review CORS blocking logs to identify:
- Misconfigured frontends
- Potential attacks
- Origins that need to be whitelisted

### 4. Coordinate with CSRF Protection

CORS and CSRF protection work together:
- CORS prevents unauthorized origins
- CSRF tokens prevent forged requests from allowed origins

Both are required for complete protection.

### 5. Review Periodically

Schedule quarterly reviews of:
- Whitelisted origins (remove unused)
- Allowed methods (restrict if possible)
- Exposed headers (minimize surface)
- Blocked request logs (identify patterns)

## References

- **Security Audit:** `SECURITY-AUDIT-REPORT.md` Lines 1255-1309
- **OWASP:** [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- **CWE:** [CWE-346 - Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- **MDN:** [CORS Documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- **W3C:** [CORS Specification](https://www.w3.org/TR/cors/)

## Change Log

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-12-28 | 1.0 | Initial CORS hardening implementation | tdd-executor-cors |

---

**Status:** ✅ Implemented and Tested
**Review Needed:** Security team approval for production deployment
**Next Steps:** Add CORS validation to CI/CD pipeline
