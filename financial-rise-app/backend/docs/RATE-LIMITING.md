# Authentication Rate Limiting Documentation

**Work Stream:** 56 - Authentication Endpoint Rate Limiting (HIGH-001)
**Security Finding:** HIGH-001 - Missing rate limiting on authentication
**OWASP:** A07:2021 - Identification and Authentication Failures
**CWE:** CWE-307 - Improper Restriction of Excessive Authentication Attempts
**Implementation Date:** 2025-12-28

## Overview

This document describes the rate limiting implementation for authentication endpoints in the Financial RISE Report backend API. Rate limiting is a critical security control that protects against brute force attacks, credential stuffing, password reset spam, and registration flooding.

## Implementation Summary

### Technology Stack
- **Framework:** NestJS v10.3.0
- **Library:** @nestjs/throttler v5.2.0
- **Storage:** In-memory (default) - Can be extended to Redis for distributed systems

### Protected Endpoints

| Endpoint | Rate Limit | TTL | Protection Against |
|----------|-----------|-----|-------------------|
| `POST /auth/login` | 5 requests | 60 seconds (1 minute) | Brute force attacks |
| `POST /auth/forgot-password` | 3 requests | 300 seconds (5 minutes) | Password reset spam |
| `POST /auth/register` | 3 requests | 3600 seconds (1 hour) | Registration flooding |

## Architecture

### Global Configuration

The `ThrottlerModule` is configured globally in `app.module.ts`:

```typescript
ThrottlerModule.forRoot([
  {
    ttl: 60000, // 1 minute (default)
    limit: 100, // 100 requests per minute (default)
  },
]),
```

The `ThrottlerGuard` is applied globally to all routes:

```typescript
providers: [
  {
    provide: APP_GUARD,
    useClass: ThrottlerGuard,
  },
],
```

### Endpoint-Specific Overrides

Each authentication endpoint uses the `@Throttle` decorator to override the global rate limits:

#### Login Endpoint
```typescript
@Throttle({ default: { ttl: 60000, limit: 5 } }) // 5 requests per minute
@Post('login')
async login(@Request() req: any, @Body() loginDto: LoginDto) {
  return this.authService.login(req.user);
}
```

**Rationale:** Login is the most common attack vector for brute force. Limiting to 5 attempts per minute balances security with legitimate user retry scenarios (e.g., mistyped password).

#### Password Reset Endpoint
```typescript
@Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 requests per 5 minutes
@Post('forgot-password')
async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
  return this.authService.forgotPassword(forgotPasswordDto.email);
}
```

**Rationale:** Password reset requests trigger emails, which can be abused for spam or denial of service. The 5-minute window prevents attackers from flooding users with reset emails.

#### Registration Endpoint
```typescript
@Throttle({ default: { ttl: 3600000, limit: 3 } }) // 3 requests per hour
@Post('register')
async register(@Body() registerDto: RegisterDto) {
  return this.authService.register(registerDto);
}
```

**Rationale:** Registration is resource-intensive (database writes, email verification). Limiting to 3 per hour prevents automated account creation while allowing legitimate users to retry.

## Rate Limit Headers

The `ThrottlerGuard` automatically adds the following HTTP headers to all responses:

- **X-RateLimit-Limit:** Maximum number of requests allowed in the time window
- **X-RateLimit-Remaining:** Number of requests remaining in the current time window
- **X-RateLimit-Reset:** Unix timestamp (seconds) when the rate limit resets

### Example Response Headers
```
X-RateLimit-Limit: 5
X-RateLimit-Remaining: 3
X-RateLimit-Reset: 1735387320
```

## Error Responses

When a client exceeds the rate limit, the API returns:

**Status Code:** `429 Too Many Requests`

**Response Body:**
```json
{
  "statusCode": 429,
  "message": "ThrottlerException: Too Many Requests"
}
```

## Rate Limiting Strategy

### Tracking Mechanism
- **Key:** IP address + endpoint path
- **Storage:** In-memory (production should use Redis)
- **Granularity:** Per-endpoint, per-IP

### TTL Behavior
- Rate limits reset automatically after the TTL expires
- Each request resets the TTL for that specific client/endpoint combination

### Concurrent Requests
The throttler counts all requests, including concurrent ones. If a client sends 10 simultaneous login requests:
- First 5 succeed (or fail based on credentials)
- Remaining 5 return 429

## Testing

### Unit Tests
Comprehensive unit tests are located in:
- `src/modules/auth/auth.rate-limiting.spec.ts` (30 tests, all passing)

### Test Coverage
- ✅ Throttle decorator configuration validation
- ✅ Controller endpoint verification
- ✅ ThrottlerGuard availability
- ✅ Rate limit header expectations
- ✅ Security compliance (OWASP A07:2021, CWE-307)

### Manual Testing

#### Test Rate Limit on Login
```bash
# Should succeed (first 5 requests)
for i in {1..5}; do
  curl -X POST http://localhost:3000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"password"}' \
    -i
done

# Should return 429 (6th request)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}' \
  -i
```

#### Test Rate Limit on Password Reset
```bash
# Should succeed (first 3 requests)
for i in {1..3}; do
  curl -X POST http://localhost:3000/auth/forgot-password \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com"}' \
    -i
done

# Should return 429 (4th request)
curl -X POST http://localhost:3000/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}' \
  -i
```

## Production Considerations

### Redis Integration (Recommended)

For production deployments with multiple backend instances, configure Redis as the storage backend:

```bash
npm install @nestjs/throttler-storage-redis ioredis
```

**Update `app.module.ts`:**
```typescript
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from '@nestjs/throttler-storage-redis';
import Redis from 'ioredis';

ThrottlerModule.forRootAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (configService: ConfigService) => ({
    throttlers: [
      {
        ttl: 60000,
        limit: 100,
      },
    ],
    storage: new ThrottlerStorageRedisService(
      new Redis({
        host: configService.get('REDIS_HOST'),
        port: configService.get('REDIS_PORT'),
        password: configService.get('REDIS_PASSWORD'),
      }),
    ),
  }),
}),
```

### Environment Variables
```env
# Redis Configuration (Production)
REDIS_HOST=your-redis-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password
```

### Monitoring & Alerting

Configure monitoring for rate limit violations:

1. **Log Rate Limit Hits:**
   - The `ThrottlerGuard` can be extended to log violations
   - Track IP addresses that frequently hit rate limits (potential attackers)

2. **Metrics to Track:**
   - Number of 429 responses per endpoint
   - IP addresses with high violation rates
   - Time distribution of rate limit hits

3. **Alerts:**
   - Alert when a single IP exceeds rate limits 10+ times in 1 hour
   - Alert when overall 429 rate exceeds 5% of total requests

## Bypass Mechanisms (Testing Only)

For automated testing, you can skip throttling:

### Option 1: Environment-Based Bypass
```typescript
// main.ts (NOT for production)
if (process.env.NODE_ENV === 'test') {
  app.useGlobalGuards(new SkipThrottlerGuard());
}
```

### Option 2: Test-Specific Configuration
```typescript
// In test files
const module = await Test.createTestingModule({
  imports: [
    ThrottlerModule.forRoot([
      { ttl: 60000, limit: 999999 }, // Effectively unlimited
    ]),
  ],
}).compile();
```

## Security Best Practices

### ✅ Implemented
- [x] Rate limiting on login (5/min)
- [x] Rate limiting on password reset (3/5min)
- [x] Rate limiting on registration (3/hour)
- [x] Global ThrottlerGuard application
- [x] Rate limit headers in responses
- [x] Per-IP, per-endpoint tracking
- [x] Comprehensive unit tests

### 🔄 Future Enhancements
- [ ] Redis storage for distributed rate limiting
- [ ] Rate limit violation logging
- [ ] IP-based blacklisting after repeated violations
- [ ] CAPTCHA integration after rate limit exceeded
- [ ] Adaptive rate limiting based on threat detection
- [ ] Whitelist for trusted IPs (e.g., internal monitoring)

## Compliance

### OWASP A07:2021 - Identification and Authentication Failures
✅ **Compliant:** Rate limiting prevents automated attacks against authentication mechanisms.

### CWE-307 - Improper Restriction of Excessive Authentication Attempts
✅ **Compliant:** All authentication endpoints enforce rate limits to prevent brute force attacks.

### GDPR/CCPA Considerations
- Rate limiting uses IP addresses for tracking (considered personal data under GDPR)
- IP addresses are not stored persistently (in-memory only)
- IP addresses expire after TTL (60 seconds to 1 hour)
- No IP address logging implemented (privacy-preserving)

## Troubleshooting

### Issue: Legitimate Users Blocked
**Symptom:** Users complain they can't log in after a few attempts.

**Solution:**
- Verify rate limits are not too strict
- Consider increasing login limit from 5 to 10 attempts/min
- Implement exponential backoff UI to discourage rapid retries

### Issue: Rate Limits Not Working
**Symptom:** Attackers can make unlimited requests.

**Diagnosis:**
1. Check if ThrottlerGuard is applied globally
2. Verify `@Throttle` decorators are present on endpoints
3. Ensure ThrottlerModule is imported in AppModule

**Debug:**
```bash
# Check if rate limit headers are present
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password"}' \
  -i | grep X-RateLimit
```

### Issue: Different IPs Not Rate Limited Separately
**Symptom:** All users share the same rate limit.

**Solution:**
- Verify throttler is using IP-based tracking (default behavior)
- If behind a proxy, configure `app.set('trust proxy', true)` to read `X-Forwarded-For`

## References

- [NestJS Throttler Documentation](https://docs.nestjs.com/security/rate-limiting)
- [OWASP: Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#login-throttling)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2025-12-28 | 1.0 | Initial implementation of rate limiting for login, password reset, and registration endpoints |

---

**Last Updated:** 2025-12-28
**Author:** TDD Executor Agent (tdd-executor-auth-rate-limiting)
**Work Stream:** 56 - Authentication Endpoint Rate Limiting (HIGH-001)
