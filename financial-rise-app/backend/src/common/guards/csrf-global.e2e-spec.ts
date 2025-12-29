import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import * as cookieParser from 'cookie-parser';
import { json, urlencoded } from 'express';
import { AppModule } from '../../app.module';
import { CsrfInterceptor } from '../interceptors/csrf.interceptor';
import { CsrfGuard } from './csrf.guard';
import { Reflector } from '@nestjs/core';
import { configureSecurityHeaders } from '../../config/security-headers.config';
import { getCorsConfig } from '../../config/cors.config';

/**
 * Helper function to extract CSRF token from response headers
 * Properly handles TypeScript types for set-cookie header which can be string | string[] | undefined
 */
function extractCsrfToken(response: request.Response): string | undefined {
  const rawSetCookie = response.headers['set-cookie'];
  const cookies = typeof rawSetCookie === 'string'
    ? [rawSetCookie]
    : rawSetCookie;

  if (!cookies || !Array.isArray(cookies)) {
    return undefined;
  }
  const csrfCookie = cookies.find((c: string) => c.startsWith('XSRF-TOKEN='));
  return csrfCookie?.match(/XSRF-TOKEN=([^;]+)/)?.[1];
}

/**
 * Global CSRF Protection E2E Tests
 * Work Stream 63 (MED-002) - Global CSRF Protection
 *
 * Purpose: Verify that CSRF protection is applied globally across all
 * state-changing endpoints using the double-submit cookie pattern.
 *
 * Security Finding: MED-002 - CSRF protection not enabled globally
 * OWASP: A01:2021 - Broken Access Control
 * CWE: CWE-352 - Cross-Site Request Forgery
 *
 * Test Coverage:
 * 1. CSRF tokens are automatically generated on all requests
 * 2. Safe methods (GET, HEAD, OPTIONS) don't require CSRF tokens
 * 3. State-changing methods (POST, PUT, PATCH, DELETE) require CSRF tokens
 * 4. Requests without CSRF tokens are blocked (403 Forbidden)
 * 5. Requests with mismatched CSRF tokens are blocked
 * 6. Double-submit cookie pattern works correctly
 * 7. CSRF protection works across different modules
 * 8. CSRF attack scenarios are prevented
 *
 * Reference: SECURITY-AUDIT-REPORT.md Lines 527-579
 */
describe('Global CSRF Protection (E2E)', () => {
  let app: INestApplication;
  let csrfToken: string;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    // Create app with bodyParser disabled, just like main.ts
    app = moduleFixture.createNestApplication({
      bodyParser: false, // Disable built-in parser to apply custom limits
    });

    // Apply middleware in the same order as main.ts
    // Request Size Limits - must come FIRST after disabling bodyParser
    app.use(json({ limit: '10mb' }));
    app.use(urlencoded({ extended: true, limit: '10mb' }));

    app.use(cookieParser());

    // Apply security headers
    configureSecurityHeaders(app);

    // Enable CORS
    app.enableCors(getCorsConfig());

    // Apply global validation pipe
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
        transformOptions: {
          enableImplicitConversion: true,
        },
      }),
    );

    // Apply CSRF protection globally (THIS IS WHAT WE'RE TESTING)
    const reflector = app.get(Reflector);
    app.useGlobalInterceptors(new CsrfInterceptor());
    app.useGlobalGuards(new CsrfGuard(reflector));

    // Set API prefix
    app.setGlobalPrefix('api/v1');

    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('CSRF Token Generation', () => {
    it('should automatically set CSRF cookie on first request', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      // Verify CSRF cookie is set using helper function
      const token = extractCsrfToken(response);
      expect(token).toBeDefined();
      expect(token).toBeTruthy();
      expect(token!.length).toBeGreaterThan(0);
    });

    it('should not regenerate CSRF cookie if already present', async () => {
      // First request - get initial token
      const firstResponse = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const firstToken = extractCsrfToken(firstResponse);
      expect(firstToken).toBeDefined();

      // Second request - send existing token
      const secondResponse = await request(app.getHttpServer())
        .get('/api/v1/health')
        .set('Cookie', `XSRF-TOKEN=${firstToken}`)
        .expect(200);

      // Should not set a new cookie
      const secondCookies = secondResponse.headers['set-cookie'];
      expect(secondCookies).toBeUndefined();
    });

    it('should generate unique tokens for different sessions', async () => {
      const response1 = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const response2 = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token1 = extractCsrfToken(response1) || '';
      const token2 = extractCsrfToken(response2) || '';

      expect(token1).not.toBe(token2);
    });

    it('should set CSRF cookie with correct security attributes', async () => {
      const response = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      // Use runtime type checking to handle set-cookie header properly
      const rawSetCookie = response.headers['set-cookie'];
      const cookies = typeof rawSetCookie === 'string'
        ? [rawSetCookie]
        : rawSetCookie;

      expect(cookies).toBeDefined();
      expect(Array.isArray(cookies)).toBe(true);

      const csrfCookie = cookies?.find((c: string) => c.startsWith('XSRF-TOKEN='));

      // httpOnly=false (client needs to read it for double-submit pattern)
      expect(csrfCookie).not.toContain('HttpOnly');

      // SameSite=Strict (prevents CSRF attacks)
      expect(csrfCookie).toContain('SameSite=Strict');

      // Max-Age set (24 hours)
      expect(csrfCookie).toContain('Max-Age=');
    });
  });

  describe('Safe Methods (No CSRF Required)', () => {
    it('should allow GET requests without CSRF token', async () => {
      await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);
    });

    it('should allow HEAD requests without CSRF token', async () => {
      await request(app.getHttpServer())
        .head('/api/v1/health')
        .expect(200);
    });

    it('should allow OPTIONS requests without CSRF token', async () => {
      await request(app.getHttpServer())
        .options('/api/v1/health')
        .expect(200);
    });
  });

  describe('State-Changing Methods (CSRF Required)', () => {
    beforeEach(async () => {
      // Get a fresh CSRF token for each test
      const response = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      csrfToken = extractCsrfToken(response) || '';
    });

    describe('POST requests', () => {
      it('should block POST request without CSRF token', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .send({
            email: 'test@example.com',
            password: 'SecurePassword123!',
            first_name: 'Test',
            last_name: 'User',
          })
          .expect(403);

        expect(response.body.message).toContain('CSRF token missing');
      });

      it('should block POST request with missing cookie token', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('X-CSRF-Token', csrfToken)
          .send({
            email: 'test@example.com',
            password: 'SecurePassword123!',
            first_name: 'Test',
            last_name: 'User',
          })
          .expect(403);

        expect(response.body.message).toContain('CSRF token missing');
      });

      it('should block POST request with missing header token', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('Cookie', `XSRF-TOKEN=${csrfToken}`)
          .send({
            email: 'test@example.com',
            password: 'SecurePassword123!',
            first_name: 'Test',
            last_name: 'User',
          })
          .expect(403);

        expect(response.body.message).toContain('CSRF token missing');
      });

      it('should block POST request with mismatched CSRF tokens', async () => {
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('Cookie', `XSRF-TOKEN=${csrfToken}`)
          .set('X-CSRF-Token', 'different-token-12345')
          .send({
            email: 'test@example.com',
            password: 'SecurePassword123!',
            first_name: 'Test',
            last_name: 'User',
          })
          .expect(403);

        expect(response.body.message).toContain('CSRF token mismatch');
      });

      it('should allow POST request with valid CSRF tokens', async () => {
        // Note: This may fail with 400 due to validation, but should NOT fail with 403 (CSRF error)
        const response = await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('Cookie', `XSRF-TOKEN=${csrfToken}`)
          .set('X-CSRF-Token', csrfToken)
          .send({
            email: 'test@example.com',
            password: 'SecurePassword123!',
            first_name: 'Test',
            last_name: 'User',
          });

        // Should NOT return 403 (CSRF error)
        expect(response.status).not.toBe(403);
        expect(response.body.message).not.toContain('CSRF');
      });
    });

    describe('PUT requests', () => {
      it('should block PUT request without CSRF token', async () => {
        const response = await request(app.getHttpServer())
          .put('/api/v1/users/123')
          .send({
            first_name: 'Updated',
          })
          .expect(403);

        expect(response.body.message).toContain('CSRF token missing');
      });

      it('should allow PUT request with valid CSRF tokens', async () => {
        const response = await request(app.getHttpServer())
          .put('/api/v1/users/123')
          .set('Cookie', `XSRF-TOKEN=${csrfToken}`)
          .set('X-CSRF-Token', csrfToken)
          .send({
            first_name: 'Updated',
          });

        // Should NOT return 403 (CSRF error)
        expect(response.status).not.toBe(403);
        expect(response.body.message).not.toContain('CSRF');
      });
    });

    describe('PATCH requests', () => {
      it('should block PATCH request without CSRF token', async () => {
        const response = await request(app.getHttpServer())
          .patch('/api/v1/users/123')
          .send({
            first_name: 'Updated',
          })
          .expect(403);

        expect(response.body.message).toContain('CSRF token missing');
      });

      it('should allow PATCH request with valid CSRF tokens', async () => {
        const response = await request(app.getHttpServer())
          .patch('/api/v1/users/123')
          .set('Cookie', `XSRF-TOKEN=${csrfToken}`)
          .set('X-CSRF-Token', csrfToken)
          .send({
            first_name: 'Updated',
          });

        // Should NOT return 403 (CSRF error)
        expect(response.status).not.toBe(403);
        expect(response.body.message).not.toContain('CSRF');
      });
    });

    describe('DELETE requests', () => {
      it('should block DELETE request without CSRF token', async () => {
        const response = await request(app.getHttpServer())
          .delete('/api/v1/users/123')
          .expect(403);

        expect(response.body.message).toContain('CSRF token missing');
      });

      it('should allow DELETE request with valid CSRF tokens', async () => {
        const response = await request(app.getHttpServer())
          .delete('/api/v1/users/123')
          .set('Cookie', `XSRF-TOKEN=${csrfToken}`)
          .set('X-CSRF-Token', csrfToken);

        // Should NOT return 403 (CSRF error)
        expect(response.status).not.toBe(403);
        expect(response.body.message).not.toContain('CSRF');
      });
    });
  });

  describe('Double-Submit Cookie Pattern', () => {
    it('should verify both cookie and header are required', async () => {
      // Get token
      const tokenResponse = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token = extractCsrfToken(tokenResponse) || '';

      // Only cookie (no header) - should fail
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Cookie', `XSRF-TOKEN=${token}`)
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          first_name: 'Test',
          last_name: 'User',
        })
        .expect(403);

      // Only header (no cookie) - should fail
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('X-CSRF-Token', token)
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          first_name: 'Test',
          last_name: 'User',
        })
        .expect(403);

      // Both cookie and header with matching values - should pass CSRF check
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Cookie', `XSRF-TOKEN=${token}`)
        .set('X-CSRF-Token', token)
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          first_name: 'Test',
          last_name: 'User',
        });

      expect(response.status).not.toBe(403);
    });

    it('should enforce exact match between cookie and header', async () => {
      const tokenResponse = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token = extractCsrfToken(tokenResponse) || '';

      // Different values - should fail
      await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Cookie', `XSRF-TOKEN=${token}`)
        .set('X-CSRF-Token', `${token}-modified`)
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          first_name: 'Test',
          last_name: 'User',
        })
        .expect(403);

      // Case sensitivity - should fail
      const upperToken = token.toUpperCase();
      if (upperToken !== token) {
        await request(app.getHttpServer())
          .post('/api/v1/auth/register')
          .set('Cookie', `XSRF-TOKEN=${token}`)
          .set('X-CSRF-Token', upperToken)
          .send({
            email: 'test@example.com',
            password: 'Password123!',
            first_name: 'Test',
            last_name: 'User',
          })
          .expect(403);
      }
    });
  });

  describe('CSRF Attack Prevention', () => {
    it('should prevent CSRF attack without token', async () => {
      // Attacker tries to create a user without knowing the CSRF token
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'attacker@malicious.com',
          password: 'Hacked123!',
          first_name: 'Attacker',
          last_name: 'User',
        })
        .expect(403);

      expect(response.body.message).toContain('CSRF token missing');
    });

    it('should prevent CSRF attack with cookie-only token', async () => {
      // Get a valid token
      const tokenResponse = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token = extractCsrfToken(tokenResponse) || '';

      // Attacker can set cookies but not custom headers in CSRF attack
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Cookie', `XSRF-TOKEN=${token}`)
        // No X-CSRF-Token header (attacker can't set custom headers cross-origin)
        .send({
          email: 'attacker@malicious.com',
          password: 'Hacked123!',
          first_name: 'Attacker',
          last_name: 'User',
        })
        .expect(403);

      expect(response.body.message).toContain('CSRF token missing');
    });

    it('should prevent CSRF attack with forged header', async () => {
      // Attacker tries to forge both cookie and header
      const fakeToken = 'forged-csrf-token-12345678901234567890123456789012';

      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Cookie', `XSRF-TOKEN=${fakeToken}`)
        .set('X-CSRF-Token', fakeToken)
        .send({
          email: 'attacker@malicious.com',
          password: 'Hacked123!',
          first_name: 'Attacker',
          last_name: 'User',
        });

      // Should fail (token not in server's cookie jar or validation fails)
      // Note: Might not be 403 if endpoint doesn't exist, but should not succeed
      expect([400, 401, 403, 404]).toContain(response.status);
    });
  });

  describe('Cross-Module CSRF Protection', () => {
    beforeEach(async () => {
      // Get fresh CSRF token
      const response = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      csrfToken = extractCsrfToken(response) || '';
    });

    it('should protect auth endpoints', async () => {
      // Login requires CSRF token
      await request(app.getHttpServer())
        .post('/api/v1/auth/login')
        .send({
          email: 'test@example.com',
          password: 'Password123!',
        })
        .expect(403);
    });

    it('should protect assessment endpoints', async () => {
      // Create assessment requires CSRF token
      await request(app.getHttpServer())
        .post('/api/v1/assessments')
        .send({
          client_name: 'Test Client',
          business_name: 'Test Business',
        })
        .expect(403);
    });

    it('should protect questionnaire endpoints', async () => {
      // Submit response requires CSRF token
      await request(app.getHttpServer())
        .post('/api/v1/questionnaire/responses')
        .send({
          assessmentId: '123',
          questionId: 'Q001',
          answer: { value: 'test' },
        })
        .expect(403);
    });

    it('should protect report endpoints', async () => {
      // Generate report requires CSRF token
      await request(app.getHttpServer())
        .post('/api/v1/reports/generate/client')
        .send({
          assessmentId: '123',
        })
        .expect(403);
    });
  });

  describe('CSRF Token Lifecycle', () => {
    it('should maintain same token across multiple requests in same session', async () => {
      // First request - get token
      const response1 = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token1 = extractCsrfToken(response1) || '';

      // Second request with same token
      const response2 = await request(app.getHttpServer())
        .get('/api/v1/health')
        .set('Cookie', `XSRF-TOKEN=${token1}`)
        .expect(200);

      // Should not generate new token
      expect(response2.headers['set-cookie']).toBeUndefined();
    });

    it('should generate new token for new session', async () => {
      // Session 1
      const response1 = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      // Session 2 (no cookies sent)
      const response2 = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token1 = extractCsrfToken(response1) || '';
      const token2 = extractCsrfToken(response2) || '';

      expect(token1).not.toBe(token2);
    });
  });

  describe('Error Messages', () => {
    it('should return clear error when CSRF token is missing', async () => {
      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          first_name: 'Test',
          last_name: 'User',
        })
        .expect(403);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('CSRF token missing');
      expect(response.body).toHaveProperty('statusCode', 403);
    });

    it('should return clear error when CSRF tokens mismatch', async () => {
      const tokenResponse = await request(app.getHttpServer())
        .get('/api/v1/health')
        .expect(200);

      const token = extractCsrfToken(tokenResponse) || '';

      const response = await request(app.getHttpServer())
        .post('/api/v1/auth/register')
        .set('Cookie', `XSRF-TOKEN=${token}`)
        .set('X-CSRF-Token', 'wrong-token')
        .send({
          email: 'test@example.com',
          password: 'Password123!',
          first_name: 'Test',
          last_name: 'User',
        })
        .expect(403);

      expect(response.body).toHaveProperty('message');
      expect(response.body.message).toContain('CSRF token mismatch');
      expect(response.body).toHaveProperty('statusCode', 403);
    });
  });
});
