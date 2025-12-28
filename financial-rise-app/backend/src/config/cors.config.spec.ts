/**
 * Unit Test Suite: CORS Configuration (Work Stream 59 - HIGH-010)
 *
 * Purpose: Verify CORS configuration utility functions and validation logic
 * without requiring a full application context.
 *
 * Security Finding: HIGH-010 - CORS misconfiguration risk
 * OWASP: A05:2021 - Security Misconfiguration
 * CWE: CWE-346 - Origin Validation Error
 */

import { getCorsConfig } from './cors.config';
import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';

describe('CORS Configuration (Work Stream 59 - Unit Tests)', () => {
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    // Save original environment
    originalEnv = { ...process.env };
  });

  afterEach(() => {
    // Restore original environment
    process.env = originalEnv;
  });

  /**
   * RED PHASE: Test CORS configuration structure
   */
  describe('RED PHASE: Configuration Structure', () => {
    it('should return a valid CORS configuration object', () => {
      const config = getCorsConfig();

      expect(config).toBeDefined();
      expect(typeof config).toBe('object');
    });

    it('should configure credentials as true', () => {
      const config = getCorsConfig();

      expect(config.credentials).toBe(true);
    });

    it('should have a custom origin validation function', () => {
      const config = getCorsConfig();

      expect(config.origin).toBeDefined();
      expect(typeof config.origin).toBe('function');
    });

    it('should explicitly define allowed methods', () => {
      const config = getCorsConfig();

      expect(config.methods).toBeDefined();
      expect(Array.isArray(config.methods)).toBe(true);
      if (config.methods) {
        expect(config.methods.length).toBeGreaterThan(0);
      }
    });

    it('should explicitly define allowed headers', () => {
      const config = getCorsConfig();

      expect(config.allowedHeaders).toBeDefined();
      expect(Array.isArray(config.allowedHeaders)).toBe(true);
      if (config.allowedHeaders) {
        expect(config.allowedHeaders.length).toBeGreaterThan(0);
      }
    });

    it('should define exposed headers', () => {
      const config = getCorsConfig();

      expect(config.exposedHeaders).toBeDefined();
      expect(Array.isArray(config.exposedHeaders)).toBe(true);
    });

    it('should configure preflight cache maxAge', () => {
      const config = getCorsConfig();

      expect(config.maxAge).toBeDefined();
      expect(typeof config.maxAge).toBe('number');
      expect(config.maxAge).toBe(3600); // 1 hour
    });
  });

  /**
   * GREEN PHASE: Test allowed HTTP methods
   */
  describe('GREEN PHASE: Allowed HTTP Methods', () => {
    let config: CorsOptions;

    beforeEach(() => {
      config = getCorsConfig();
    });

    it('should allow GET method', () => {
      expect(config.methods).toContain('GET');
    });

    it('should allow POST method', () => {
      expect(config.methods).toContain('POST');
    });

    it('should allow PUT method', () => {
      expect(config.methods).toContain('PUT');
    });

    it('should allow PATCH method', () => {
      expect(config.methods).toContain('PATCH');
    });

    it('should allow DELETE method', () => {
      expect(config.methods).toContain('DELETE');
    });

    it('should allow OPTIONS method', () => {
      expect(config.methods).toContain('OPTIONS');
    });

    it('should NOT allow TRACE method (security risk)', () => {
      expect(config.methods).not.toContain('TRACE');
    });

    it('should NOT allow CONNECT method (security risk)', () => {
      expect(config.methods).not.toContain('CONNECT');
    });

    it('should have exactly 6 allowed methods', () => {
      expect(config.methods).toHaveLength(6);
    });
  });

  /**
   * REFACTOR PHASE: Test allowed and exposed headers
   */
  describe('REFACTOR PHASE: Headers Configuration', () => {
    let config: CorsOptions;

    beforeEach(() => {
      config = getCorsConfig();
    });

    describe('Allowed Request Headers', () => {
      it('should allow Content-Type header', () => {
        expect(config.allowedHeaders).toContain('Content-Type');
      });

      it('should allow Authorization header', () => {
        expect(config.allowedHeaders).toContain('Authorization');
      });

      it('should allow X-CSRF-Token header', () => {
        expect(config.allowedHeaders).toContain('X-CSRF-Token');
      });

      it('should allow X-Requested-With header', () => {
        expect(config.allowedHeaders).toContain('X-Requested-With');
      });

      it('should allow Accept header', () => {
        expect(config.allowedHeaders).toContain('Accept');
      });

      it('should have at least 8 allowed headers', () => {
        if (config.allowedHeaders) {
          expect(config.allowedHeaders.length).toBeGreaterThanOrEqual(8);
        }
      });
    });

    describe('Exposed Response Headers', () => {
      it('should expose X-Total-Count header for pagination', () => {
        expect(config.exposedHeaders).toContain('X-Total-Count');
      });

      it('should expose X-Page-Number header', () => {
        expect(config.exposedHeaders).toContain('X-Page-Number');
      });

      it('should expose X-Page-Size header', () => {
        expect(config.exposedHeaders).toContain('X-Page-Size');
      });

      it('should expose rate limit headers', () => {
        expect(config.exposedHeaders).toContain('X-RateLimit-Limit');
        expect(config.exposedHeaders).toContain('X-RateLimit-Remaining');
        expect(config.exposedHeaders).toContain('X-RateLimit-Reset');
      });
    });
  });

  /**
   * VERIFY PHASE: Test origin validation callback
   */
  describe('VERIFY PHASE: Origin Validation Callback', () => {
    let config: CorsOptions;
    let originCallback: Function;

    beforeEach(() => {
      config = getCorsConfig();
      originCallback = config.origin as Function;
    });

    it('should accept localhost:3001 (default frontend)', (done) => {
      originCallback('http://localhost:3001', (err: Error | null, allow?: boolean) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should accept localhost:5173 (Vite dev server)', (done) => {
      originCallback('http://localhost:5173', (err: Error | null, allow?: boolean) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should accept origin from FRONTEND_URL environment variable', (done) => {
      process.env.FRONTEND_URL = 'https://app.financialrise.com';

      // Need to reload config to pick up env change
      const newConfig = getCorsConfig();
      const newCallback = newConfig.origin as Function;

      newCallback('https://app.financialrise.com', (err: Error | null, allow?: boolean) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should accept origin from FRONTEND_URL_STAGING environment variable', (done) => {
      process.env.FRONTEND_URL_STAGING = 'https://staging.financialrise.com';

      const newConfig = getCorsConfig();
      const newCallback = newConfig.origin as Function;

      newCallback('https://staging.financialrise.com', (err: Error | null, allow?: boolean) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should reject unauthorized origin (evil.com)', (done) => {
      originCallback('http://evil.com', (err: Error | null, allow?: boolean) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('Not allowed by CORS');
        expect(allow).toBeUndefined();
        done();
      });
    });

    it('should reject origin with wrong port', (done) => {
      originCallback('http://localhost:9999', (err: Error | null, allow?: boolean) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('Not allowed by CORS');
        done();
      });
    });

    it('should reject origin with wrong protocol', (done) => {
      originCallback('https://localhost:3001', (err: Error | null, allow?: boolean) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('Not allowed by CORS');
        done();
      });
    });

    it('should allow requests with no origin (mobile apps, Postman)', (done) => {
      originCallback(undefined, (err: Error | null, allow?: boolean) => {
        expect(err).toBeNull();
        expect(allow).toBe(true);
        done();
      });
    });

    it('should be case-sensitive for origin matching', (done) => {
      originCallback('http://LOCALHOST:3001', (err: Error | null, allow?: boolean) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('Not allowed by CORS');
        done();
      });
    });

    it('should reject subdomain attacks', (done) => {
      originCallback('http://malicious.localhost:3001', (err: Error | null, allow?: boolean) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('Not allowed by CORS');
        done();
      });
    });

    it('should reject IPv4 addresses unless whitelisted', (done) => {
      originCallback('http://127.0.0.1:3001', (err: Error | null, allow?: boolean) => {
        expect(err).toBeInstanceOf(Error);
        expect(err?.message).toBe('Not allowed by CORS');
        done();
      });
    });
  });

  /**
   * Security Tests
   */
  describe('Security Hardening Tests', () => {
    it('should not use wildcard origin with credentials', () => {
      const config = getCorsConfig();

      expect(config.credentials).toBe(true);
      expect(config.origin).not.toBe('*');
      expect(typeof config.origin).toBe('function');
    });

    it('should have preflightContinue set to false', () => {
      const config = getCorsConfig();

      expect(config.preflightContinue).toBe(false);
    });

    it('should have optionsSuccessStatus set to 200', () => {
      const config = getCorsConfig();

      expect(config.optionsSuccessStatus).toBe(200);
    });

    it('should cache preflight for reasonable duration (not too long)', () => {
      const config = getCorsConfig();

      // Should be 1 hour (3600 seconds)
      expect(config.maxAge).toBeLessThanOrEqual(3600);
      expect(config.maxAge).toBeGreaterThan(0);
    });
  });

  /**
   * Configuration Completeness Tests
   */
  describe('Configuration Completeness', () => {
    it('should have all required CORS properties configured', () => {
      const config = getCorsConfig();

      expect(config.origin).toBeDefined();
      expect(config.credentials).toBeDefined();
      expect(config.methods).toBeDefined();
      expect(config.allowedHeaders).toBeDefined();
      expect(config.exposedHeaders).toBeDefined();
      expect(config.maxAge).toBeDefined();
      expect(config.optionsSuccessStatus).toBeDefined();
      expect(config.preflightContinue).toBeDefined();
    });

    it('should not have dangerous default configurations', () => {
      const config = getCorsConfig();

      // Should not allow all origins
      expect(config.origin).not.toBe('*');
      expect(config.origin).not.toBe(true);

      // Should not have overly permissive cache
      expect(config.maxAge).toBeLessThanOrEqual(3600);

      // Should not continue after preflight
      expect(config.preflightContinue).toBe(false);
    });
  });
});

/**
 * Test Coverage Summary:
 *
 * ✅ Configuration structure validation
 * ✅ Allowed HTTP methods (6 methods, no dangerous methods)
 * ✅ Allowed request headers (Content-Type, Authorization, CSRF, etc.)
 * ✅ Exposed response headers (pagination, rate limits)
 * ✅ Origin validation callback (whitelisted origins)
 * ✅ Unauthorized origin rejection
 * ✅ Null origin handling
 * ✅ Security edge cases (case sensitivity, subdomain attacks)
 * ✅ Credentials configuration
 * ✅ Preflight caching
 * ✅ Configuration completeness
 *
 * Acceptance Criteria (Work Stream 59):
 * ✅ Only whitelisted origins allowed
 * ✅ Blocked origins logged (implemented in cors.config.ts)
 * ✅ All CORS tests pass
 * ✅ Documentation complete
 */
