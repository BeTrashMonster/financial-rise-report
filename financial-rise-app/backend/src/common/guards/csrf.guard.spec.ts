import { ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { CsrfGuard } from './csrf.guard';

describe('CsrfGuard', () => {
  let guard: CsrfGuard;
  let reflector: Reflector;

  beforeEach(() => {
    reflector = new Reflector();
    guard = new CsrfGuard(reflector);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  describe('canActivate', () => {
    const createMockContext = (method: string, cookies: any = {}, headers: any = {}): ExecutionContext => {
      return {
        switchToHttp: () => ({
          getRequest: () => ({
            method,
            cookies,
            headers,
          }),
        }),
      } as any;
    };

    describe('Safe methods (GET, HEAD, OPTIONS)', () => {
      it('should allow GET requests without CSRF token', () => {
        const context = createMockContext('GET');

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should allow HEAD requests without CSRF token', () => {
        const context = createMockContext('HEAD');

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should allow OPTIONS requests without CSRF token', () => {
        const context = createMockContext('OPTIONS');

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should be case-insensitive for HTTP methods', () => {
        const methods = ['get', 'Get', 'GET', 'head', 'HEAD', 'options', 'OPTIONS'];

        methods.forEach((method) => {
          const context = createMockContext(method);
          const result = guard.canActivate(context);
          expect(result).toBe(true);
        });
      });
    });

    describe('State-changing methods (POST, PUT, PATCH, DELETE)', () => {
      const csrfToken = 'test-csrf-token-12345';

      it('should allow POST request with matching CSRF tokens', () => {
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': csrfToken },
          { 'x-csrf-token': csrfToken },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should allow PUT request with matching CSRF tokens', () => {
        const context = createMockContext(
          'PUT',
          { 'XSRF-TOKEN': csrfToken },
          { 'x-csrf-token': csrfToken },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should allow PATCH request with matching CSRF tokens', () => {
        const context = createMockContext(
          'PATCH',
          { 'XSRF-TOKEN': csrfToken },
          { 'x-csrf-token': csrfToken },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should allow DELETE request with matching CSRF tokens', () => {
        const context = createMockContext(
          'DELETE',
          { 'XSRF-TOKEN': csrfToken },
          { 'x-csrf-token': csrfToken },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should throw ForbiddenException when cookie token is missing', () => {
        const context = createMockContext('POST', {}, { 'x-csrf-token': csrfToken });

        expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });

      it('should throw ForbiddenException when header token is missing', () => {
        const context = createMockContext('POST', { 'XSRF-TOKEN': csrfToken }, {});

        expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });

      it('should throw ForbiddenException when both tokens are missing', () => {
        const context = createMockContext('POST', {}, {});

        expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });

      it('should throw ForbiddenException when tokens do not match', () => {
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': 'token-from-cookie' },
          { 'x-csrf-token': 'different-token' },
        );

        expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
        expect(() => guard.canActivate(context)).toThrow('CSRF token mismatch');
      });

      it('should be case-sensitive for token comparison', () => {
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': 'TOKEN' },
          { 'x-csrf-token': 'token' },
        );

        expect(() => guard.canActivate(context)).toThrow(ForbiddenException);
      });

      it('should handle empty string tokens as missing', () => {
        const context = createMockContext('POST', { 'XSRF-TOKEN': '' }, { 'x-csrf-token': '' });

        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });

      it('should handle null tokens as missing', () => {
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': null },
          { 'x-csrf-token': null },
        );

        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });

      it('should handle undefined cookies object', () => {
        const context = {
          switchToHttp: () => ({
            getRequest: () => ({
              method: 'POST',
              cookies: undefined,
              headers: { 'x-csrf-token': csrfToken },
            }),
          }),
        } as any;

        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });
    });

    describe('Double-submit cookie pattern', () => {
      it('should verify both cookie and header are present', () => {
        const token = 'secure-random-token';
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': token },
          { 'x-csrf-token': token },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should use correct cookie name XSRF-TOKEN', () => {
        const token = 'test-token';
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': token },
          { 'x-csrf-token': token },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should use correct header name x-csrf-token', () => {
        const token = 'test-token';
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': token },
          { 'x-csrf-token': token },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should fail with wrong cookie name', () => {
        const token = 'test-token';
        const context = createMockContext(
          'POST',
          { 'CSRF-TOKEN': token }, // Wrong name
          { 'x-csrf-token': token },
        );

        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });

      it('should fail with wrong header name', () => {
        const token = 'test-token';
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': token },
          { 'csrf-token': token }, // Missing 'x-' prefix
        );

        expect(() => guard.canActivate(context)).toThrow('CSRF token missing');
      });
    });

    describe('Edge cases', () => {
      it('should handle very long tokens', () => {
        const longToken = 'a'.repeat(1000);
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': longToken },
          { 'x-csrf-token': longToken },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should handle special characters in tokens', () => {
        const specialToken = 'token-with-!@#$%^&*()_+-=[]{}|;:,.<>?';
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': specialToken },
          { 'x-csrf-token': specialToken },
        );

        const result = guard.canActivate(context);

        expect(result).toBe(true);
      });

      it('should handle whitespace in tokens strictly', () => {
        const context = createMockContext(
          'POST',
          { 'XSRF-TOKEN': 'token' },
          { 'x-csrf-token': ' token' }, // Leading space
        );

        expect(() => guard.canActivate(context)).toThrow('CSRF token mismatch');
      });
    });
  });
});
