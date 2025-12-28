import { ExecutionContext, CallHandler } from '@nestjs/common';
import { of } from 'rxjs';
import { CsrfInterceptor } from './csrf.interceptor';

describe('CsrfInterceptor', () => {
  let interceptor: CsrfInterceptor;

  beforeEach(() => {
    interceptor = new CsrfInterceptor();
  });

  it('should be defined', () => {
    expect(interceptor).toBeDefined();
  });

  describe('intercept', () => {
    const createMockContext = (cookies: any = {}): ExecutionContext => {
      const mockResponse = {
        cookie: jest.fn(),
      };

      const mockRequest = {
        cookies,
      };

      return {
        switchToHttp: () => ({
          getResponse: () => mockResponse,
          getRequest: () => mockRequest,
        }),
      } as any;
    };

    const mockNext: CallHandler = {
      handle: jest.fn(() => of({})),
    };

    afterEach(() => {
      jest.clearAllMocks();
    });

    it('should generate and set CSRF cookie if not present', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      expect(response.cookie).toHaveBeenCalled();
      const [cookieName, cookieValue, cookieOptions] = (response.cookie as jest.Mock).mock.calls[0];

      expect(cookieName).toBe('XSRF-TOKEN');
      expect(cookieValue).toBeDefined();
      expect(typeof cookieValue).toBe('string');
      expect(cookieValue.length).toBeGreaterThan(0);
    });

    it('should not set cookie if CSRF token already exists', () => {
      const existingToken = 'existing-csrf-token-12345';
      const context = createMockContext({ 'XSRF-TOKEN': existingToken });
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      expect(response.cookie).not.toHaveBeenCalled();
    });

    it('should generate a random token', () => {
      const context1 = createMockContext({});
      const context2 = createMockContext({});
      const response1 = context1.switchToHttp().getResponse();
      const response2 = context2.switchToHttp().getResponse();

      interceptor.intercept(context1, mockNext);
      interceptor.intercept(context2, mockNext);

      const token1 = (response1.cookie as jest.Mock).mock.calls[0][1];
      const token2 = (response2.cookie as jest.Mock).mock.calls[0][1];

      expect(token1).not.toBe(token2);
    });

    it('should set cookie with correct options', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const [, , options] = (response.cookie as jest.Mock).mock.calls[0];

      expect(options.httpOnly).toBe(false); // Client needs to read this
      expect(options.sameSite).toBe('strict');
      expect(options.maxAge).toBe(24 * 60 * 60 * 1000); // 24 hours
    });

    it('should set secure flag in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const [, , options] = (response.cookie as jest.Mock).mock.calls[0];

      expect(options.secure).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });

    it('should not set secure flag in development', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const [, , options] = (response.cookie as jest.Mock).mock.calls[0];

      expect(options.secure).toBe(false);

      process.env.NODE_ENV = originalEnv;
    });

    it('should call next.handle() to continue request', () => {
      const context = createMockContext({});

      interceptor.intercept(context, mockNext);

      expect(mockNext.handle).toHaveBeenCalled();
    });

    it('should return the result from next.handle()', (done) => {
      const context = createMockContext({});
      const expectedResult = { data: 'test' };
      const customNext: CallHandler = {
        handle: jest.fn(() => of(expectedResult)),
      };

      const result$ = interceptor.intercept(context, customNext);

      result$.subscribe({
        next: (value) => {
          expect(value).toEqual(expectedResult);
          done();
        },
      });
    });

    it('should generate token with correct length', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const token = (response.cookie as jest.Mock).mock.calls[0][1];

      // Token is 32 bytes in hex = 64 characters
      expect(token.length).toBe(64);
    });

    it('should generate hexadecimal token', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const token = (response.cookie as jest.Mock).mock.calls[0][1];

      // Should only contain hex characters (0-9, a-f)
      expect(token).toMatch(/^[0-9a-f]+$/);
    });

    it('should use cookie name XSRF-TOKEN', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const cookieName = (response.cookie as jest.Mock).mock.calls[0][0];

      expect(cookieName).toBe('XSRF-TOKEN');
    });

    it('should set httpOnly to false for client access', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const options = (response.cookie as jest.Mock).mock.calls[0][2];

      // httpOnly must be false so JavaScript can read it
      expect(options.httpOnly).toBe(false);
    });

    it('should set sameSite to strict', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const options = (response.cookie as jest.Mock).mock.calls[0][2];

      expect(options.sameSite).toBe('strict');
    });

    it('should set cookie max age to 24 hours', () => {
      const context = createMockContext({});
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      const options = (response.cookie as jest.Mock).mock.calls[0][2];

      const expectedMaxAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
      expect(options.maxAge).toBe(expectedMaxAge);
    });

    it('should handle undefined cookies object', () => {
      const mockResponse = {
        cookie: jest.fn(),
      };
      const context = {
        switchToHttp: () => ({
          getResponse: () => mockResponse,
          getRequest: () => ({
            cookies: undefined,
          }),
        }),
      } as any;

      expect(() => {
        interceptor.intercept(context, mockNext);
      }).not.toThrow();

      expect(mockResponse.cookie).toHaveBeenCalled();
    });

    it('should handle null cookies object', () => {
      const mockResponse = {
        cookie: jest.fn(),
      };
      const context = {
        switchToHttp: () => ({
          getResponse: () => mockResponse,
          getRequest: () => ({
            cookies: null,
          }),
        }),
      } as any;

      expect(() => {
        interceptor.intercept(context, mockNext);
      }).not.toThrow();

      expect(mockResponse.cookie).toHaveBeenCalled();
    });

    it('should preserve existing token exactly', () => {
      const existingToken = 'my-existing-token-abc123';
      const context = createMockContext({ 'XSRF-TOKEN': existingToken });
      const response = context.switchToHttp().getResponse();

      interceptor.intercept(context, mockNext);

      // Should not set a new cookie
      expect(response.cookie).not.toHaveBeenCalled();
    });

    describe('Double-submit cookie pattern', () => {
      it('should support client reading the cookie value', () => {
        const context = createMockContext({});
        const response = context.switchToHttp().getResponse();

        interceptor.intercept(context, mockNext);

        const options = (response.cookie as jest.Mock).mock.calls[0][2];

        // httpOnly=false allows JavaScript to read document.cookie
        expect(options.httpOnly).toBe(false);
      });

      it('should set cookie that client can send in header', () => {
        const context = createMockContext({});
        const response = context.switchToHttp().getResponse();

        interceptor.intercept(context, mockNext);

        const [cookieName] = (response.cookie as jest.Mock).mock.calls[0];

        // Cookie name should match what CsrfGuard expects
        expect(cookieName).toBe('XSRF-TOKEN');
      });
    });

    describe('Security', () => {
      it('should use cryptographically secure random token', () => {
        const tokens = new Set();
        const iterations = 100;

        for (let i = 0; i < iterations; i++) {
          const context = createMockContext({});
          const response = context.switchToHttp().getResponse();

          interceptor.intercept(context, mockNext);

          const token = (response.cookie as jest.Mock).mock.calls[0][1];
          tokens.add(token);
        }

        // All tokens should be unique
        expect(tokens.size).toBe(iterations);
      });

      it('should enforce SameSite=strict to prevent CSRF', () => {
        const context = createMockContext({});
        const response = context.switchToHttp().getResponse();

        interceptor.intercept(context, mockNext);

        const options = (response.cookie as jest.Mock).mock.calls[0][2];

        expect(options.sameSite).toBe('strict');
      });

      it('should use secure cookies in production', () => {
        const originalEnv = process.env.NODE_ENV;
        process.env.NODE_ENV = 'production';

        const context = createMockContext({});
        const response = context.switchToHttp().getResponse();

        interceptor.intercept(context, mockNext);

        const options = (response.cookie as jest.Mock).mock.calls[0][2];

        expect(options.secure).toBe(true);

        process.env.NODE_ENV = originalEnv;
      });
    });
  });
});
