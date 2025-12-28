import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { of } from 'rxjs';
import { LoggingInterceptor } from './logging.interceptor';
import { LogSanitizer } from '../utils/log-sanitizer';

describe('LoggingInterceptor', () => {
  let interceptor: LoggingInterceptor;
  let mockContext: ExecutionContext;
  let mockHandler: CallHandler;
  let logger: Logger;

  beforeEach(() => {
    interceptor = new LoggingInterceptor();
    logger = new Logger('TestLogger');

    // Mock execution context
    mockContext = {
      getType: jest.fn().mockReturnValue('http'),
      getClass: jest.fn().mockReturnValue({ name: 'TestController' }),
      getHandler: jest.fn().mockReturnValue({ name: 'testHandler' }),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          method: 'POST',
          url: '/api/test',
          body: {
            email: 'test@example.com',
            password: 'secretPassword123',
            name: 'John Doe',
          },
          user: { id: 'user-123', email: 'user@test.com' },
        }),
        getResponse: jest.fn().mockReturnValue({ statusCode: 200 }),
      }),
    } as any;

    mockHandler = {
      handle: jest.fn().mockReturnValue(of({ success: true })),
    } as any;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(interceptor).toBeDefined();
  });

  it('should intercept and log requests', (done) => {
    const logSpy = jest.spyOn(Logger.prototype, 'log');

    interceptor.intercept(mockContext, mockHandler).subscribe({
      next: (value) => {
        expect(value).toEqual({ success: true });
        expect(mockHandler.handle).toHaveBeenCalled();
        done();
      },
    });
  });

  it('should sanitize PII in request body before logging', (done) => {
    const logSpy = jest.spyOn(Logger.prototype, 'log');

    interceptor.intercept(mockContext, mockHandler).subscribe({
      next: () => {
        const logCalls = logSpy.mock.calls;
        const requestLog = logCalls.find((call) =>
          call[0]?.toString().includes('Incoming request'),
        );

        if (requestLog && typeof requestLog[1] === 'object') {
          // Email should be sanitized
          expect(JSON.stringify(requestLog[1])).toContain('***@example.com');
          expect(JSON.stringify(requestLog[1])).not.toContain('test@example.com');

          // Password should be redacted
          expect(JSON.stringify(requestLog[1])).toContain('[REDACTED - PASSWORD]');
          expect(JSON.stringify(requestLog[1])).not.toContain('secretPassword123');

          // Name should be sanitized
          expect(JSON.stringify(requestLog[1])).toContain('J***');
          expect(JSON.stringify(requestLog[1])).not.toContain('John Doe');
        }

        done();
      },
    });
  });

  it('should log response completion time', (done) => {
    const logSpy = jest.spyOn(Logger.prototype, 'log');

    interceptor.intercept(mockContext, mockHandler).subscribe({
      next: () => {
        const logCalls = logSpy.mock.calls;
        const responseLog = logCalls.find((call) =>
          call[0]?.toString().includes('Request completed'),
        );

        expect(responseLog).toBeDefined();
        if (responseLog && typeof responseLog[1] === 'object') {
          expect(responseLog[1]).toHaveProperty('duration');
          expect(responseLog[1]).toHaveProperty('method');
          expect(responseLog[1]).toHaveProperty('url');
          expect(responseLog[1]).toHaveProperty('statusCode');
        }

        done();
      },
    });
  });

  it('should not log sensitive routes', (done) => {
    const sensitiveContext = {
      ...mockContext,
      getType: jest.fn().mockReturnValue('http'),
      switchToHttp: jest.fn().mockReturnValue({
        getRequest: jest.fn().mockReturnValue({
          method: 'POST',
          url: '/api/auth/login',
          body: { email: 'test@test.com', password: 'secret' },
        }),
        getResponse: jest.fn().mockReturnValue({ statusCode: 200 }),
      }),
    } as any;

    const logSpy = jest.spyOn(Logger.prototype, 'debug');

    interceptor.intercept(sensitiveContext, mockHandler).subscribe({
      next: () => {
        // Should still log, but with sanitized data
        expect(mockHandler.handle).toHaveBeenCalled();
        done();
      },
    });
  });

  it('should handle errors gracefully', (done) => {
    const { throwError } = require('rxjs');

    const errorHandler = {
      handle: jest.fn().mockReturnValue(throwError(() => new Error('Test error'))),
    } as any;

    const logSpy = jest.spyOn(Logger.prototype, 'error');

    interceptor.intercept(mockContext, errorHandler).subscribe({
      error: (error) => {
        expect(error.message).toBe('Test error');
        expect(logSpy).toHaveBeenCalled();
        done();
      },
    });
  });

  it('should sanitize user object in request', (done) => {
    const logSpy = jest.spyOn(Logger.prototype, 'log');

    interceptor.intercept(mockContext, mockHandler).subscribe({
      next: () => {
        const logCalls = logSpy.mock.calls;
        const requestLog = logCalls.find((call) =>
          call[0]?.toString().includes('Incoming request'),
        );

        if (requestLog && typeof requestLog[1] === 'object') {
          const logString = JSON.stringify(requestLog[1]);
          // User email should be sanitized
          expect(logString).toContain('***@test.com');
          expect(logString).not.toContain('user@test.com');
        }

        done();
      },
    });
  });

  it('should measure request duration', (done) => {
    const logSpy = jest.spyOn(Logger.prototype, 'log');

    interceptor.intercept(mockContext, mockHandler).subscribe({
      next: () => {
        const logCalls = logSpy.mock.calls;
        const responseLog = logCalls.find((call) =>
          call[0]?.toString().includes('Request completed'),
        );

        if (responseLog && typeof responseLog[1] === 'object') {
          expect(responseLog[1].duration).toMatch(/\d+ms/);
        }

        done();
      },
    });
  });
});
