/**
 * Request Size Limits Configuration Tests
 * Work Stream 64: Request Size Limits & DoS Prevention (MED-003)
 */

import {
  getSizeLimitForPath,
  ENDPOINT_SIZE_LIMITS,
  DEFAULT_SIZE_LIMITS,
  requestSizeMonitoring,
  payloadTooLargeErrorHandler,
} from './request-size-limits.config';
import { Request, Response, NextFunction } from 'express';

describe('Request Size Limits Configuration', () => {
  describe('getSizeLimitForPath', () => {
    it('should return 1mb for authentication registration endpoint', () => {
      const limit = getSizeLimitForPath('/api/v1/auth/register');
      expect(limit).toBe('1mb');
    });

    it('should return 1mb for authentication login endpoint', () => {
      const limit = getSizeLimitForPath('/api/v1/auth/login');
      expect(limit).toBe('1mb');
    });

    it('should return 1mb for forgot-password endpoint', () => {
      const limit = getSizeLimitForPath('/api/v1/auth/forgot-password');
      expect(limit).toBe('1mb');
    });

    it('should return 1mb for reset-password endpoint', () => {
      const limit = getSizeLimitForPath('/api/v1/auth/reset-password');
      expect(limit).toBe('1mb');
    });

    it('should return 5mb for assessment response endpoints', () => {
      const limit = getSizeLimitForPath('/api/v1/assessments/123/responses');
      expect(limit).toBe('5mb');
    });

    it('should return 5mb for report endpoints', () => {
      const limit = getSizeLimitForPath('/api/v1/reports/456');
      expect(limit).toBe('5mb');
    });

    it('should return default 10mb for unmatched endpoints', () => {
      const limit = getSizeLimitForPath('/api/v1/users/123');
      expect(limit).toBe('10mb');
    });

    it('should return default 10mb for health check endpoint', () => {
      const limit = getSizeLimitForPath('/api/v1/health');
      expect(limit).toBe('10mb');
    });
  });

  describe('ENDPOINT_SIZE_LIMITS configuration', () => {
    it('should have authentication endpoint limits configured', () => {
      const authConfig = ENDPOINT_SIZE_LIMITS.find(c =>
        c.description.includes('Authentication'),
      );
      expect(authConfig).toBeDefined();
      expect(authConfig?.limit).toBe('1mb');
    });

    it('should have assessment endpoint limits configured', () => {
      const assessmentConfig = ENDPOINT_SIZE_LIMITS.find(c =>
        c.description.includes('Assessment'),
      );
      expect(assessmentConfig).toBeDefined();
      expect(assessmentConfig?.limit).toBe('5mb');
    });

    it('should have report endpoint limits configured', () => {
      const reportConfig = ENDPOINT_SIZE_LIMITS.find(c =>
        c.description.includes('Report'),
      );
      expect(reportConfig).toBeDefined();
      expect(reportConfig?.limit).toBe('5mb');
    });

    it('should have at least 3 endpoint configurations', () => {
      expect(ENDPOINT_SIZE_LIMITS.length).toBeGreaterThanOrEqual(3);
    });
  });

  describe('DEFAULT_SIZE_LIMITS', () => {
    it('should have json limit set to 10mb', () => {
      expect(DEFAULT_SIZE_LIMITS.json).toBe('10mb');
    });

    it('should have urlencoded limit set to 10mb', () => {
      expect(DEFAULT_SIZE_LIMITS.urlencoded).toBe('10mb');
    });
  });

  describe('requestSizeMonitoring middleware', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: NextFunction;
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
      mockReq = {
        method: 'POST',
        path: '/api/v1/auth/register',
        get: jest.fn(),
      };
      mockRes = {};
      mockNext = jest.fn();
      consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    });

    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });

    it('should call next() when content-length header is present', () => {
      (mockReq.get as jest.Mock).mockReturnValue('1024');

      requestSizeMonitoring(
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalled();
    });

    it('should attach request size metadata to request object', () => {
      (mockReq.get as jest.Mock).mockReturnValue('2048');

      requestSizeMonitoring(
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect((mockReq as any).requestSizeBytes).toBe(2048);
      expect((mockReq as any).requestSizeMB).toBe(0.00);
    });

    it('should log warning for large requests (>5MB)', () => {
      (mockReq.get as jest.Mock).mockReturnValue(String(6 * 1024 * 1024)); // 6MB

      requestSizeMonitoring(
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Large request detected'),
      );
      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('6.00MB'),
      );
    });

    it('should not log warning for small requests (<5MB)', () => {
      (mockReq.get as jest.Mock).mockReturnValue(String(2 * 1024 * 1024)); // 2MB

      requestSizeMonitoring(
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });

    it('should call next() even without content-length header', () => {
      (mockReq.get as jest.Mock).mockReturnValue(undefined);

      requestSizeMonitoring(
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalled();
    });
  });

  describe('payloadTooLargeErrorHandler', () => {
    let mockReq: Partial<Request>;
    let mockRes: Partial<Response>;
    let mockNext: NextFunction;
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
      mockReq = {
        method: 'POST',
        path: '/api/v1/auth/register',
      };
      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
      };
      mockNext = jest.fn();
      consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    });

    afterEach(() => {
      consoleWarnSpy.mockRestore();
    });

    it('should return 413 status for entity.too.large error', () => {
      const error = {
        type: 'entity.too.large',
        message: 'request entity too large',
      };

      payloadTooLargeErrorHandler(
        error,
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockRes.status).toHaveBeenCalledWith(413);
    });

    it('should return JSON error response with correct format', () => {
      const error = {
        type: 'entity.too.large',
      };

      payloadTooLargeErrorHandler(
        error,
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          statusCode: 413,
          error: 'Payload Too Large',
          message: expect.stringContaining('Maximum allowed size is 1mb'),
          path: '/api/v1/auth/register',
          timestamp: expect.any(String),
        }),
      );
    });

    it('should include correct size limit in error message', () => {
      const error = { type: 'entity.too.large' };
      const assessmentReq = {
        ...mockReq,
        path: '/api/v1/assessments/123/responses',
      };

      payloadTooLargeErrorHandler(
        error,
        assessmentReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockRes.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('5mb'),
        }),
      );
    });

    it('should log security warning for oversized requests', () => {
      const error = { type: 'entity.too.large' };

      payloadTooLargeErrorHandler(
        error,
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[DoS Prevention] Rejected oversized request'),
      );
    });

    it('should handle 413 status errors', () => {
      const error = { status: 413 };

      payloadTooLargeErrorHandler(
        error,
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockRes.status).toHaveBeenCalledWith(413);
    });

    it('should call next() for non-payload-size errors', () => {
      const error = {
        type: 'other.error',
        status: 500,
      };

      payloadTooLargeErrorHandler(
        error,
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(mockNext).toHaveBeenCalledWith(error);
      expect(mockRes.status).not.toHaveBeenCalled();
    });

    it('should not log security warning for non-payload errors', () => {
      const error = { type: 'other.error' };

      payloadTooLargeErrorHandler(
        error,
        mockReq as Request,
        mockRes as Response,
        mockNext,
      );

      expect(consoleWarnSpy).not.toHaveBeenCalled();
    });
  });
});
