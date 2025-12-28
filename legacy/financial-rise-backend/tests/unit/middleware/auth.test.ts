import { Request, Response, NextFunction } from 'express';
import { authenticate, authorize, optionalAuth } from '../../../src/middleware/auth';
import { verifyAccessToken } from '../../../src/utils/jwt';
import { UserRole } from '../../../src/database/entities/User';

// Mock JWT utilities
jest.mock('../../../src/utils/jwt');

describe('Authentication Middleware', () => {
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();

    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });
    nextFunction = jest.fn();

    mockRequest = {
      headers: {}
    };

    mockResponse = {
      status: statusMock,
      json: jsonMock
    };
  });

  describe('authenticate', () => {
    it('should authenticate valid token and attach user to request', () => {
      const mockPayload = {
        userId: 'user-123',
        email: 'user@example.com',
        role: UserRole.CONSULTANT
      };

      mockRequest.headers = {
        authorization: 'Bearer valid-token-12345'
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(mockPayload);

      authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(verifyAccessToken).toHaveBeenCalledWith('valid-token-12345');
      expect(mockRequest.user).toEqual(mockPayload);
      expect(nextFunction).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should return 401 if no authorization header provided', () => {
      mockRequest.headers = {};

      authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'No token provided'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should return 401 if authorization header does not start with Bearer', () => {
      mockRequest.headers = {
        authorization: 'Basic invalid-auth-scheme'
      };

      authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'No token provided'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should return 401 if token verification fails', () => {
      mockRequest.headers = {
        authorization: 'Bearer invalid-token'
      };

      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Token expired');
      });

      authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Token expired'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should return 401 with generic message for non-Error exceptions', () => {
      mockRequest.headers = {
        authorization: 'Bearer malformed-token'
      };

      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw 'Unexpected error';
      });

      authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid token'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should correctly extract token after "Bearer " prefix', () => {
      mockRequest.headers = {
        authorization: 'Bearer my-jwt-token'
      };

      (verifyAccessToken as jest.Mock).mockReturnValue({
        userId: 'user-123',
        email: 'user@example.com',
        role: UserRole.ADMIN
      });

      authenticate(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(verifyAccessToken).toHaveBeenCalledWith('my-jwt-token');
    });
  });

  describe('authorize', () => {
    it('should allow access if user has required role', () => {
      mockRequest.user = {
        userId: 'admin-123',
        email: 'admin@example.com',
        role: UserRole.ADMIN
      };

      const middleware = authorize(UserRole.ADMIN);
      middleware(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(nextFunction).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should allow access if user role matches one of allowed roles', () => {
      mockRequest.user = {
        userId: 'consultant-123',
        email: 'consultant@example.com',
        role: UserRole.CONSULTANT
      };

      const middleware = authorize(UserRole.ADMIN, UserRole.CONSULTANT);
      middleware(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(nextFunction).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should return 401 if no user attached to request', () => {
      mockRequest.user = undefined;

      const middleware = authorize(UserRole.ADMIN);
      middleware(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should return 403 if user does not have required role', () => {
      mockRequest.user = {
        userId: 'consultant-123',
        email: 'consultant@example.com',
        role: UserRole.CONSULTANT
      };

      const middleware = authorize(UserRole.ADMIN);
      middleware(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Insufficient permissions'
      });
      expect(nextFunction).not.toHaveBeenCalled();
    });

    it('should return 403 if user role is not in allowed roles list', () => {
      mockRequest.user = {
        userId: 'consultant-123',
        email: 'consultant@example.com',
        role: UserRole.CONSULTANT
      };

      const middleware = authorize(UserRole.ADMIN);
      middleware(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Insufficient permissions'
      });
    });

    it('should work with multiple allowed roles', () => {
      const adminUser = {
        userId: 'admin-123',
        email: 'admin@example.com',
        role: UserRole.ADMIN
      };

      const consultantUser = {
        userId: 'consultant-123',
        email: 'consultant@example.com',
        role: UserRole.CONSULTANT
      };

      const middleware = authorize(UserRole.ADMIN, UserRole.CONSULTANT);

      // Test admin access
      mockRequest.user = adminUser;
      const next1 = jest.fn();
      middleware(mockRequest as Request, mockResponse as Response, next1);
      expect(next1).toHaveBeenCalled();

      // Test consultant access
      mockRequest.user = consultantUser;
      const next2 = jest.fn();
      middleware(mockRequest as Request, mockResponse as Response, next2);
      expect(next2).toHaveBeenCalled();
    });
  });

  describe('optionalAuth', () => {
    it('should attach user if valid token provided', () => {
      const mockPayload = {
        userId: 'user-123',
        email: 'user@example.com',
        role: UserRole.CONSULTANT
      };

      mockRequest.headers = {
        authorization: 'Bearer valid-token'
      };

      (verifyAccessToken as jest.Mock).mockReturnValue(mockPayload);

      optionalAuth(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockRequest.user).toEqual(mockPayload);
      expect(nextFunction).toHaveBeenCalled();
    });

    it('should proceed without error if no token provided', () => {
      mockRequest.headers = {};

      optionalAuth(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockRequest.user).toBeUndefined();
      expect(nextFunction).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should proceed without error if invalid token provided', () => {
      mockRequest.headers = {
        authorization: 'Bearer invalid-token'
      };

      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      optionalAuth(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockRequest.user).toBeUndefined();
      expect(nextFunction).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
    });

    it('should proceed without error if token format is invalid', () => {
      mockRequest.headers = {
        authorization: 'InvalidFormat token'
      };

      optionalAuth(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockRequest.user).toBeUndefined();
      expect(nextFunction).toHaveBeenCalled();
      expect(verifyAccessToken).not.toHaveBeenCalled();
    });

    it('should silently ignore token verification errors', () => {
      mockRequest.headers = {
        authorization: 'Bearer expired-token'
      };

      (verifyAccessToken as jest.Mock).mockImplementation(() => {
        throw new Error('Token expired');
      });

      optionalAuth(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(mockRequest.user).toBeUndefined();
      expect(nextFunction).toHaveBeenCalled();
      expect(statusMock).not.toHaveBeenCalled();
      expect(jsonMock).not.toHaveBeenCalled();
    });

    it('should correctly extract token after "Bearer " prefix', () => {
      mockRequest.headers = {
        authorization: 'Bearer optional-token'
      };

      (verifyAccessToken as jest.Mock).mockReturnValue({
        userId: 'user-123',
        email: 'user@example.com',
        role: UserRole.CONSULTANT
      });

      optionalAuth(mockRequest as Request, mockResponse as Response, nextFunction);

      expect(verifyAccessToken).toHaveBeenCalledWith('optional-token');
    });
  });
});
