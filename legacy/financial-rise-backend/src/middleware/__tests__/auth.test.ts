import { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { authenticate } from '../auth';
import { AuthenticatedRequest } from '../../types';

describe('Authentication Middleware', () => {
  let mockRequest: Partial<AuthenticatedRequest>;
  let mockResponse: Partial<Response>;
  let nextFunction: NextFunction;

  beforeEach(() => {
    mockRequest = {
      headers: {},
    };
    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    nextFunction = jest.fn();
    process.env.JWT_SECRET = 'test-secret';
  });

  it('should reject request without authorization header', async () => {
    await authenticate(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith({
      error: {
        code: 'UNAUTHORIZED',
        message: 'Missing or invalid authorization header',
      },
    });
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it('should reject request with invalid authorization header format', async () => {
    mockRequest.headers = {
      authorization: 'InvalidFormat token123',
    };

    await authenticate(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it('should reject request with invalid JWT token', async () => {
    mockRequest.headers = {
      authorization: 'Bearer invalid.jwt.token',
    };

    await authenticate(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith({
      error: {
        code: 'INVALID_TOKEN',
        message: 'Invalid JWT token',
      },
    });
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it('should reject expired JWT token', async () => {
    const expiredToken = jwt.sign(
      { consultantId: 'test-id', userId: 'user-id' },
      process.env.JWT_SECRET!,
      { expiresIn: '-1h' }
    );

    mockRequest.headers = {
      authorization: `Bearer ${expiredToken}`,
    };

    await authenticate(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

    expect(mockResponse.status).toHaveBeenCalledWith(401);
    expect(mockResponse.json).toHaveBeenCalledWith({
      error: {
        code: 'TOKEN_EXPIRED',
        message: 'JWT token has expired',
      },
    });
    expect(nextFunction).not.toHaveBeenCalled();
  });

  it('should accept valid JWT token and set consultantId', async () => {
    const token = jwt.sign(
      { consultantId: 'test-consultant-id', userId: 'test-user-id' },
      process.env.JWT_SECRET!,
      { expiresIn: '1h' }
    );

    mockRequest.headers = {
      authorization: `Bearer ${token}`,
    };

    await authenticate(mockRequest as AuthenticatedRequest, mockResponse as Response, nextFunction);

    expect(mockRequest.consultantId).toBe('test-consultant-id');
    expect(mockRequest.userId).toBe('test-user-id');
    expect(nextFunction).toHaveBeenCalled();
    expect(mockResponse.status).not.toHaveBeenCalled();
  });
});
