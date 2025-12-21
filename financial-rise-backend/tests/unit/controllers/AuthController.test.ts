import { Request, Response } from 'express';
import { AuthController } from '../../../src/controllers/AuthController';
import { AuthService } from '../../../src/services/AuthService';
import { UserRole } from '../../../src/database/entities/User';

// Mock AuthService
const mockAuthService = {
  register: jest.fn(),
  login: jest.fn(),
  logout: jest.fn(),
  refreshAccessToken: jest.fn(),
  forgotPassword: jest.fn(),
  resetPassword: jest.fn()
} as unknown as AuthService;

describe('AuthController', () => {
  let authController: AuthController;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let jsonMock: jest.Mock;
  let statusMock: jest.Mock;

  beforeEach(() => {
    jest.clearAllMocks();
    authController = new AuthController(mockAuthService);

    jsonMock = jest.fn();
    statusMock = jest.fn().mockReturnValue({ json: jsonMock });

    mockRequest = {
      body: {},
      ip: '192.168.1.1',
      socket: { remoteAddress: '192.168.1.1' } as any
    };

    mockResponse = {
      status: statusMock,
      json: jsonMock
    };
  });

  describe('register', () => {
    it('should successfully register a new user', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      (mockAuthService.register as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'newuser@example.com',
        role: UserRole.CONSULTANT
      });

      await authController.register(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.register).toHaveBeenCalledWith({
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      });
      expect(statusMock).toHaveBeenCalledWith(201);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'Account created successfully',
        userId: 'user-123'
      });
    });

    it('should default to CONSULTANT role if not provided', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'SecurePass123!'
      };

      (mockAuthService.register as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'newuser@example.com',
        role: UserRole.CONSULTANT
      });

      await authController.register(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.register).toHaveBeenCalledWith({
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      });
    });

    it('should return 409 if email already registered', async () => {
      mockRequest.body = {
        email: 'existing@example.com',
        password: 'SecurePass123!'
      };

      (mockAuthService.register as jest.Mock).mockRejectedValue(
        new Error('Email already registered')
      );

      await authController.register(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(409);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Conflict',
        message: 'Email already registered'
      });
    });

    it('should return 422 if password validation fails', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'weak'
      };

      (mockAuthService.register as jest.Mock).mockRejectedValue(
        new Error('Password must be at least 12 characters long')
      );

      await authController.register(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(422);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Validation Error',
        message: 'Password must be at least 12 characters long'
      });
    });

    it('should return 400 for other errors', async () => {
      mockRequest.body = {
        email: 'invalid',
        password: 'SecurePass123!'
      };

      (mockAuthService.register as jest.Mock).mockRejectedValue(
        new Error('Invalid email format')
      );

      await authController.register(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid email format'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.body = {
        email: 'newuser@example.com',
        password: 'SecurePass123!'
      };

      (mockAuthService.register as jest.Mock).mockRejectedValue('Unexpected error');

      await authController.register(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('login', () => {
    it('should successfully login a user', async () => {
      mockRequest.body = {
        email: 'user@example.com',
        password: 'SecurePass123!'
      };

      const mockLoginResponse = {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 900,
        user: {
          id: 'user-123',
          email: 'user@example.com',
          role: UserRole.CONSULTANT
        }
      };

      (mockAuthService.login as jest.Mock).mockResolvedValue(mockLoginResponse);

      await authController.login(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.login).toHaveBeenCalledWith({
        email: 'user@example.com',
        password: 'SecurePass123!',
        ipAddress: '192.168.1.1'
      });
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(mockLoginResponse);
    });

    it('should return 403 if account is locked', async () => {
      mockRequest.body = {
        email: 'user@example.com',
        password: 'SecurePass123!'
      };

      (mockAuthService.login as jest.Mock).mockRejectedValue(
        new Error('Account locked due to too many failed attempts')
      );

      await authController.login(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(403);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Forbidden',
        message: 'Account locked due to too many failed attempts'
      });
    });

    it('should return 401 for invalid credentials', async () => {
      mockRequest.body = {
        email: 'user@example.com',
        password: 'WrongPassword123!'
      };

      (mockAuthService.login as jest.Mock).mockRejectedValue(
        new Error('Invalid credentials')
      );

      await authController.login(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid credentials'
      });
    });

    it('should return 401 for deactivated account', async () => {
      mockRequest.body = {
        email: 'user@example.com',
        password: 'SecurePass123!'
      };

      (mockAuthService.login as jest.Mock).mockRejectedValue(
        new Error('Account is deactivated')
      );

      await authController.login(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Account is deactivated'
      });
    });

    it('should handle missing IP address', async () => {
      const requestWithoutIp: Partial<Request> = {
        body: {
          email: 'user@example.com',
          password: 'SecurePass123!'
        },
        socket: { remoteAddress: undefined } as any,
        headers: {}
      };

      (mockAuthService.login as jest.Mock).mockResolvedValue({
        accessToken: 'token',
        refreshToken: 'refresh',
        expiresIn: 900,
        user: { id: '123', email: 'user@example.com', role: UserRole.CONSULTANT }
      });

      await authController.login(requestWithoutIp as Request, mockResponse as Response);

      expect(mockAuthService.login).toHaveBeenCalledWith(
        expect.objectContaining({ ipAddress: 'unknown' })
      );
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.body = {
        email: 'user@example.com',
        password: 'SecurePass123!'
      };

      (mockAuthService.login as jest.Mock).mockRejectedValue('Unexpected error');

      await authController.login(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('logout', () => {
    it('should successfully logout a user', async () => {
      mockRequest.user = { userId: 'user-123', email: 'user@example.com', role: UserRole.CONSULTANT };
      mockRequest.body = { refreshToken: 'refresh-token' };

      (mockAuthService.logout as jest.Mock).mockResolvedValue(undefined);

      await authController.logout(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.logout).toHaveBeenCalledWith('user-123', 'refresh-token');
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'Logged out successfully'
      });
    });

    it('should return 401 if user not authenticated', async () => {
      mockRequest.user = undefined;
      mockRequest.body = { refreshToken: 'refresh-token' };

      await authController.logout(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.logout).not.toHaveBeenCalled();
      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Authentication required'
      });
    });

    it('should return 400 for service errors', async () => {
      mockRequest.user = { userId: 'user-123', email: 'user@example.com', role: UserRole.CONSULTANT };
      mockRequest.body = { refreshToken: 'refresh-token' };

      (mockAuthService.logout as jest.Mock).mockRejectedValue(
        new Error('Token not found')
      );

      await authController.logout(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Token not found'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.user = { userId: 'user-123', email: 'user@example.com', role: UserRole.CONSULTANT };
      mockRequest.body = { refreshToken: 'refresh-token' };

      (mockAuthService.logout as jest.Mock).mockRejectedValue('Unexpected error');

      await authController.logout(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('refresh', () => {
    it('should successfully refresh access token', async () => {
      mockRequest.body = { refreshToken: 'refresh-token' };

      const mockRefreshResponse = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresIn: 900
      };

      (mockAuthService.refreshAccessToken as jest.Mock).mockResolvedValue(mockRefreshResponse);

      await authController.refresh(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.refreshAccessToken).toHaveBeenCalledWith('refresh-token');
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith(mockRefreshResponse);
    });

    it('should return 401 for invalid refresh token', async () => {
      mockRequest.body = { refreshToken: 'invalid-token' };

      (mockAuthService.refreshAccessToken as jest.Mock).mockRejectedValue(
        new Error('Invalid or expired refresh token')
      );

      await authController.refresh(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(401);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Unauthorized',
        message: 'Invalid or expired refresh token'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.body = { refreshToken: 'refresh-token' };

      (mockAuthService.refreshAccessToken as jest.Mock).mockRejectedValue('Unexpected error');

      await authController.refresh(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('forgotPassword', () => {
    it('should return success message in production', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';

      mockRequest.body = { email: 'user@example.com' };

      (mockAuthService.forgotPassword as jest.Mock).mockResolvedValue('reset-token-123');

      await authController.forgotPassword(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.forgotPassword).toHaveBeenCalledWith('user@example.com');
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'If an account exists with this email, a password reset link has been sent.'
      });

      process.env.NODE_ENV = originalEnv;
    });

    it('should return token in development mode', async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'development';

      mockRequest.body = { email: 'user@example.com' };

      (mockAuthService.forgotPassword as jest.Mock).mockResolvedValue('reset-token-123');

      await authController.forgotPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'If an account exists with this email, a password reset link has been sent.',
        token: 'reset-token-123'
      });

      process.env.NODE_ENV = originalEnv;
    });

    it('should return 400 for service errors', async () => {
      mockRequest.body = { email: 'invalid-email' };

      (mockAuthService.forgotPassword as jest.Mock).mockRejectedValue(
        new Error('Invalid email')
      );

      await authController.forgotPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid email'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.body = { email: 'user@example.com' };

      (mockAuthService.forgotPassword as jest.Mock).mockRejectedValue('Unexpected error');

      await authController.forgotPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });

  describe('resetPassword', () => {
    it('should successfully reset password', async () => {
      mockRequest.body = {
        token: 'reset-token-123',
        newPassword: 'NewSecurePass456!'
      };

      (mockAuthService.resetPassword as jest.Mock).mockResolvedValue(undefined);

      await authController.resetPassword(mockRequest as Request, mockResponse as Response);

      expect(mockAuthService.resetPassword).toHaveBeenCalledWith('reset-token-123', 'NewSecurePass456!');
      expect(statusMock).toHaveBeenCalledWith(200);
      expect(jsonMock).toHaveBeenCalledWith({
        message: 'Password reset successfully'
      });
    });

    it('should return 400 for invalid token', async () => {
      mockRequest.body = {
        token: 'invalid-token',
        newPassword: 'NewSecurePass456!'
      };

      (mockAuthService.resetPassword as jest.Mock).mockRejectedValue(
        new Error('Invalid or expired reset token')
      );

      await authController.resetPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Invalid or expired reset token'
      });
    });

    it('should return 400 for already used token', async () => {
      mockRequest.body = {
        token: 'used-token',
        newPassword: 'NewSecurePass456!'
      };

      (mockAuthService.resetPassword as jest.Mock).mockRejectedValue(
        new Error('Reset token has already been used')
      );

      await authController.resetPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(400);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Bad Request',
        message: 'Reset token has already been used'
      });
    });

    it('should return 422 for weak password', async () => {
      mockRequest.body = {
        token: 'reset-token-123',
        newPassword: 'weak'
      };

      (mockAuthService.resetPassword as jest.Mock).mockRejectedValue(
        new Error('Password must be at least 12 characters long')
      );

      await authController.resetPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(422);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Validation Error',
        message: 'Password must be at least 12 characters long'
      });
    });

    it('should return 500 for unexpected errors', async () => {
      mockRequest.body = {
        token: 'reset-token-123',
        newPassword: 'NewSecurePass456!'
      };

      (mockAuthService.resetPassword as jest.Mock).mockRejectedValue('Unexpected error');

      await authController.resetPassword(mockRequest as Request, mockResponse as Response);

      expect(statusMock).toHaveBeenCalledWith(500);
      expect(jsonMock).toHaveBeenCalledWith({
        error: 'Internal Server Error',
        message: 'An unexpected error occurred'
      });
    });
  });
});
