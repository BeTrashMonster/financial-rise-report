import { AuthService } from '../../../src/services/AuthService';
import { User, UserRole } from '../../../src/database/entities/User';
import { Repository, MoreThan, IsNull } from 'typeorm';
import * as passwordUtils from '../../../src/utils/password';
import * as jwtUtils from '../../../src/utils/jwt';

// Mock utilities
jest.mock('../../../src/utils/password');
jest.mock('../../../src/utils/jwt');
jest.mock('crypto', () => ({
  randomBytes: jest.fn(() => ({
    toString: jest.fn(() => 'mock-random-token-12345')
  }))
}));

// Mock repositories
const mockUserRepository = {
  findOne: jest.fn(),
  create: jest.fn(),
  save: jest.fn()
} as unknown as Repository<User>;

const mockRefreshTokenRepository = {
  findOne: jest.fn(),
  create: jest.fn(),
  save: jest.fn(),
  remove: jest.fn(),
  update: jest.fn()
} as unknown as Repository<any>;

const mockPasswordResetTokenRepository = {
  findOne: jest.fn(),
  create: jest.fn(),
  save: jest.fn()
} as unknown as Repository<any>;

const mockFailedLoginAttemptRepository = {
  count: jest.fn(),
  create: jest.fn(),
  save: jest.fn(),
  delete: jest.fn()
} as unknown as Repository<any>;

const mockAuditLogRepository = {
  create: jest.fn(),
  save: jest.fn()
} as unknown as Repository<any>;

describe('AuthService', () => {
  let authService: AuthService;

  beforeEach(() => {
    jest.clearAllMocks();
    authService = new AuthService(
      mockUserRepository,
      mockRefreshTokenRepository,
      mockPasswordResetTokenRepository,
      mockFailedLoginAttemptRepository,
      mockAuditLogRepository
    );

    // Default mock implementations
    (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
    (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});
  });

  describe('register', () => {
    const validRegisterInput = {
      email: 'newuser@example.com',
      password: 'SecurePass123!',
      role: UserRole.CONSULTANT
    };

    it('should successfully register a new user', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      (passwordUtils.validatePasswordComplexity as jest.Mock).mockReturnValue({
        valid: true,
        errors: []
      });
      (passwordUtils.hashPassword as jest.Mock).mockResolvedValue('hashed-password');

      const mockUser = {
        id: 'user-123',
        email: validRegisterInput.email,
        role: validRegisterInput.role,
        isActive: true,
        emailVerified: false
      };

      (mockUserRepository.create as jest.Mock).mockReturnValue(mockUser);
      (mockUserRepository.save as jest.Mock).mockResolvedValue(mockUser);

      const result = await authService.register(validRegisterInput);

      expect(result).toEqual(mockUser);
      expect(mockUserRepository.findOne).toHaveBeenCalledWith({
        where: { email: validRegisterInput.email }
      });
      expect(passwordUtils.validatePasswordComplexity).toHaveBeenCalledWith(validRegisterInput.password);
      expect(passwordUtils.hashPassword).toHaveBeenCalledWith(validRegisterInput.password);
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error if email already exists', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue({
        email: validRegisterInput.email
      });

      await expect(authService.register(validRegisterInput)).rejects.toThrow('Email already registered');
      expect(passwordUtils.validatePasswordComplexity).not.toHaveBeenCalled();
    });

    it('should throw error if password is weak', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      (passwordUtils.validatePasswordComplexity as jest.Mock).mockReturnValue({
        valid: false,
        errors: ['Password must be at least 12 characters long']
      });

      await expect(authService.register({
        ...validRegisterInput,
        password: 'weak'
      })).rejects.toThrow('Password must be at least 12 characters long');
      expect(passwordUtils.hashPassword).not.toHaveBeenCalled();
    });

    it('should default to CONSULTANT role if not specified', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      (passwordUtils.validatePasswordComplexity as jest.Mock).mockReturnValue({
        valid: true,
        errors: []
      });
      (passwordUtils.hashPassword as jest.Mock).mockResolvedValue('hashed-password');

      const mockUser = {
        id: 'user-123',
        email: validRegisterInput.email,
        role: UserRole.CONSULTANT
      };

      (mockUserRepository.create as jest.Mock).mockReturnValue(mockUser);
      (mockUserRepository.save as jest.Mock).mockResolvedValue(mockUser);

      await authService.register({
        email: validRegisterInput.email,
        password: validRegisterInput.password
      });

      expect(mockUserRepository.create).toHaveBeenCalledWith(
        expect.objectContaining({ role: UserRole.CONSULTANT })
      );
    });
  });

  describe('login', () => {
    const validLoginInput = {
      email: 'user@example.com',
      password: 'SecurePass123!',
      ipAddress: '192.168.1.1'
    };

    const mockUser = {
      id: 'user-123',
      email: validLoginInput.email,
      passwordHash: 'hashed-password',
      role: UserRole.CONSULTANT,
      isActive: true,
      lastLoginAt: null
    };

    beforeEach(() => {
      (mockFailedLoginAttemptRepository.count as jest.Mock).mockResolvedValue(0);
    });

    it('should successfully login with valid credentials', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (passwordUtils.verifyPassword as jest.Mock).mockResolvedValue(true);
      (mockUserRepository.save as jest.Mock).mockResolvedValue({ ...mockUser, lastLoginAt: new Date() });

      (jwtUtils.createAccessToken as jest.Mock).mockReturnValue('access-token');
      (jwtUtils.createRefreshToken as jest.Mock).mockReturnValue('refresh-token');

      const mockRefreshToken = { id: 'token-123', token: 'refresh-token' };
      (mockRefreshTokenRepository.create as jest.Mock).mockReturnValue(mockRefreshToken);
      (mockRefreshTokenRepository.save as jest.Mock).mockResolvedValue(mockRefreshToken);
      (mockFailedLoginAttemptRepository.delete as jest.Mock).mockResolvedValue({});

      const result = await authService.login(validLoginInput);

      expect(result).toEqual({
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
        expiresIn: 900,
        user: {
          id: mockUser.id,
          email: mockUser.email,
          role: mockUser.role
        }
      });
      expect(mockFailedLoginAttemptRepository.delete).toHaveBeenCalledWith({ email: validLoginInput.email });
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error if account is locked', async () => {
      (mockFailedLoginAttemptRepository.count as jest.Mock).mockResolvedValue(5);

      await expect(authService.login(validLoginInput)).rejects.toThrow(
        'Account locked due to too many failed attempts'
      );
      expect(mockUserRepository.findOne).not.toHaveBeenCalled();
    });

    it('should throw error and record failed attempt if user not found', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      (mockFailedLoginAttemptRepository.create as jest.Mock).mockReturnValue({});
      (mockFailedLoginAttemptRepository.save as jest.Mock).mockResolvedValue({});

      await expect(authService.login(validLoginInput)).rejects.toThrow('Invalid credentials');
      expect(mockFailedLoginAttemptRepository.save).toHaveBeenCalled();
    });

    it('should throw error and record failed attempt if password is invalid', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (passwordUtils.verifyPassword as jest.Mock).mockResolvedValue(false);
      (mockFailedLoginAttemptRepository.create as jest.Mock).mockReturnValue({});
      (mockFailedLoginAttemptRepository.save as jest.Mock).mockResolvedValue({});

      await expect(authService.login(validLoginInput)).rejects.toThrow('Invalid credentials');
      expect(mockFailedLoginAttemptRepository.save).toHaveBeenCalled();
    });

    it('should throw error if account is deactivated', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue({
        ...mockUser,
        isActive: false
      });
      (passwordUtils.verifyPassword as jest.Mock).mockResolvedValue(true);

      await expect(authService.login(validLoginInput)).rejects.toThrow('Account is deactivated');
    });

    it('should update lastLoginAt timestamp', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (passwordUtils.verifyPassword as jest.Mock).mockResolvedValue(true);
      (mockUserRepository.save as jest.Mock).mockResolvedValue(mockUser);

      (jwtUtils.createAccessToken as jest.Mock).mockReturnValue('access-token');
      (jwtUtils.createRefreshToken as jest.Mock).mockReturnValue('refresh-token');

      const mockRefreshToken = { id: 'token-123' };
      (mockRefreshTokenRepository.create as jest.Mock).mockReturnValue(mockRefreshToken);
      (mockRefreshTokenRepository.save as jest.Mock).mockResolvedValue(mockRefreshToken);
      (mockFailedLoginAttemptRepository.delete as jest.Mock).mockResolvedValue({});

      await authService.login(validLoginInput);

      expect(mockUserRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          lastLoginAt: expect.any(Date)
        })
      );
    });
  });

  describe('logout', () => {
    it('should revoke refresh token and log audit', async () => {
      const mockToken = {
        id: 'token-123',
        token: 'refresh-token',
        userId: 'user-123',
        revokedAt: null
      };

      (mockRefreshTokenRepository.findOne as jest.Mock).mockResolvedValue(mockToken);
      (mockRefreshTokenRepository.save as jest.Mock).mockResolvedValue({
        ...mockToken,
        revokedAt: expect.any(Date)
      });

      await authService.logout('user-123', 'refresh-token');

      expect(mockRefreshTokenRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ revokedAt: expect.any(Date) })
      );
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should handle logout when token not found', async () => {
      (mockRefreshTokenRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(authService.logout('user-123', 'invalid-token')).resolves.not.toThrow();
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });
  });

  describe('refreshAccessToken', () => {
    const mockTokenPayload = {
      userId: 'user-123',
      tokenId: 'token-123'
    };

    const mockTokenEntity = {
      id: 'token-123',
      token: 'refresh-token',
      userId: 'user-123',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      revokedAt: null,
      user: {
        id: 'user-123',
        email: 'user@example.com',
        role: UserRole.CONSULTANT
      }
    };

    it('should successfully refresh access token', async () => {
      (jwtUtils.verifyRefreshToken as jest.Mock).mockReturnValue(mockTokenPayload);
      (mockRefreshTokenRepository.findOne as jest.Mock).mockResolvedValue(mockTokenEntity);
      (mockRefreshTokenRepository.remove as jest.Mock).mockResolvedValue({});

      const newTokenEntity = { id: 'new-token-123' };
      (mockRefreshTokenRepository.create as jest.Mock).mockReturnValue(newTokenEntity);
      (mockRefreshTokenRepository.save as jest.Mock).mockResolvedValue(newTokenEntity);

      (jwtUtils.createAccessToken as jest.Mock).mockReturnValue('new-access-token');
      (jwtUtils.createRefreshToken as jest.Mock).mockReturnValue('new-refresh-token');
      (jwtUtils.getTokenExpirationDate as jest.Mock).mockReturnValue(new Date());

      const result = await authService.refreshAccessToken('refresh-token');

      expect(result).toEqual({
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token',
        expiresIn: 900
      });
      expect(mockRefreshTokenRepository.remove).toHaveBeenCalledWith(mockTokenEntity);
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error if JWT verification fails', async () => {
      (jwtUtils.verifyRefreshToken as jest.Mock).mockImplementation(() => {
        throw new Error('Invalid token');
      });

      await expect(authService.refreshAccessToken('invalid-token')).rejects.toThrow(
        'Invalid or expired refresh token'
      );
    });

    it('should throw error if token not found in database', async () => {
      (jwtUtils.verifyRefreshToken as jest.Mock).mockReturnValue(mockTokenPayload);
      (mockRefreshTokenRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(authService.refreshAccessToken('refresh-token')).rejects.toThrow(
        'Refresh token not found'
      );
    });

    it('should throw error if token is revoked', async () => {
      (jwtUtils.verifyRefreshToken as jest.Mock).mockReturnValue(mockTokenPayload);
      (mockRefreshTokenRepository.findOne as jest.Mock).mockResolvedValue({
        ...mockTokenEntity,
        revokedAt: new Date()
      });

      await expect(authService.refreshAccessToken('refresh-token')).rejects.toThrow(
        'Refresh token has been revoked'
      );
    });

    it('should throw error if token is expired', async () => {
      (jwtUtils.verifyRefreshToken as jest.Mock).mockReturnValue(mockTokenPayload);
      (mockRefreshTokenRepository.findOne as jest.Mock).mockResolvedValue({
        ...mockTokenEntity,
        expiresAt: new Date(Date.now() - 1000)
      });

      await expect(authService.refreshAccessToken('refresh-token')).rejects.toThrow(
        'Refresh token has expired'
      );
    });
  });

  describe('forgotPassword', () => {
    it('should generate reset token for existing user', async () => {
      const mockUser = {
        id: 'user-123',
        email: 'user@example.com'
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(mockUser);
      (mockPasswordResetTokenRepository.create as jest.Mock).mockReturnValue({
        userId: mockUser.id,
        token: 'mock-random-token-12345',
        expiresAt: expect.any(Date)
      });
      (mockPasswordResetTokenRepository.save as jest.Mock).mockResolvedValue({});

      const token = await authService.forgotPassword('user@example.com');

      expect(token).toBe('mock-random-token-12345');
      expect(mockPasswordResetTokenRepository.save).toHaveBeenCalled();
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should return fake token if user not found (prevent email enumeration)', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);

      const token = await authService.forgotPassword('nonexistent@example.com');

      expect(token).toBe('mock-random-token-12345');
      expect(mockPasswordResetTokenRepository.save).not.toHaveBeenCalled();
      expect(mockAuditLogRepository.save).not.toHaveBeenCalled();
    });
  });

  describe('resetPassword', () => {
    const mockResetToken = {
      id: 'reset-123',
      token: 'reset-token',
      userId: 'user-123',
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      usedAt: null,
      user: {
        id: 'user-123',
        email: 'user@example.com',
        passwordHash: 'old-hash'
      }
    };

    it('should successfully reset password', async () => {
      (mockPasswordResetTokenRepository.findOne as jest.Mock).mockResolvedValue(mockResetToken);
      (passwordUtils.validatePasswordComplexity as jest.Mock).mockReturnValue({
        valid: true,
        errors: []
      });
      (passwordUtils.hashPassword as jest.Mock).mockResolvedValue('new-hashed-password');
      (mockUserRepository.save as jest.Mock).mockResolvedValue({});
      (mockPasswordResetTokenRepository.save as jest.Mock).mockResolvedValue({});
      (mockRefreshTokenRepository.update as jest.Mock).mockResolvedValue({});

      await authService.resetPassword('reset-token', 'NewSecurePass456!');

      expect(mockUserRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          passwordHash: 'new-hashed-password'
        })
      );
      expect(mockPasswordResetTokenRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({ usedAt: expect.any(Date) })
      );
      expect(mockRefreshTokenRepository.update).toHaveBeenCalled();
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error if token not found', async () => {
      (mockPasswordResetTokenRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(authService.resetPassword('invalid-token', 'NewPass123!')).rejects.toThrow(
        'Invalid or expired reset token'
      );
    });

    it('should throw error if token already used', async () => {
      (mockPasswordResetTokenRepository.findOne as jest.Mock).mockResolvedValue({
        ...mockResetToken,
        usedAt: new Date()
      });

      await expect(authService.resetPassword('reset-token', 'NewPass123!')).rejects.toThrow(
        'Reset token has already been used'
      );
    });

    it('should throw error if token expired', async () => {
      (mockPasswordResetTokenRepository.findOne as jest.Mock).mockResolvedValue({
        ...mockResetToken,
        usedAt: null,
        expiresAt: new Date(Date.now() - 1000)
      });

      await expect(authService.resetPassword('reset-token', 'NewPass123!')).rejects.toThrow(
        'Reset token has expired'
      );
    });

    it('should throw error if new password is weak', async () => {
      // Fresh mock without usedAt
      const freshMockResetToken = {
        ...mockResetToken,
        usedAt: null
      };
      (mockPasswordResetTokenRepository.findOne as jest.Mock).mockResolvedValue(freshMockResetToken);
      (passwordUtils.validatePasswordComplexity as jest.Mock).mockReturnValue({
        valid: false,
        errors: ['Password must be at least 12 characters long']
      });

      await expect(authService.resetPassword('reset-token', 'weak')).rejects.toThrow(
        'Password must be at least 12 characters long'
      );
      expect(mockUserRepository.save).not.toHaveBeenCalled();
    });

    it('should revoke all refresh tokens after password reset', async () => {
      // Fresh mock without usedAt
      const freshMockResetToken = {
        ...mockResetToken,
        usedAt: null
      };
      (mockPasswordResetTokenRepository.findOne as jest.Mock).mockResolvedValue(freshMockResetToken);
      (passwordUtils.validatePasswordComplexity as jest.Mock).mockReturnValue({
        valid: true,
        errors: []
      });
      (passwordUtils.hashPassword as jest.Mock).mockResolvedValue('new-hashed-password');
      (mockUserRepository.save as jest.Mock).mockResolvedValue({});
      (mockPasswordResetTokenRepository.save as jest.Mock).mockResolvedValue({});
      (mockRefreshTokenRepository.update as jest.Mock).mockResolvedValue({});

      await authService.resetPassword('reset-token', 'NewSecurePass456!');

      expect(mockRefreshTokenRepository.update).toHaveBeenCalledWith(
        { userId: freshMockResetToken.userId, revokedAt: IsNull() },
        { revokedAt: expect.any(Date) }
      );
    });
  });
});
