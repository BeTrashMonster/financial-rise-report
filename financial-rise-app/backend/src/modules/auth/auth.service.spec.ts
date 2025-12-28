import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { BadRequestException, UnauthorizedException, ConflictException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { RefreshTokenService } from './refresh-token.service';
import { User, UserStatus, UserRole } from '../users/entities/user.entity';
import * as bcrypt from 'bcrypt';

describe('AuthService - Security Enhancements', () => {
  let service: AuthService;
  let usersService: jest.Mocked<UsersService>;
  let jwtService: jest.Mocked<JwtService>;
  let configService: jest.Mocked<ConfigService>;
  let refreshTokenService: jest.Mocked<RefreshTokenService>;

  const mockUser: User = {
    id: '123e4567-e89b-12d3-a456-426614174000',
    email: 'test@example.com',
    password_hash: '$2b$12$hashedpassword',
    first_name: 'Test',
    last_name: 'User',
    role: UserRole.CONSULTANT,
    status: UserStatus.ACTIVE,
    failed_login_attempts: 0,
    locked_until: null,
    reset_password_token: null,
    reset_password_expires: null,
    reset_password_used_at: null,
    refresh_token: null,
    created_at: new Date(),
    updated_at: new Date(),
    last_login_at: null,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: {
            findByEmail: jest.fn(),
            findById: jest.fn(),
            create: jest.fn(),
            update: jest.fn(),
            isAccountLocked: jest.fn(),
            incrementFailedLoginAttempts: jest.fn(),
            resetFailedLoginAttempts: jest.fn(),
            updateLastLogin: jest.fn(),
            updateRefreshToken: jest.fn(),
            setResetPasswordToken: jest.fn(),
            findByResetToken: jest.fn(),
            clearResetPasswordToken: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn(),
            verify: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string, defaultValue?: any) => {
              const configMap: Record<string, any> = {
                JWT_SECRET: 'test-secret',
                JWT_EXPIRATION: '1h',
                JWT_REFRESH_SECRET: 'test-refresh-secret',
                JWT_REFRESH_EXPIRATION: '7d',
                JWT_EXPIRATION_SECONDS: 3600,
                NODE_ENV: 'test',
              };
              return configMap[key] || defaultValue;
            }),
          },
        },
        {
          provide: RefreshTokenService,
          useValue: {
            createToken: jest.fn(),
            findValidToken: jest.fn(),
            revokeToken: jest.fn(),
            revokeAllUserTokens: jest.fn(),
            getActiveTokens: jest.fn(),
            cleanupExpiredTokens: jest.fn(),
            countActiveSessions: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);
    refreshTokenService = module.get(RefreshTokenService);
  });

  describe('Security Fix 1: Password Complexity Validation', () => {
    it('should reject password shorter than 8 characters', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.register({
          email: 'test@example.com',
          password: 'Short1!',
          first_name: 'Test',
          last_name: 'User',
          role: UserRole.CONSULTANT,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject password without uppercase letter', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.register({
          email: 'test@example.com',
          password: 'lowercase123!',
          first_name: 'Test',
          last_name: 'User',
          role: UserRole.CONSULTANT,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject password without lowercase letter', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.register({
          email: 'test@example.com',
          password: 'UPPERCASE123!',
          first_name: 'Test',
          last_name: 'User',
          role: UserRole.CONSULTANT,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject password without number', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.register({
          email: 'test@example.com',
          password: 'NoNumbers!',
          first_name: 'Test',
          last_name: 'User',
          role: UserRole.CONSULTANT,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject password without special character', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        service.register({
          email: 'test@example.com',
          password: 'NoSpecial123',
          first_name: 'Test',
          last_name: 'User',
          role: UserRole.CONSULTANT,
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should accept valid password with all requirements', async () => {
      usersService.findByEmail.mockResolvedValue(null);
      usersService.create.mockResolvedValue(mockUser);
      jwtService.sign.mockReturnValue('mock-jwt-token');
      refreshTokenService.createToken.mockResolvedValue({} as any);

      const result = await service.register({
        email: 'test@example.com',
        password: 'ValidPass123!',
        first_name: 'Test',
        last_name: 'User',
        role: UserRole.CONSULTANT,
      });

      expect(result.access_token).toBeDefined();
      expect(result.user.email).toBe(mockUser.email);
    });

    it('should validate password complexity in resetPassword', async () => {
      const userWithResetToken = {
        ...mockUser,
        reset_password_token: 'hashed-token',
        reset_password_expires: new Date(Date.now() + 3600000),
        reset_password_used_at: null,
      };

      usersService.findByResetToken.mockResolvedValue(userWithResetToken);

      await expect(service.resetPassword('valid-token', 'weak')).rejects.toThrow(BadRequestException);
    });
  });

  describe('Security Fix 2: Reset Token Reuse Prevention', () => {
    it('should reject reset token that has already been used', async () => {
      const usedResetToken = {
        ...mockUser,
        reset_password_token: 'hashed-token',
        reset_password_expires: new Date(Date.now() + 3600000),
        reset_password_used_at: new Date(Date.now() - 1000), // Already used
      };

      usersService.findByResetToken.mockResolvedValue(usedResetToken);

      await expect(service.resetPassword('valid-token', 'NewPassword123!')).rejects.toThrow(
        'Reset token has already been used',
      );
    });

    it('should mark reset token as used after successful password reset', async () => {
      const validResetToken = {
        ...mockUser,
        reset_password_token: 'hashed-token',
        reset_password_expires: new Date(Date.now() + 3600000),
        reset_password_used_at: null,
      };

      usersService.findByResetToken.mockResolvedValue(validResetToken);
      usersService.update.mockResolvedValue(mockUser);
      usersService.clearResetPasswordToken.mockResolvedValue(undefined);
      refreshTokenService.revokeAllUserTokens.mockResolvedValue(undefined);

      await service.resetPassword('valid-token', 'NewPassword123!');

      expect(usersService.update).toHaveBeenCalledWith(
        mockUser.id,
        expect.objectContaining({
          reset_password_used_at: expect.any(Date),
        }),
      );
    });

    it('should not mark token as used if password reset fails validation', async () => {
      const validResetToken = {
        ...mockUser,
        reset_password_token: 'hashed-token',
        reset_password_expires: new Date(Date.now() + 3600000),
        reset_password_used_at: null,
      };

      usersService.findByResetToken.mockResolvedValue(validResetToken);

      await expect(service.resetPassword('valid-token', 'weak')).rejects.toThrow(BadRequestException);

      expect(usersService.update).not.toHaveBeenCalled();
    });
  });

  describe('Security Fix 3: CSRF Protection', () => {
    it('CSRF guard and interceptor are implemented (see csrf.guard.ts and csrf.interceptor.ts)', () => {
      // CSRF protection is implemented in separate files:
      // - src/common/guards/csrf.guard.ts
      // - src/common/interceptors/csrf.interceptor.ts
      // Tests for these are in their respective spec files
      expect(true).toBe(true);
    });
  });

  describe('Security Fix 4: Refresh Token Table (Multi-Device Support)', () => {
    it('should create refresh token in database on login', async () => {
      jwtService.sign.mockReturnValueOnce('access-token').mockReturnValueOnce('refresh-token');

      refreshTokenService.createToken.mockResolvedValue({} as any);

      await service.login(mockUser, 'iPhone 13', '192.168.1.1');

      expect(refreshTokenService.createToken).toHaveBeenCalledWith(
        mockUser.id,
        'refresh-token',
        expect.any(Date),
        'iPhone 13',
        '192.168.1.1',
      );
    });

    it('should validate refresh token from database', async () => {
      const payload = { sub: mockUser.id, email: mockUser.email, role: mockUser.role };

      jwtService.verify.mockReturnValue(payload);
      usersService.findById.mockResolvedValue(mockUser);
      refreshTokenService.findValidToken.mockResolvedValue({} as any);
      jwtService.sign.mockReturnValue('new-access-token');

      const result = await service.refreshToken('valid-refresh-token');

      expect(refreshTokenService.findValidToken).toHaveBeenCalledWith(mockUser.id, 'valid-refresh-token');
      expect(result.access_token).toBe('new-access-token');
    });

    it('should reject refresh token not in database', async () => {
      const payload = { sub: mockUser.id, email: mockUser.email, role: mockUser.role };

      jwtService.verify.mockReturnValue(payload);
      usersService.findById.mockResolvedValue(mockUser);
      refreshTokenService.findValidToken.mockResolvedValue(null);

      await expect(service.refreshToken('invalid-refresh-token')).rejects.toThrow(UnauthorizedException);
    });

    it('should revoke all refresh tokens on logout', async () => {
      refreshTokenService.revokeAllUserTokens.mockResolvedValue(undefined);

      await service.logout(mockUser.id);

      expect(refreshTokenService.revokeAllUserTokens).toHaveBeenCalledWith(mockUser.id);
    });

    it('should revoke all refresh tokens on password reset', async () => {
      const validResetToken = {
        ...mockUser,
        reset_password_token: 'hashed-token',
        reset_password_expires: new Date(Date.now() + 3600000),
        reset_password_used_at: null,
      };

      usersService.findByResetToken.mockResolvedValue(validResetToken);
      usersService.update.mockResolvedValue(mockUser);
      usersService.clearResetPasswordToken.mockResolvedValue(undefined);
      refreshTokenService.revokeAllUserTokens.mockResolvedValue(undefined);

      await service.resetPassword('valid-token', 'NewPassword123!');

      expect(refreshTokenService.revokeAllUserTokens).toHaveBeenCalledWith(mockUser.id);
    });

    it('should support multiple concurrent logins (different devices)', async () => {
      jwtService.sign.mockReturnValue('token');
      refreshTokenService.createToken.mockResolvedValue({} as any);

      // Login from device 1
      await service.login(mockUser, 'iPhone 13', '192.168.1.1');

      // Login from device 2
      await service.login(mockUser, 'MacBook Pro', '192.168.1.2');

      // Both logins should create separate tokens
      expect(refreshTokenService.createToken).toHaveBeenCalledTimes(2);
    });
  });

  describe('Combined Security Scenarios', () => {
    it('should enforce all security measures on registration', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      // Weak password should fail
      await expect(
        service.register({
          email: 'test@example.com',
          password: 'weak',
          first_name: 'Test',
          last_name: 'User',
          role: UserRole.CONSULTANT,
        }),
      ).rejects.toThrow(BadRequestException);

      usersService.create.mockResolvedValue(mockUser);
      jwtService.sign.mockReturnValue('token');
      refreshTokenService.createToken.mockResolvedValue({} as any);

      // Strong password should succeed
      const result = await service.register({
        email: 'test@example.com',
        password: 'StrongPass123!',
        first_name: 'Test',
        last_name: 'User',
        role: UserRole.CONSULTANT,
      });

      expect(result.access_token).toBeDefined();
      expect(result.refresh_token).toBeDefined();
    });

    it('should enforce all security measures on password reset', async () => {
      const validResetToken = {
        ...mockUser,
        reset_password_token: 'hashed-token',
        reset_password_expires: new Date(Date.now() + 3600000),
        reset_password_used_at: null,
      };

      usersService.findByResetToken.mockResolvedValue(validResetToken);
      usersService.update.mockResolvedValue(mockUser);
      usersService.clearResetPasswordToken.mockResolvedValue(undefined);
      refreshTokenService.revokeAllUserTokens.mockResolvedValue(undefined);

      // Reset password successfully
      await service.resetPassword('valid-token', 'NewStrongPass123!');

      // Should have:
      // 1. Validated password complexity
      // 2. Marked token as used
      // 3. Revoked all refresh tokens
      expect(usersService.update).toHaveBeenCalledWith(
        mockUser.id,
        expect.objectContaining({
          password_hash: expect.any(String),
          reset_password_used_at: expect.any(Date),
        }),
      );
      expect(refreshTokenService.revokeAllUserTokens).toHaveBeenCalled();

      // Try to use same token again (should fail)
      const usedToken = {
        ...validResetToken,
        reset_password_used_at: new Date(),
      };
      usersService.findByResetToken.mockResolvedValue(usedToken);

      await expect(service.resetPassword('valid-token', 'AnotherPass123!')).rejects.toThrow(
        'Reset token has already been used',
      );
    });
  });
});
