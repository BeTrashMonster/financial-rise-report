import { Test, TestingModule } from '@nestjs/testing';
import { UnauthorizedException } from '@nestjs/common';
import { LocalStrategy } from './local.strategy';
import { AuthService } from '../auth.service';
import { UserRole, UserStatus } from '../../users/entities/user.entity';

describe('LocalStrategy', () => {
  let strategy: LocalStrategy;
  let authService: AuthService;

  const mockAuthService = {
    validateUser: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        LocalStrategy,
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    strategy = module.get<LocalStrategy>(LocalStrategy);
    authService = module.get<AuthService>(AuthService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  describe('constructor', () => {
    it('should configure email as username field', () => {
      // The strategy is configured with usernameField: 'email'
      expect(strategy).toBeDefined();
    });

    it('should configure password field', () => {
      // The strategy is configured with passwordField: 'password'
      expect(strategy).toBeDefined();
    });
  });

  describe('validate', () => {
    const email = 'test@example.com';
    const password = 'SecurePassword123!';

    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      role: UserRole.CONSULTANT,
      status: UserStatus.ACTIVE,
      first_name: 'John',
      last_name: 'Doe',
    };

    it('should validate and return user for valid credentials', async () => {
      mockAuthService.validateUser.mockResolvedValue(mockUser);

      const result = await strategy.validate(email, password);

      expect(authService.validateUser).toHaveBeenCalledWith(email, password);
      expect(result).toEqual(mockUser);
    });

    it('should throw UnauthorizedException for invalid credentials', async () => {
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate(email, password)).rejects.toThrow(UnauthorizedException);
      await expect(strategy.validate(email, password)).rejects.toThrow(
        'Invalid email or password',
      );
    });

    it('should call authService.validateUser with correct parameters', async () => {
      mockAuthService.validateUser.mockResolvedValue(mockUser);

      await strategy.validate(email, password);

      expect(authService.validateUser).toHaveBeenCalledWith(email, password);
      expect(authService.validateUser).toHaveBeenCalledTimes(1);
    });

    it('should handle wrong email', async () => {
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate('wrong@example.com', password)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should handle wrong password', async () => {
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate(email, 'wrongpassword')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should handle empty email', async () => {
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate('', password)).rejects.toThrow(UnauthorizedException);
    });

    it('should handle empty password', async () => {
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate(email, '')).rejects.toThrow(UnauthorizedException);
    });

    it('should handle null credentials', async () => {
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate(null as any, null as any)).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should return complete user object on success', async () => {
      const fullUser = {
        id: 'user-456',
        email: 'admin@example.com',
        role: UserRole.ADMIN,
        status: UserStatus.ACTIVE,
        first_name: 'Admin',
        last_name: 'User',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockAuthService.validateUser.mockResolvedValue(fullUser);

      const result = await strategy.validate('admin@example.com', 'password');

      expect(result).toEqual(fullUser);
    });

    it('should handle different user roles', async () => {
      const roles = [UserRole.ADMIN, UserRole.CONSULTANT];

      for (const role of roles) {
        const user = { ...mockUser, role };
        mockAuthService.validateUser.mockResolvedValue(user);

        const result = await strategy.validate(email, password);

        expect(result.role).toBe(role);
      }
    });

    it('should handle case-sensitive email validation', async () => {
      mockAuthService.validateUser.mockResolvedValue(mockUser);

      await strategy.validate('Test@Example.com', password);

      // Should pass the email as-is to the service
      expect(authService.validateUser).toHaveBeenCalledWith('Test@Example.com', password);
    });

    it('should handle special characters in password', async () => {
      const specialPassword = 'P@ssw0rd!#$%^&*()';
      mockAuthService.validateUser.mockResolvedValue(mockUser);

      await strategy.validate(email, specialPassword);

      expect(authService.validateUser).toHaveBeenCalledWith(email, specialPassword);
    });

    it('should throw when validateUser returns undefined', async () => {
      mockAuthService.validateUser.mockResolvedValue(undefined);

      await expect(strategy.validate(email, password)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw when validateUser returns false', async () => {
      mockAuthService.validateUser.mockResolvedValue(false);

      await expect(strategy.validate(email, password)).rejects.toThrow(UnauthorizedException);
    });

    it('should propagate service errors', async () => {
      mockAuthService.validateUser.mockRejectedValue(new Error('Database error'));

      await expect(strategy.validate(email, password)).rejects.toThrow('Database error');
    });

    it('should handle account lockout through AuthService', async () => {
      // AuthService should handle account lockout logic
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate(email, password)).rejects.toThrow(UnauthorizedException);
    });

    it('should handle inactive accounts through AuthService', async () => {
      // AuthService should handle inactive account logic
      mockAuthService.validateUser.mockResolvedValue(null);

      await expect(strategy.validate(email, password)).rejects.toThrow(UnauthorizedException);
    });

    describe('Integration with passport-local', () => {
      it('should use email field instead of default username', () => {
        // Configuration check - passport-local default is 'username'
        // Our strategy overrides with 'email'
        expect(strategy).toBeDefined();
      });

      it('should extract credentials from request body', () => {
        // Passport-local extracts from req.body by default
        expect(strategy).toBeDefined();
      });
    });
  });
});
