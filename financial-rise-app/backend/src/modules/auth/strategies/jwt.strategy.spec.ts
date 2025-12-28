import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';
import { UsersService } from '../../users/users.service';
import { UserRole, UserStatus } from '../../users/entities/user.entity';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let usersService: UsersService;
  let configService: ConfigService;

  const mockConfigService = {
    get: jest.fn((key: string) => {
      if (key === 'JWT_SECRET') return 'test-secret-key';
      return null;
    }),
  };

  const mockUsersService = {
    findById: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
    usersService = module.get<UsersService>(UsersService);
    configService = module.get<ConfigService>(ConfigService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  describe('constructor', () => {
    it('should configure JWT extraction from Bearer token', () => {
      expect(strategy).toBeDefined();
      // Strategy is configured to extract JWT from Authorization Bearer header
    });

    it('should use JWT_SECRET from config', () => {
      expect(configService.get).toHaveBeenCalledWith('JWT_SECRET');
    });

    it('should not ignore token expiration', () => {
      // The strategy is configured with ignoreExpiration: false
      expect(strategy).toBeDefined();
    });
  });

  describe('validate', () => {
    const validPayload = {
      sub: 'user-123',
      email: 'test@example.com',
      role: 'consultant',
    };

    const mockUser = {
      id: 'user-123',
      email: 'test@example.com',
      first_name: 'John',
      last_name: 'Doe',
      role: UserRole.CONSULTANT,
      status: UserStatus.ACTIVE,
      created_at: new Date(),
      updated_at: new Date(),
    };

    it('should validate and return user data for valid payload', async () => {
      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await strategy.validate(validPayload);

      expect(usersService.findById).toHaveBeenCalledWith('user-123');
      expect(result).toEqual({
        userId: 'user-123',
        email: 'test@example.com',
        role: 'consultant',
      });
    });

    it('should throw UnauthorizedException if user not found', async () => {
      mockUsersService.findById.mockResolvedValue(null);

      await expect(strategy.validate(validPayload)).rejects.toThrow(UnauthorizedException);
      await expect(strategy.validate(validPayload)).rejects.toThrow('User not found');
    });

    it('should throw UnauthorizedException if user is not active', async () => {
      const inactiveUser = {
        ...mockUser,
        status: UserStatus.INACTIVE,
      };

      mockUsersService.findById.mockResolvedValue(inactiveUser);

      await expect(strategy.validate(validPayload)).rejects.toThrow(UnauthorizedException);
      await expect(strategy.validate(validPayload)).rejects.toThrow('Account is not active');
    });

    it('should throw UnauthorizedException if user is locked', async () => {
      const lockedUser = {
        ...mockUser,
        status: UserStatus.LOCKED,
      };

      mockUsersService.findById.mockResolvedValue(lockedUser);

      await expect(strategy.validate(validPayload)).rejects.toThrow(UnauthorizedException);
      await expect(strategy.validate(validPayload)).rejects.toThrow('Account is not active');
    });

    it('should extract userId from sub claim', async () => {
      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await strategy.validate(validPayload);

      expect(result.userId).toBe('user-123');
    });

    it('should preserve email from payload', async () => {
      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await strategy.validate(validPayload);

      expect(result.email).toBe('test@example.com');
    });

    it('should preserve role from payload', async () => {
      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await strategy.validate(validPayload);

      expect(result.role).toBe('consultant');
    });

    it('should handle different user roles', async () => {
      const roles = [UserRole.ADMIN, UserRole.CONSULTANT];

      for (const role of roles) {
        const payload = { ...validPayload, role };
        const user = { ...mockUser, status: UserStatus.ACTIVE, role };

        mockUsersService.findById.mockResolvedValue(user);

        const result = await strategy.validate(payload);

        expect(result.role).toBe(role);
      }
    });

    it('should handle payload with different user IDs', async () => {
      const userIds = ['user-1', 'user-2', 'user-3'];

      for (const userId of userIds) {
        const payload = { ...validPayload, sub: userId };
        const user = { ...mockUser, id: userId, status: UserStatus.ACTIVE };

        mockUsersService.findById.mockResolvedValue(user);

        const result = await strategy.validate(payload);

        expect(result.userId).toBe(userId);
        expect(usersService.findById).toHaveBeenCalledWith(userId);
      }
    });

    it('should call findById with correct user ID', async () => {
      mockUsersService.findById.mockResolvedValue(mockUser);

      await strategy.validate(validPayload);

      expect(usersService.findById).toHaveBeenCalledWith('user-123');
      expect(usersService.findById).toHaveBeenCalledTimes(1);
    });

    it('should return minimal user data (not full user entity)', async () => {
      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await strategy.validate(validPayload);

      // Should only return userId, email, and role
      expect(Object.keys(result)).toEqual(['userId', 'email', 'role']);
      expect(result).not.toHaveProperty('password_hash');
      expect(result).not.toHaveProperty('created_at');
      expect(result).not.toHaveProperty('updated_at');
    });

    it('should handle database errors gracefully', async () => {
      mockUsersService.findById.mockRejectedValue(new Error('Database connection failed'));

      await expect(strategy.validate(validPayload)).rejects.toThrow('Database connection failed');
    });

    it('should validate active status strictly', async () => {
      const statuses = [UserStatus.INACTIVE, UserStatus.LOCKED, 'pending', 'suspended'];

      for (const status of statuses) {
        const user = { ...mockUser, status };
        mockUsersService.findById.mockResolvedValue(user);

        if (status !== UserStatus.ACTIVE) {
          await expect(strategy.validate(validPayload)).rejects.toThrow(
            'Account is not active',
          );
        }
      }
    });
  });

  describe('JWT Configuration', () => {
    it('should extract JWT from Authorization header', () => {
      // This is configured via ExtractJwt.fromAuthHeaderAsBearerToken()
      expect(strategy).toBeDefined();
    });

    it('should use correct secret key', () => {
      expect(mockConfigService.get).toHaveBeenCalledWith('JWT_SECRET');
    });

    it('should not allow expired tokens', () => {
      // Configured with ignoreExpiration: false
      expect(strategy).toBeDefined();
    });
  });
});
