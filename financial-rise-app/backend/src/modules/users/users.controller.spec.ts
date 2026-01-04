import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { UserRole, UserStatus } from './entities/user.entity';

describe('UsersController', () => {
  let controller: UsersController;
  let usersService: UsersService;

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

  const mockUsersService = {
    findById: jest.fn(),
    findByEmail: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [UsersController],
      providers: [
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    })
      .overrideGuard(JwtAuthGuard)
      .useValue({ canActivate: jest.fn(() => true) })
      .compile();

    controller = module.get<UsersController>(UsersController);
    usersService = module.get<UsersService>(UsersService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('getProfile', () => {
    it('should return user profile for authenticated user', async () => {
      const req = {
        user: { id: 'user-123' },
      };

      mockUsersService.findById.mockResolvedValue(mockUser);

      const result = await controller.getProfile(req);

      expect(result).toEqual(mockUser);
      expect(usersService.findById).toHaveBeenCalledWith('user-123');
      expect(usersService.findById).toHaveBeenCalledTimes(1);
    });

    it('should return null if user not found', async () => {
      const req = {
        user: { id: 'nonexistent-user' },
      };

      mockUsersService.findById.mockResolvedValue(null);

      const result = await controller.getProfile(req);

      expect(result).toBeNull();
      expect(usersService.findById).toHaveBeenCalledWith('nonexistent-user');
    });

    it('should use JwtAuthGuard', () => {
      const guards = Reflect.getMetadata('__guards__', controller.getProfile);
      const guardNames = guards.map((guard: any) => guard.name);
      expect(guardNames).toContain('JwtAuthGuard');
    });

    it('should handle service errors', async () => {
      const req = {
        user: { id: 'user-123' },
      };

      mockUsersService.findById.mockRejectedValue(new Error('Database error'));

      await expect(controller.getProfile(req)).rejects.toThrow('Database error');
      expect(usersService.findById).toHaveBeenCalledWith('user-123');
    });

    it('should extract userId from request.user', async () => {
      const req = {
        user: { id: 'test-user-456', email: 'other@example.com' },
      };

      mockUsersService.findById.mockResolvedValue({
        ...mockUser,
        id: 'test-user-456',
      });

      const result = await controller.getProfile(req);

      expect(usersService.findById).toHaveBeenCalledWith('test-user-456');
      expect(result).not.toBeNull();
      expect(result?.id).toBe('test-user-456');
    });
  });
});
