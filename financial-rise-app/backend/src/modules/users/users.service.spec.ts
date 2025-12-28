import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { User, UserRole, UserStatus } from './entities/user.entity';

describe('UsersService', () => {
  let service: UsersService;
  let repository: Repository<User>;

  const mockRepository = {
    findOne: jest.fn(),
    create: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
  };

  const mockUser: Partial<User> = {
    id: 'user-123',
    email: 'test@example.com',
    first_name: 'John',
    last_name: 'Doe',
    role: UserRole.CONSULTANT,
    status: UserStatus.ACTIVE,
    failed_login_attempts: 0,
    created_at: new Date(),
    updated_at: new Date(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
    repository = module.get<Repository<User>>(getRepositoryToken(User));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      mockRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.findByEmail('test@example.com');

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { email: 'test@example.com' },
      });
      expect(result).toEqual(mockUser);
    });

    it('should return null if user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.findByEmail('nonexistent@example.com');

      expect(result).toBeNull();
    });

    it('should handle database errors', async () => {
      mockRepository.findOne.mockRejectedValue(new Error('Database error'));

      await expect(service.findByEmail('test@example.com')).rejects.toThrow('Database error');
    });
  });

  describe('findById', () => {
    it('should find user by ID', async () => {
      mockRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.findById('user-123');

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { id: 'user-123' },
      });
      expect(result).toEqual(mockUser);
    });

    it('should return null if user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.findById('nonexistent-id');

      expect(result).toBeNull();
    });
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const userData = {
        email: 'new@example.com',
        first_name: 'Jane',
        last_name: 'Smith',
        role: UserRole.CONSULTANT,
      };

      mockRepository.create.mockReturnValue(userData);
      mockRepository.save.mockResolvedValue({ ...userData, id: 'new-user-123' });

      const result = await service.create(userData);

      expect(repository.create).toHaveBeenCalledWith(userData);
      expect(repository.save).toHaveBeenCalled();
      expect(result.id).toBe('new-user-123');
    });

    it('should handle creation errors', async () => {
      mockRepository.create.mockReturnValue({});
      mockRepository.save.mockRejectedValue(new Error('Duplicate email'));

      await expect(service.create(mockUser)).rejects.toThrow('Duplicate email');
    });
  });

  describe('update', () => {
    it('should update an existing user', async () => {
      const updateData = { first_name: 'Updated' };
      const updatedUser = { ...mockUser, ...updateData };

      mockRepository.findOne.mockResolvedValue(mockUser);
      mockRepository.save.mockResolvedValue(updatedUser);

      const result = await service.update('user-123', updateData);

      expect(repository.findOne).toHaveBeenCalledWith({ where: { id: 'user-123' } });
      expect(repository.save).toHaveBeenCalledWith(expect.objectContaining(updateData));
      expect(result.first_name).toBe('Updated');
    });

    it('should throw NotFoundException if user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      await expect(service.update('nonexistent-id', {})).rejects.toThrow(NotFoundException);
      await expect(service.update('nonexistent-id', {})).rejects.toThrow('User not found');
    });

    it('should merge update data with existing user', async () => {
      const updateData = { last_name: 'NewLastName' };
      mockRepository.findOne.mockResolvedValue(mockUser);
      mockRepository.save.mockImplementation((user) => Promise.resolve(user));

      await service.update('user-123', updateData);

      const savedUser = mockRepository.save.mock.calls[0][0];
      expect(savedUser.first_name).toBe(mockUser.first_name); // Original preserved
      expect(savedUser.last_name).toBe('NewLastName'); // Updated
    });
  });

  describe('incrementFailedLoginAttempts', () => {
    it('should increment failed login attempts', async () => {
      const user = { ...mockUser, failed_login_attempts: 2 };
      mockRepository.findOne.mockResolvedValue(user);
      mockRepository.save.mockResolvedValue({ ...user, failed_login_attempts: 3 });

      await service.incrementFailedLoginAttempts('user-123');

      expect(repository.save).toHaveBeenCalledWith(
        expect.objectContaining({ failed_login_attempts: 3 }),
      );
    });

    it('should lock account after 5 failed attempts', async () => {
      const user = { ...mockUser, failed_login_attempts: 4 };
      mockRepository.findOne.mockResolvedValue(user);
      mockRepository.save.mockImplementation((u) => Promise.resolve(u));

      await service.incrementFailedLoginAttempts('user-123');

      const savedUser = mockRepository.save.mock.calls[0][0];
      expect(savedUser.failed_login_attempts).toBe(5);
      expect(savedUser.status).toBe(UserStatus.LOCKED);
      expect(savedUser.locked_until).toBeDefined();
    });

    it('should set locked_until to 30 minutes from now', async () => {
      const user = { ...mockUser, failed_login_attempts: 4 };
      mockRepository.findOne.mockResolvedValue(user);
      mockRepository.save.mockImplementation((u) => Promise.resolve(u));

      const beforeLock = Date.now();
      await service.incrementFailedLoginAttempts('user-123');
      const afterLock = Date.now();

      const savedUser = mockRepository.save.mock.calls[0][0];
      const lockTime = savedUser.locked_until.getTime();
      const expectedMin = beforeLock + 30 * 60 * 1000;
      const expectedMax = afterLock + 30 * 60 * 1000;

      expect(lockTime).toBeGreaterThanOrEqual(expectedMin);
      expect(lockTime).toBeLessThanOrEqual(expectedMax);
    });

    it('should return early if user not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      await service.incrementFailedLoginAttempts('nonexistent-id');

      expect(repository.save).not.toHaveBeenCalled();
    });
  });

  describe('resetFailedLoginAttempts', () => {
    it('should reset failed login attempts to 0', async () => {
      await service.resetFailedLoginAttempts('user-123');

      expect(repository.update).toHaveBeenCalledWith('user-123', {
        failed_login_attempts: 0,
        status: UserStatus.ACTIVE,
        locked_until: null,
      });
    });

    it('should set status to ACTIVE', async () => {
      await service.resetFailedLoginAttempts('user-123');

      const updateData = mockRepository.update.mock.calls[0][1];
      expect(updateData.status).toBe(UserStatus.ACTIVE);
    });

    it('should clear locked_until timestamp', async () => {
      await service.resetFailedLoginAttempts('user-123');

      const updateData = mockRepository.update.mock.calls[0][1];
      expect(updateData.locked_until).toBeNull();
    });
  });

  describe('isAccountLocked', () => {
    it('should return false if status is not LOCKED', async () => {
      const user = { ...mockUser, status: UserStatus.ACTIVE };

      const result = await service.isAccountLocked(user as User);

      expect(result).toBe(false);
    });

    it('should return true if account is locked and lock has not expired', async () => {
      const user = {
        ...mockUser,
        status: UserStatus.LOCKED,
        locked_until: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes from now
      };

      const result = await service.isAccountLocked(user as User);

      expect(result).toBe(true);
    });

    it('should return false and reset if lock has expired', async () => {
      const user = {
        ...mockUser,
        id: 'user-123',
        status: UserStatus.LOCKED,
        locked_until: new Date(Date.now() - 1000), // 1 second ago
      };

      mockRepository.update.mockResolvedValue({ affected: 1 });

      const result = await service.isAccountLocked(user as User);

      expect(result).toBe(false);
      expect(repository.update).toHaveBeenCalledWith('user-123', {
        failed_login_attempts: 0,
        status: UserStatus.ACTIVE,
        locked_until: null,
      });
    });

    it('should return true if locked_until is in the future', async () => {
      const futureTime = new Date(Date.now() + 1000 * 60 * 30); // 30 minutes from now
      const user = {
        ...mockUser,
        status: UserStatus.LOCKED,
        locked_until: futureTime,
      };

      const result = await service.isAccountLocked(user as User);

      expect(result).toBe(true);
    });
  });

  describe('updateLastLogin', () => {
    it('should update last_login_at timestamp', async () => {
      const beforeUpdate = Date.now();

      await service.updateLastLogin('user-123');

      const afterUpdate = Date.now();
      const updateCall = mockRepository.update.mock.calls[0];

      expect(updateCall[0]).toBe('user-123');
      expect(updateCall[1].last_login_at).toBeInstanceOf(Date);

      const lastLoginTime = updateCall[1].last_login_at.getTime();
      expect(lastLoginTime).toBeGreaterThanOrEqual(beforeUpdate);
      expect(lastLoginTime).toBeLessThanOrEqual(afterUpdate);
    });
  });

  describe('setResetPasswordToken', () => {
    it('should set reset token with default expiry (1 hour)', async () => {
      const token = 'reset-token-123';
      const beforeSet = Date.now();

      await service.setResetPasswordToken('user-123', token);

      const afterSet = Date.now();
      const updateCall = mockRepository.update.mock.calls[0];

      expect(updateCall[0]).toBe('user-123');
      expect(updateCall[1].reset_password_token).toBe(token);

      const expiryTime = updateCall[1].reset_password_expires.getTime();
      const expectedMin = beforeSet + 3600000; // 1 hour
      const expectedMax = afterSet + 3600000;

      expect(expiryTime).toBeGreaterThanOrEqual(expectedMin);
      expect(expiryTime).toBeLessThanOrEqual(expectedMax);
    });

    it('should accept custom expiry time', async () => {
      const token = 'reset-token-456';
      const customExpiry = 1800000; // 30 minutes
      const beforeSet = Date.now();

      await service.setResetPasswordToken('user-123', token, customExpiry);

      const afterSet = Date.now();
      const updateCall = mockRepository.update.mock.calls[0];

      const expiryTime = updateCall[1].reset_password_expires.getTime();
      const expectedMin = beforeSet + customExpiry;
      const expectedMax = afterSet + customExpiry;

      expect(expiryTime).toBeGreaterThanOrEqual(expectedMin);
      expect(expiryTime).toBeLessThanOrEqual(expectedMax);
    });
  });

  describe('findByResetToken', () => {
    it('should find user by reset password token', async () => {
      const token = 'reset-token-abc';
      mockRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.findByResetToken(token);

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { reset_password_token: token },
      });
      expect(result).toEqual(mockUser);
    });

    it('should return null if token not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.findByResetToken('invalid-token');

      expect(result).toBeNull();
    });
  });

  describe('clearResetPasswordToken', () => {
    it('should clear reset password token and expiry', async () => {
      await service.clearResetPasswordToken('user-123');

      expect(repository.update).toHaveBeenCalledWith('user-123', {
        reset_password_token: null,
        reset_password_expires: null,
      });
    });
  });

  describe('updateRefreshToken', () => {
    it('should update refresh token', async () => {
      const refreshToken = 'new-refresh-token';

      await service.updateRefreshToken('user-123', refreshToken);

      expect(repository.update).toHaveBeenCalledWith('user-123', {
        refresh_token: refreshToken,
      });
    });

    it('should allow setting refresh token to null', async () => {
      await service.updateRefreshToken('user-123', null);

      expect(repository.update).toHaveBeenCalledWith('user-123', {
        refresh_token: null,
      });
    });
  });

  describe('findByRefreshToken', () => {
    it('should find user by refresh token', async () => {
      const refreshToken = 'refresh-token-xyz';
      mockRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.findByRefreshToken(refreshToken);

      expect(repository.findOne).toHaveBeenCalledWith({
        where: { refresh_token: refreshToken },
      });
      expect(result).toEqual(mockUser);
    });

    it('should return null if refresh token not found', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.findByRefreshToken('invalid-token');

      expect(result).toBeNull();
    });
  });
});
