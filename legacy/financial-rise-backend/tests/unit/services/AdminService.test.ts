import { AdminService } from '../../../src/services/AdminService';
import { User, UserRole } from '../../../src/database/entities/User';
import { Repository } from 'typeorm';

// Mock repositories
const mockUserRepository = {
  findOne: jest.fn(),
  find: jest.fn(),
  count: jest.fn(),
  create: jest.fn(),
  save: jest.fn(),
  remove: jest.fn(),
  update: jest.fn()
} as unknown as Repository<User>;

const mockAuditLogRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
  count: jest.fn(),
  createQueryBuilder: jest.fn()
} as unknown as Repository<any>;

const mockRefreshTokenRepository = {
  update: jest.fn()
} as unknown as Repository<any>;

describe('AdminService', () => {
  let adminService: AdminService;
  const adminId = 'admin-uuid-123';

  beforeEach(() => {
    jest.clearAllMocks();
    adminService = new AdminService(
      mockUserRepository,
      mockAuditLogRepository,
      mockRefreshTokenRepository
    );
  });

  describe('listUsers', () => {
    it('should return paginated list of users', async () => {
      const mockUsers = [
        {
          id: 'user-1',
          email: 'user1@example.com',
          role: UserRole.CONSULTANT,
          isActive: true
        },
        {
          id: 'user-2',
          email: 'user2@example.com',
          role: UserRole.ADMIN,
          isActive: true
        }
      ];

      (mockUserRepository.count as jest.Mock).mockResolvedValue(2);
      (mockUserRepository.find as jest.Mock).mockResolvedValue(mockUsers);
      (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
      (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});

      const result = await adminService.listUsers({ page: 1, limit: 20 }, adminId);

      expect(result.data).toEqual(mockUsers);
      expect(result.pagination).toEqual({
        total: 2,
        page: 1,
        limit: 20,
        totalPages: 1
      });
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should filter users by role', async () => {
      (mockUserRepository.count as jest.Mock).mockResolvedValue(1);
      (mockUserRepository.find as jest.Mock).mockResolvedValue([]);
      (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
      (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});

      await adminService.listUsers({ role: UserRole.CONSULTANT }, adminId);

      expect(mockUserRepository.find).toHaveBeenCalledWith(
        expect.objectContaining({
          where: expect.objectContaining({ role: UserRole.CONSULTANT })
        })
      );
    });
  });

  describe('createUser', () => {
    it('should create a new user successfully', async () => {
      const newUser = {
        email: 'newuser@example.com',
        password: 'SecurePass123!',
        role: UserRole.CONSULTANT
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);
      (mockUserRepository.create as jest.Mock).mockReturnValue({
        id: 'new-user-id',
        email: newUser.email,
        role: newUser.role,
        passwordHash: 'hashed'
      });
      (mockUserRepository.save as jest.Mock).mockResolvedValue({
        id: 'new-user-id',
        email: newUser.email,
        role: newUser.role
      });
      (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
      (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});

      const result = await adminService.createUser(newUser, adminId);

      expect(result.email).toBe(newUser.email);
      expect(result).not.toHaveProperty('passwordHash');
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error if email already exists', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue({
        email: 'existing@example.com'
      });

      await expect(
        adminService.createUser({
          email: 'existing@example.com',
          password: 'Pass123!',
          role: UserRole.CONSULTANT
        }, adminId)
      ).rejects.toThrow('Email already registered');
    });

    it('should throw error for weak password', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(
        adminService.createUser({
          email: 'newuser@example.com',
          password: 'weak',
          role: UserRole.CONSULTANT
        }, adminId)
      ).rejects.toThrow('Password must');
    });
  });

  describe('updateUser', () => {
    it('should update user successfully', async () => {
      const existingUser = {
        id: 'user-123',
        email: 'old@example.com',
        role: UserRole.CONSULTANT,
        isActive: true
      };

      // First call - find the user by ID
      // Second call - check for email uniqueness (should return null = email available)
      (mockUserRepository.findOne as jest.Mock)
        .mockResolvedValueOnce(existingUser)
        .mockResolvedValueOnce(null);
      (mockUserRepository.save as jest.Mock).mockResolvedValue({
        ...existingUser,
        email: 'new@example.com'
      });
      (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
      (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});

      const result = await adminService.updateUser(
        'user-123',
        { email: 'new@example.com' },
        adminId
      );

      expect(result.email).toBe('new@example.com');
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error when user not found', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(null);

      await expect(
        adminService.updateUser('nonexistent', { email: 'new@example.com' }, adminId)
      ).rejects.toThrow('User not found');
    });

    it('should prevent admin from changing own role', async () => {
      const adminUser = {
        id: adminId,
        email: 'admin@example.com',
        role: UserRole.ADMIN
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(adminUser);

      await expect(
        adminService.updateUser(adminId, { role: UserRole.CONSULTANT }, adminId)
      ).rejects.toThrow('Cannot change your own role');
    });

    it('should prevent deactivating last admin', async () => {
      const adminUser = {
        id: 'admin-123',
        email: 'admin@example.com',
        role: UserRole.ADMIN,
        isActive: true
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(adminUser);
      (mockUserRepository.count as jest.Mock).mockResolvedValue(1);

      await expect(
        adminService.updateUser('admin-123', { isActive: false }, adminId)
      ).rejects.toThrow('Cannot deactivate the last admin user');
    });
  });

  describe('deleteUser', () => {
    it('should delete user successfully', async () => {
      const userToDelete = {
        id: 'user-123',
        email: 'delete@example.com',
        role: UserRole.CONSULTANT
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(userToDelete);
      (mockUserRepository.remove as jest.Mock).mockResolvedValue({});
      (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
      (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});

      await adminService.deleteUser('user-123', adminId);

      expect(mockUserRepository.remove).toHaveBeenCalledWith(userToDelete);
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error when deleting own account', async () => {
      const adminUser = {
        id: adminId,
        email: 'admin@example.com',
        role: UserRole.ADMIN
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(adminUser);

      await expect(
        adminService.deleteUser(adminId, adminId)
      ).rejects.toThrow('Cannot delete your own account');
    });

    it('should throw error when deleting last admin', async () => {
      const adminUser = {
        id: 'admin-123',
        email: 'admin@example.com',
        role: UserRole.ADMIN
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(adminUser);
      (mockUserRepository.count as jest.Mock).mockResolvedValue(1);

      await expect(
        adminService.deleteUser('admin-123', adminId)
      ).rejects.toThrow('Cannot delete the last admin user');
    });
  });

  describe('resetUserPassword', () => {
    it('should reset user password successfully', async () => {
      const user = {
        id: 'user-123',
        email: 'user@example.com',
        passwordHash: 'old-hash'
      };

      (mockUserRepository.findOne as jest.Mock).mockResolvedValue(user);
      (mockUserRepository.save as jest.Mock).mockResolvedValue(user);
      (mockRefreshTokenRepository.update as jest.Mock).mockResolvedValue({});
      (mockAuditLogRepository.create as jest.Mock).mockReturnValue({});
      (mockAuditLogRepository.save as jest.Mock).mockResolvedValue({});

      await adminService.resetUserPassword('user-123', 'NewSecurePass456!', adminId);

      expect(mockUserRepository.save).toHaveBeenCalled();
      expect(mockRefreshTokenRepository.update).toHaveBeenCalled();
      expect(mockAuditLogRepository.save).toHaveBeenCalled();
    });

    it('should throw error for weak new password', async () => {
      (mockUserRepository.findOne as jest.Mock).mockResolvedValue({
        id: 'user-123',
        email: 'user@example.com'
      });

      await expect(
        adminService.resetUserPassword('user-123', 'weak', adminId)
      ).rejects.toThrow('Password must');
    });
  });
});
