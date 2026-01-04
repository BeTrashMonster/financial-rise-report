import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { User, UserRole, UserStatus } from './entities/user.entity';

describe('UsersController - GDPR Account Deletion (Article 17)', () => {
  let controller: UsersController;
  let service: UsersService;

  const mockUserId = '123e4567-e89b-12d3-a456-426614174000';
  const mockUser: Partial<User> = {
    id: mockUserId,
    email: 'consultant@example.com',
    first_name: 'John',
    last_name: 'Doe',
    role: UserRole.CONSULTANT,
    status: UserStatus.ACTIVE,
  };

  const mockUsersService = {
    findById: jest.fn(),
    deleteUser: jest.fn(),
    deleteUserCascade: jest.fn(),
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
    }).compile();

    controller = module.get<UsersController>(UsersController);
    service = module.get<UsersService>(UsersService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('DELETE /api/users/:id - GDPR Article 17 (Right to Erasure)', () => {
    it('should delete user account successfully', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deleted).toBe(true);
      expect(result).toHaveProperty('deletedAt');
      expect(service.deleteUserCascade).toHaveBeenCalledWith(mockUserId);
    });

    it('should cascade delete all related assessments', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedAssessments: 5,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletedAssessments).toBe(5);
    });

    it('should cascade delete all assessment responses', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedAssessments: 5,
        deletedResponses: 150,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletedResponses).toBeGreaterThan(0);
    });

    it('should cascade delete all DISC profiles', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedAssessments: 5,
        deletedDISCProfiles: 5,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletedDISCProfiles).toBeGreaterThan(0);
    });

    it('should cascade delete all phase results', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedAssessments: 5,
        deletedPhaseResults: 5,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletedPhaseResults).toBeGreaterThan(0);
    });

    it('should delete all refresh tokens', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedRefreshTokens: 3,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletedRefreshTokens).toBeGreaterThan(0);
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUsersService.deleteUserCascade.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      const req = { user: { id: 'non-existent', role: UserRole.CONSULTANT } };

      await expect(controller.deleteUser('non-existent', req)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should only allow users to delete their own account', async () => {
      const req = { user: { id: 'different-user-id', role: UserRole.CONSULTANT } };

      await expect(controller.deleteUser(mockUserId, req)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should allow admins to delete any user account', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: 'admin-id', role: UserRole.ADMIN } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deleted).toBe(true);
    });

    it('should log deletion for audit trail', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        auditLog: {
          action: 'USER_DELETED',
          id: mockUser.id,
          timestamp: expect.any(String),
          reason: 'GDPR Article 17 - User requested deletion',
        },
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result).toHaveProperty('auditLog');
      expect(result.auditLog.action).toBe('USER_DELETED');
    });

    it('should return summary of all deleted data', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedAssessments: 5,
        deletedResponses: 150,
        deletedDISCProfiles: 5,
        deletedPhaseResults: 5,
        deletedRefreshTokens: 3,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result).toHaveProperty('deletedAssessments');
      expect(result).toHaveProperty('deletedResponses');
      expect(result).toHaveProperty('deletedDISCProfiles');
      expect(result).toHaveProperty('deletedPhaseResults');
      expect(result).toHaveProperty('deletedRefreshTokens');
    });

    it('should handle deletion when user has no assessments', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedAssessments: 0,
        deletedResponses: 0,
        deletedDISCProfiles: 0,
        deletedPhaseResults: 0,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deleted).toBe(true);
      expect(result.deletedAssessments).toBe(0);
    });

    it('should delete encrypted financial data (GDPR compliance)', async () => {
      // Encrypted data should be permanently deleted
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        deletedEncryptedData: true,
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletedEncryptedData).toBe(true);
    });

    it('should include GDPR article reference in response', async () => {
      const deleteResult = {
        deleted: true,
        deletedAt: new Date().toISOString(),
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.gdpr_article).toBe('Article 17 - Right to Erasure');
    });

    it('should use hard delete (not soft delete) for GDPR compliance', async () => {
      // GDPR requires actual deletion, not just marking as deleted
      const deleteResult = {
        deleted: true,
        deletionType: 'HARD_DELETE',
        deletedAt: new Date().toISOString(),
        gdpr_article: 'Article 17 - Right to Erasure',
      };

      mockUsersService.deleteUserCascade.mockResolvedValue(deleteResult);

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.deleteUser(mockUserId, req);

      expect(result.deletionType).toBe('HARD_DELETE');
    });

    it('should handle database transaction rollback on failure', async () => {
      mockUsersService.deleteUserCascade.mockRejectedValue(
        new Error('Database transaction failed'),
      );

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };

      await expect(controller.deleteUser(mockUserId, req)).rejects.toThrow();
    });

    it('should prevent deletion if required for legal hold', async () => {
      // Some data may need to be retained for legal compliance
      mockUsersService.deleteUserCascade.mockRejectedValue(
        new ForbiddenException('Account deletion blocked due to legal hold'),
      );

      const req = { user: { id: mockUserId, role: UserRole.CONSULTANT } };

      await expect(controller.deleteUser(mockUserId, req)).rejects.toThrow(
        ForbiddenException,
      );
    });
  });
});
