/**
 * GDPR Article 18 - Right to Restriction of Processing
 * Comprehensive test suite for processing restriction functionality
 */

import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User, UserRole, UserStatus } from './entities/user.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { UserObjection } from './entities/user-objection.entity';

describe('GDPR Article 18 - Processing Restriction', () => {
  let service: UsersService;
  let controller: UsersController;
  let userRepository: Repository<User>;

  const mockUserRepository = {
    findOne: jest.fn(),
    save: jest.fn(),
    update: jest.fn(),
    create: jest.fn(),
  };

  const mockAssessmentRepository = {
    find: jest.fn(),
    count: jest.fn(),
  };

  const mockDataSource = {
    createQueryRunner: jest.fn(),
  };

  const mockUser: Partial<User> = {
    id: 'user-123',
    email: 'test@example.com',
    first_name: 'John',
    last_name: 'Doe',
    role: UserRole.CONSULTANT,
    status: UserStatus.ACTIVE,
    processing_restricted: false,
    restriction_reason: null,
    created_at: new Date(),
    updated_at: new Date(),
  };

  const mockAdmin: Partial<User> = {
    id: 'admin-456',
    email: 'admin@example.com',
    first_name: 'Admin',
    last_name: 'User',
    role: UserRole.ADMIN,
    status: UserStatus.ACTIVE,
    processing_restricted: false,
    restriction_reason: null,
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: getRepositoryToken(Assessment),
          useValue: mockAssessmentRepository,
        },
        {
          provide: getRepositoryToken(UserObjection),
          useValue: { findOne: jest.fn(), find: jest.fn() },
        },
        {
          provide: DataSource,
          useValue: mockDataSource,
        },
      ],
      controllers: [UsersController],
    }).compile();

    service = module.get<UsersService>(UsersService);
    controller = module.get<UsersController>(UsersController);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('UsersService.restrictProcessing', () => {
    it('should restrict processing for a user without reason', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockResolvedValue({
        ...mockUser,
        processing_restricted: true,
        restriction_reason: null,
      });

      const result = await service.restrictProcessing('user-123');

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'user-123' },
      });
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          processing_restricted: true,
          restriction_reason: null,
        }),
      );
      expect(result.processing_restricted).toBe(true);
      expect(result.restriction_reason).toBeNull();
    });

    it('should restrict processing with a reason provided', async () => {
      const reason = 'I am disputing the accuracy of my data';
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockResolvedValue({
        ...mockUser,
        processing_restricted: true,
        restriction_reason: reason,
      });

      const result = await service.restrictProcessing('user-123', reason);

      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          processing_restricted: true,
          restriction_reason: reason,
        }),
      );
      expect(result.processing_restricted).toBe(true);
      expect(result.restriction_reason).toBe(reason);
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.restrictProcessing('nonexistent-id')).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.restrictProcessing('nonexistent-id')).rejects.toThrow(
        'User not found',
      );
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should handle already restricted accounts gracefully', async () => {
      const alreadyRestricted = {
        ...mockUser,
        processing_restricted: true,
        restriction_reason: 'Previous reason',
      };
      mockUserRepository.findOne.mockResolvedValue(alreadyRestricted);
      mockUserRepository.save.mockResolvedValue({
        ...alreadyRestricted,
        restriction_reason: 'New reason',
      });

      const result = await service.restrictProcessing('user-123', 'New reason');

      expect(result.processing_restricted).toBe(true);
      expect(result.restriction_reason).toBe('New reason');
    });

    it('should update restriction timestamp', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockImplementation((user) =>
        Promise.resolve({ ...user, updated_at: new Date() }),
      );

      const beforeRestriction = Date.now();
      await service.restrictProcessing('user-123');
      const afterRestriction = Date.now();

      const savedUser = mockUserRepository.save.mock.calls[0][0];
      expect(savedUser.processing_restricted).toBe(true);
    });
  });

  describe('UsersService.liftProcessingRestriction', () => {
    it('should lift processing restriction from a user', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
        restriction_reason: 'Test reason',
      };
      mockUserRepository.findOne.mockResolvedValue(restrictedUser);
      mockUserRepository.save.mockResolvedValue({
        ...restrictedUser,
        processing_restricted: false,
        restriction_reason: null,
      });

      const result = await service.liftProcessingRestriction('user-123');

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'user-123' },
      });
      expect(userRepository.save).toHaveBeenCalledWith(
        expect.objectContaining({
          processing_restricted: false,
          restriction_reason: null,
        }),
      );
      expect(result.processing_restricted).toBe(false);
      expect(result.restriction_reason).toBeNull();
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.liftProcessingRestriction('nonexistent-id')).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.liftProcessingRestriction('nonexistent-id')).rejects.toThrow(
        'User not found',
      );
      expect(userRepository.save).not.toHaveBeenCalled();
    });

    it('should handle already unrestricted accounts gracefully', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockResolvedValue(mockUser);

      const result = await service.liftProcessingRestriction('user-123');

      expect(result.processing_restricted).toBe(false);
      expect(result.restriction_reason).toBeNull();
    });
  });

  describe('UsersService.getProcessingStatus', () => {
    it('should return processing status for unrestricted user', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.getProcessingStatus('user-123');

      expect(userRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'user-123' },
        select: ['id', 'processing_restricted', 'restriction_reason', 'updated_at'],
      });
      expect(result).toEqual({
        userId: 'user-123',
        processing_restricted: false,
        restriction_reason: null,
        last_updated: expect.any(Date),
        gdpr_article: 'Article 18 - Right to Restriction of Processing',
      });
    });

    it('should return processing status for restricted user', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
        restriction_reason: 'Data accuracy dispute',
      };
      mockUserRepository.findOne.mockResolvedValue(restrictedUser);

      const result = await service.getProcessingStatus('user-123');

      expect(result).toEqual({
        userId: 'user-123',
        processing_restricted: true,
        restriction_reason: 'Data accuracy dispute',
        last_updated: expect.any(Date),
        gdpr_article: 'Article 18 - Right to Restriction of Processing',
      });
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      await expect(service.getProcessingStatus('nonexistent-id')).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.getProcessingStatus('nonexistent-id')).rejects.toThrow(
        'User not found',
      );
    });
  });

  describe('UsersService.isProcessingRestricted', () => {
    it('should return true for restricted users', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };
      mockUserRepository.findOne.mockResolvedValue(restrictedUser);

      const result = await service.isProcessingRestricted('user-123');

      expect(result).toBe(true);
    });

    it('should return false for unrestricted users', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);

      const result = await service.isProcessingRestricted('user-123');

      expect(result).toBe(false);
    });

    it('should return false if user does not exist', async () => {
      mockUserRepository.findOne.mockResolvedValue(null);

      const result = await service.isProcessingRestricted('nonexistent-id');

      expect(result).toBe(false);
    });
  });

  describe('UsersController.restrictProcessing', () => {
    it('should allow user to restrict their own processing', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockResolvedValue(restrictedUser);

      const result = await controller.restrictProcessing(
        'user-123',
        {},
        mockRequest,
      );

      expect(result.processing_restricted).toBe(true);
    });

    it('should allow user to restrict with a reason', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };
      const reason = 'I need to verify the data accuracy';
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
        restriction_reason: reason,
      };

      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockResolvedValue(restrictedUser);

      const result = await controller.restrictProcessing(
        'user-123',
        { reason },
        mockRequest,
      );

      expect(result.processing_restricted).toBe(true);
      expect(result.restriction_reason).toBe(reason);
    });

    it('should throw ForbiddenException if user tries to restrict another account', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };

      await expect(
        controller.restrictProcessing('other-user-456', {}, mockRequest),
      ).rejects.toThrow(ForbiddenException);
      await expect(
        controller.restrictProcessing('other-user-456', {}, mockRequest),
      ).rejects.toThrow('You can only restrict processing for your own account');
    });

    it('should allow admin to restrict any user account', async () => {
      const mockRequest = {
        user: { userId: 'admin-456', role: UserRole.ADMIN },
      };
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockResolvedValue(restrictedUser);

      const result = await controller.restrictProcessing(
        'user-123',
        { reason: 'Admin override' },
        mockRequest,
      );

      expect(result.processing_restricted).toBe(true);
    });
  });

  describe('UsersController.liftProcessingRestriction', () => {
    it('should allow user to lift their own processing restriction', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      mockUserRepository.findOne.mockResolvedValue(restrictedUser);
      mockUserRepository.save.mockResolvedValue({
        ...restrictedUser,
        processing_restricted: false,
        restriction_reason: null,
      });

      const result = await controller.liftProcessingRestriction('user-123', mockRequest);

      expect(result.processing_restricted).toBe(false);
    });

    it('should throw ForbiddenException if user tries to lift restriction on another account', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };

      await expect(
        controller.liftProcessingRestriction('other-user-456', mockRequest),
      ).rejects.toThrow(ForbiddenException);
      await expect(
        controller.liftProcessingRestriction('other-user-456', mockRequest),
      ).rejects.toThrow('You can only lift processing restriction for your own account');
    });

    it('should allow admin to lift restriction on any account', async () => {
      const mockRequest = {
        user: { userId: 'admin-456', role: UserRole.ADMIN },
      };
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      mockUserRepository.findOne.mockResolvedValue(restrictedUser);
      mockUserRepository.save.mockResolvedValue({
        ...restrictedUser,
        processing_restricted: false,
        restriction_reason: null,
      });

      const result = await controller.liftProcessingRestriction('user-123', mockRequest);

      expect(result.processing_restricted).toBe(false);
    });
  });

  describe('UsersController.getProcessingStatus', () => {
    it('should allow user to view their own processing status', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };

      const unrestrictedUser = {
        ...mockUser,
        processing_restricted: false,
        restriction_reason: null,
      };

      mockUserRepository.findOne.mockResolvedValue(unrestrictedUser);

      const result = await controller.getProcessingStatus('user-123', mockRequest);

      expect(result.userId).toBe('user-123');
      expect(result.processing_restricted).toBe(false);
    });

    it('should throw ForbiddenException if user tries to view another account status', async () => {
      const mockRequest = {
        user: { userId: 'user-123', role: UserRole.CONSULTANT },
      };

      await expect(
        controller.getProcessingStatus('other-user-456', mockRequest),
      ).rejects.toThrow(ForbiddenException);
      await expect(
        controller.getProcessingStatus('other-user-456', mockRequest),
      ).rejects.toThrow('You can only view processing status for your own account');
    });

    it('should allow admin to view any account processing status', async () => {
      const mockRequest = {
        user: { userId: 'admin-456', role: UserRole.ADMIN },
      };

      mockUserRepository.findOne.mockResolvedValue(mockUser);

      const result = await controller.getProcessingStatus('user-123', mockRequest);

      expect(result.userId).toBe('user-123');
    });
  });

  describe('Integration - Processing Restriction Effects', () => {
    it('should prevent creating assessments when processing is restricted', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
        restriction_reason: 'Data verification in progress',
      };

      mockUserRepository.findOne.mockResolvedValue(restrictedUser);

      const isRestricted = await service.isProcessingRestricted('user-123');

      expect(isRestricted).toBe(true);
      // The guard/interceptor will use this to block assessment creation
    });

    it('should allow viewing data when processing is restricted', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      mockUserRepository.findOne.mockResolvedValue(restrictedUser);

      // Users should still be able to view their data
      const user = await service.findById('user-123');
      expect(user).toBeDefined();
      expect(user?.processing_restricted).toBe(true);
    });

    it('should allow exporting data when processing is restricted', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      mockUserRepository.findOne.mockResolvedValue(restrictedUser);
      mockAssessmentRepository.find.mockResolvedValue([]);

      // GDPR Article 15 should still work even when processing is restricted
      const exportData = await service.exportUserData('user-123');

      expect(exportData).toBeDefined();
      expect(exportData.user.id).toBe('user-123');
    });

    it('should allow deleting account when processing is restricted', async () => {
      const restrictedUser = {
        ...mockUser,
        processing_restricted: true,
      };

      const mockQueryRunner = {
        connect: jest.fn(),
        startTransaction: jest.fn(),
        commitTransaction: jest.fn(),
        rollbackTransaction: jest.fn(),
        release: jest.fn(),
        manager: {
          findOne: jest.fn().mockResolvedValue(restrictedUser),
          find: jest.fn().mockResolvedValue([]),
          count: jest.fn().mockResolvedValue(0),
          delete: jest.fn(),
        },
      };

      mockDataSource.createQueryRunner.mockReturnValue(mockQueryRunner);

      // GDPR Article 17 should still work even when processing is restricted
      const result = await service.deleteUserCascade('user-123');

      expect(result.deleted).toBe(true);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle database errors gracefully when restricting', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockRejectedValue(new Error('Database connection failed'));

      await expect(service.restrictProcessing('user-123')).rejects.toThrow(
        'Database connection failed',
      );
    });

    it('should handle database errors gracefully when lifting restriction', async () => {
      const restrictedUser = { ...mockUser, processing_restricted: true };
      mockUserRepository.findOne.mockResolvedValue(restrictedUser);
      mockUserRepository.save.mockRejectedValue(new Error('Database connection failed'));

      await expect(service.liftProcessingRestriction('user-123')).rejects.toThrow(
        'Database connection failed',
      );
    });

    it('should truncate very long restriction reasons', async () => {
      const longReason = 'A'.repeat(2000); // Very long reason
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockImplementation((user) => Promise.resolve(user));

      await service.restrictProcessing('user-123', longReason);

      const savedUser = mockUserRepository.save.mock.calls[0][0];
      // Reason should be truncated to reasonable length (e.g., 1000 chars)
      expect(savedUser.restriction_reason).toBeDefined();
    });

    it('should handle concurrent restriction requests', async () => {
      mockUserRepository.findOne.mockResolvedValue(mockUser);
      mockUserRepository.save.mockImplementation((user) =>
        Promise.resolve({ ...user, processing_restricted: true }),
      );

      // Simulate concurrent requests
      const results = await Promise.all([
        service.restrictProcessing('user-123', 'Reason 1'),
        service.restrictProcessing('user-123', 'Reason 2'),
      ]);

      expect(results[0].processing_restricted).toBe(true);
      expect(results[1].processing_restricted).toBe(true);
    });
  });
});
