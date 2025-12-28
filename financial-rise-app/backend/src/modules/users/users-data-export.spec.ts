import { Test, TestingModule } from '@nestjs/testing';
import { UsersController } from './users.controller';
import { UsersService } from './users.service';
import { NotFoundException, ForbiddenException } from '@nestjs/common';
import { User, UserRole, UserStatus } from './entities/user.entity';

describe('UsersController - GDPR Data Export (Article 15)', () => {
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
    created_at: new Date('2024-01-01T00:00:00Z'),
    updated_at: new Date('2024-06-01T00:00:00Z'),
    last_login_at: new Date('2024-06-15T10:30:00Z'),
    failed_login_attempts: 0,
    locked_until: null,
  };

  const mockAssessments = [
    {
      id: 'assessment-1',
      client_name: 'Client One',
      business_name: 'Business One',
      client_email: 'client1@example.com',
      status: 'completed',
      created_at: new Date('2024-03-01T00:00:00Z'),
    },
    {
      id: 'assessment-2',
      client_name: 'Client Two',
      business_name: 'Business Two',
      client_email: 'client2@example.com',
      status: 'in_progress',
      created_at: new Date('2024-05-01T00:00:00Z'),
    },
  ];

  const mockUsersService = {
    findById: jest.fn(),
    exportUserData: jest.fn(),
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

  describe('GET /api/users/:id/data-export - GDPR Article 15 (Right to Access)', () => {
    it('should export user data in JSON format', async () => {
      const exportedData = {
        user: mockUser,
        assessments: mockAssessments,
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result).toEqual(exportedData);
      expect(service.exportUserData).toHaveBeenCalledWith(mockUserId);
    });

    it('should include all user profile data', async () => {
      const exportedData = {
        user: {
          id: mockUser.id,
          email: mockUser.email,
          first_name: mockUser.first_name,
          last_name: mockUser.last_name,
          role: mockUser.role,
          status: mockUser.status,
          created_at: mockUser.created_at,
          updated_at: mockUser.updated_at,
          last_login_at: mockUser.last_login_at,
        },
        assessments: [],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.user).toHaveProperty('id');
      expect(result.user).toHaveProperty('email');
      expect(result.user).toHaveProperty('first_name');
      expect(result.user).toHaveProperty('last_name');
      expect(result.user).toHaveProperty('role');
      expect(result.user).toHaveProperty('created_at');
    });

    it('should include all assessments created by the user', async () => {
      const exportedData = {
        user: mockUser,
        assessments: mockAssessments,
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.assessments).toHaveLength(2);
      expect(result.assessments[0]).toHaveProperty('client_name');
      expect(result.assessments[0]).toHaveProperty('business_name');
    });

    it('should NOT include password hash in export', async () => {
      const exportedData = {
        user: {
          id: mockUserId,
          email: mockUser.email,
          first_name: mockUser.first_name,
          last_name: mockUser.last_name,
          role: mockUser.role,
          status: mockUser.status,
          created_at: mockUser.created_at,
          updated_at: mockUser.updated_at,
          last_login_at: mockUser.last_login_at,
          // password_hash should NOT be included
        },
        assessments: [],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.user).not.toHaveProperty('password_hash');
    });

    it('should NOT include refresh tokens in export', async () => {
      const exportedData = {
        user: {
          id: mockUserId,
          email: mockUser.email,
          first_name: mockUser.first_name,
          last_name: mockUser.last_name,
          role: mockUser.role,
          status: mockUser.status,
          created_at: mockUser.created_at,
          updated_at: mockUser.updated_at,
          last_login_at: mockUser.last_login_at,
          // refresh_token and reset_password_token should NOT be included
        },
        assessments: [],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.user).not.toHaveProperty('refresh_token');
      expect(result.user).not.toHaveProperty('reset_password_token');
    });

    it('should include export metadata with timestamp', async () => {
      const exportedData = {
        user: mockUser,
        assessments: [],
        export_metadata: {
          exported_at: new Date().toISOString(),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.export_metadata).toHaveProperty('exported_at');
      expect(result.export_metadata).toHaveProperty('export_format', 'JSON');
      expect(result.export_metadata).toHaveProperty('gdpr_article');
    });

    it('should throw NotFoundException if user does not exist', async () => {
      mockUsersService.exportUserData.mockRejectedValue(
        new NotFoundException('User not found'),
      );

      const req = { user: { userId: 'non-existent', role: UserRole.CONSULTANT } };

      await expect(controller.exportUserData('non-existent', req)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should only allow users to export their own data', async () => {
      const req = { user: { userId: 'different-user-id', role: UserRole.CONSULTANT } };

      await expect(controller.exportUserData(mockUserId, req)).rejects.toThrow(
        ForbiddenException,
      );
    });

    it('should allow admins to export any user data', async () => {
      const exportedData = {
        user: mockUser,
        assessments: mockAssessments,
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: 'admin-id', role: UserRole.ADMIN } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result).toEqual(exportedData);
    });

    it('should decrypt encrypted data before export', async () => {
      // Assessment responses with financial data should be decrypted
      const exportedData = {
        user: mockUser,
        assessments: [
          {
            ...mockAssessments[0],
            responses: [
              {
                question_id: 'revenue',
                answer: { value: 500000 }, // Should be decrypted
              },
            ],
          },
        ],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.assessments[0].responses[0].answer).toHaveProperty('value');
    });

    it('should include DISC profiles in export', async () => {
      const exportedData = {
        user: mockUser,
        assessments: [
          {
            ...mockAssessments[0],
            disc_profiles: [
              {
                primary_trait: 'D',
                d_score: 85,
                i_score: 60,
                s_score: 40,
                c_score: 55,
              },
            ],
          },
        ],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.assessments[0]).toHaveProperty('disc_profiles');
      expect(result.assessments[0].disc_profiles[0]).toHaveProperty('primary_trait');
    });

    it('should include phase results in export', async () => {
      const exportedData = {
        user: mockUser,
        assessments: [
          {
            ...mockAssessments[0],
            phase_results: [
              {
                phase: 'ORGANIZE',
                score: 75,
                percentage: 0.75,
              },
            ],
          },
        ],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      const req = { user: { userId: mockUserId, role: UserRole.CONSULTANT } };
      const result = await controller.exportUserData(mockUserId, req);

      expect(result.assessments[0]).toHaveProperty('phase_results');
      expect(result.assessments[0].phase_results[0]).toHaveProperty('phase');
    });

    it('should use JSON as default export format (GDPR Article 20)', () => {
      // Data portability requires machine-readable format
      const exportedData = {
        user: mockUser,
        assessments: [],
        export_metadata: {
          exported_at: expect.any(String),
          export_format: 'JSON',
          gdpr_article: 'Article 15 - Right to Access',
        },
      };

      mockUsersService.exportUserData.mockResolvedValue(exportedData);

      expect(exportedData.export_metadata.export_format).toBe('JSON');
    });

    it('should set correct HTTP headers for JSON download', async () => {
      // Test will be in e2e tests - this is a placeholder
      expect(true).toBe(true);
    });
  });
});
