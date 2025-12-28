import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';
import { ConsentsController } from './consents.controller';
import { ConsentsService } from './consents.service';
import { ConsentType } from './entities/user-consent.entity';
import { UserRole } from '../users/entities/user.entity';

describe('ConsentsController', () => {
  let controller: ConsentsController;
  let service: ConsentsService;

  const mockUserId = '123e4567-e89b-12d3-a456-426614174000';
  const mockOtherUserId = '123e4567-e89b-12d3-a456-426614174999';

  const mockConsentsService = {
    getConsents: jest.fn(),
    getCurrentConsent: jest.fn(),
    updateConsent: jest.fn(),
    getConsentHistory: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ConsentsController],
      providers: [
        {
          provide: ConsentsService,
          useValue: mockConsentsService,
        },
      ],
    }).compile();

    controller = module.get<ConsentsController>(ConsentsController);
    service = module.get<ConsentsService>(ConsentsService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  describe('GET /users/:id/consents', () => {
    it('should return all consents for the authenticated user', async () => {
      const mockConsents = [
        {
          id: '1',
          user_id: mockUserId,
          consent_type: ConsentType.ESSENTIAL,
          granted: true,
          created_at: new Date(),
        },
        {
          id: '2',
          user_id: mockUserId,
          consent_type: ConsentType.ANALYTICS,
          granted: true,
          created_at: new Date(),
        },
      ];

      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      mockConsentsService.getConsents.mockResolvedValue(mockConsents);

      const result = await controller.getConsents(mockUserId, mockRequest);

      expect(service.getConsents).toHaveBeenCalledWith(mockUserId);
      expect(result).toEqual(mockConsents);
    });

    it('should throw ForbiddenException if user tries to access another user consents', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      await expect(
        controller.getConsents(mockOtherUserId, mockRequest),
      ).rejects.toThrow(ForbiddenException);

      await expect(
        controller.getConsents(mockOtherUserId, mockRequest),
      ).rejects.toThrow('You can only access your own consent data');

      expect(service.getConsents).not.toHaveBeenCalled();
    });

    it('should allow admin to access any user consents', async () => {
      const mockConsents = [
        {
          id: '1',
          user_id: mockOtherUserId,
          consent_type: ConsentType.ESSENTIAL,
          granted: true,
          created_at: new Date(),
        },
      ];

      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.ADMIN },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      mockConsentsService.getConsents.mockResolvedValue(mockConsents);

      const result = await controller.getConsents(mockOtherUserId, mockRequest);

      expect(service.getConsents).toHaveBeenCalledWith(mockOtherUserId);
      expect(result).toEqual(mockConsents);
    });
  });

  describe('PATCH /users/:id/consents/:type', () => {
    it('should update consent for the authenticated user', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const updateDto = { granted: false };

      const mockUpdatedConsent = {
        id: '1',
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: false,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
        created_at: new Date(),
      };

      mockConsentsService.updateConsent.mockResolvedValue(mockUpdatedConsent);

      const result = await controller.updateConsent(
        mockUserId,
        ConsentType.ANALYTICS,
        updateDto,
        mockRequest,
      );

      expect(service.updateConsent).toHaveBeenCalledWith(
        mockUserId,
        ConsentType.ANALYTICS,
        false,
        '192.168.1.1',
        'Mozilla/5.0',
      );
      expect(result).toEqual(mockUpdatedConsent);
    });

    it('should throw ForbiddenException if user tries to update another user consent', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const updateDto = { granted: true };

      await expect(
        controller.updateConsent(mockOtherUserId, ConsentType.ANALYTICS, updateDto, mockRequest),
      ).rejects.toThrow(ForbiddenException);

      expect(service.updateConsent).not.toHaveBeenCalled();
    });

    it('should allow admin to update any user consent', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.ADMIN },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const updateDto = { granted: true };

      const mockUpdatedConsent = {
        id: '1',
        user_id: mockOtherUserId,
        consent_type: ConsentType.MARKETING,
        granted: true,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
        created_at: new Date(),
      };

      mockConsentsService.updateConsent.mockResolvedValue(mockUpdatedConsent);

      const result = await controller.updateConsent(
        mockOtherUserId,
        ConsentType.MARKETING,
        updateDto,
        mockRequest,
      );

      expect(service.updateConsent).toHaveBeenCalledWith(
        mockOtherUserId,
        ConsentType.MARKETING,
        true,
        '192.168.1.1',
        'Mozilla/5.0',
      );
      expect(result).toEqual(mockUpdatedConsent);
    });

    it('should extract IP address from request', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '203.0.113.42',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      const updateDto = { granted: true };

      const mockUpdatedConsent = {
        id: '1',
        user_id: mockUserId,
        consent_type: ConsentType.MARKETING,
        granted: true,
        ip_address: '203.0.113.42',
        user_agent: 'Mozilla/5.0',
        created_at: new Date(),
      };

      mockConsentsService.updateConsent.mockResolvedValue(mockUpdatedConsent);

      await controller.updateConsent(mockUserId, ConsentType.MARKETING, updateDto, mockRequest);

      expect(service.updateConsent).toHaveBeenCalledWith(
        mockUserId,
        ConsentType.MARKETING,
        true,
        '203.0.113.42',
        'Mozilla/5.0',
      );
    });

    it('should extract user agent from request headers', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Custom User Agent String' },
      };

      const updateDto = { granted: true };

      const mockUpdatedConsent = {
        id: '1',
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
        ip_address: '192.168.1.1',
        user_agent: 'Custom User Agent String',
        created_at: new Date(),
      };

      mockConsentsService.updateConsent.mockResolvedValue(mockUpdatedConsent);

      await controller.updateConsent(mockUserId, ConsentType.ANALYTICS, updateDto, mockRequest);

      expect(service.updateConsent).toHaveBeenCalledWith(
        mockUserId,
        ConsentType.ANALYTICS,
        true,
        '192.168.1.1',
        'Custom User Agent String',
      );
    });

    it('should handle missing user agent gracefully', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: {},
      };

      const updateDto = { granted: true };

      const mockUpdatedConsent = {
        id: '1',
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
        ip_address: '192.168.1.1',
        user_agent: null,
        created_at: new Date(),
      };

      mockConsentsService.updateConsent.mockResolvedValue(mockUpdatedConsent);

      await controller.updateConsent(mockUserId, ConsentType.ANALYTICS, updateDto, mockRequest);

      expect(service.updateConsent).toHaveBeenCalledWith(
        mockUserId,
        ConsentType.ANALYTICS,
        true,
        '192.168.1.1',
        null,
      );
    });
  });

  describe('GET /users/:id/consents/:type/history', () => {
    it('should return consent history for a specific type', async () => {
      const mockHistory = [
        {
          id: '3',
          user_id: mockUserId,
          consent_type: ConsentType.ANALYTICS,
          granted: false,
          created_at: new Date('2024-01-03'),
        },
        {
          id: '2',
          user_id: mockUserId,
          consent_type: ConsentType.ANALYTICS,
          granted: true,
          created_at: new Date('2024-01-02'),
        },
        {
          id: '1',
          user_id: mockUserId,
          consent_type: ConsentType.ANALYTICS,
          granted: true,
          created_at: new Date('2024-01-01'),
        },
      ];

      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      mockConsentsService.getConsentHistory.mockResolvedValue(mockHistory);

      const result = await controller.getConsentHistory(
        mockUserId,
        ConsentType.ANALYTICS,
        mockRequest,
      );

      expect(service.getConsentHistory).toHaveBeenCalledWith(mockUserId, ConsentType.ANALYTICS);
      expect(result).toEqual(mockHistory);
      expect(result.length).toBe(3);
    });

    it('should throw ForbiddenException if user tries to access another user history', async () => {
      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.CONSULTANT },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      await expect(
        controller.getConsentHistory(mockOtherUserId, ConsentType.ANALYTICS, mockRequest),
      ).rejects.toThrow(ForbiddenException);

      expect(service.getConsentHistory).not.toHaveBeenCalled();
    });

    it('should allow admin to access any user consent history', async () => {
      const mockHistory = [
        {
          id: '1',
          user_id: mockOtherUserId,
          consent_type: ConsentType.MARKETING,
          granted: true,
          created_at: new Date(),
        },
      ];

      const mockRequest = {
        user: { userId: mockUserId, role: UserRole.ADMIN },
        ip: '192.168.1.1',
        headers: { 'user-agent': 'Mozilla/5.0' },
      };

      mockConsentsService.getConsentHistory.mockResolvedValue(mockHistory);

      const result = await controller.getConsentHistory(
        mockOtherUserId,
        ConsentType.MARKETING,
        mockRequest,
      );

      expect(service.getConsentHistory).toHaveBeenCalledWith(
        mockOtherUserId,
        ConsentType.MARKETING,
      );
      expect(result).toEqual(mockHistory);
    });
  });
});
