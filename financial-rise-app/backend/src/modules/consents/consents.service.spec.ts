import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { ConsentsService } from './consents.service';
import { UserConsent, ConsentType } from './entities/user-consent.entity';

describe('ConsentsService', () => {
  let service: ConsentsService;
  let repository: Repository<UserConsent>;

  const mockUserId = '123e4567-e89b-12d3-a456-426614174000';
  const mockConsentId = '123e4567-e89b-12d3-a456-426614174001';

  const mockRepository = {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ConsentsService,
        {
          provide: getRepositoryToken(UserConsent),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<ConsentsService>(ConsentsService);
    repository = module.get<Repository<UserConsent>>(getRepositoryToken(UserConsent));

    // Clear all mocks before each test
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('logConsent', () => {
    it('should log a new consent with all required fields', async () => {
      const consentData = {
        userId: mockUserId,
        type: ConsentType.ANALYTICS,
        granted: true,
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      };

      const expectedConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
        created_at: new Date(),
        updated_at: new Date(),
      };

      mockRepository.create.mockReturnValue(expectedConsent);
      mockRepository.save.mockResolvedValue(expectedConsent);

      const result = await service.logConsent(
        consentData.userId,
        consentData.type,
        consentData.granted,
        consentData.ipAddress,
        consentData.userAgent,
      );

      expect(mockRepository.create).toHaveBeenCalledWith({
        user_id: consentData.userId,
        consent_type: consentData.type,
        granted: consentData.granted,
        ip_address: consentData.ipAddress,
        user_agent: consentData.userAgent,
      });
      expect(mockRepository.save).toHaveBeenCalledWith(expectedConsent);
      expect(result).toEqual(expectedConsent);
    });

    it('should log consent with granted=false when user withdraws consent', async () => {
      const consentData = {
        userId: mockUserId,
        type: ConsentType.MARKETING,
        granted: false,
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      };

      const expectedConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.MARKETING,
        granted: false,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
      };

      mockRepository.create.mockReturnValue(expectedConsent);
      mockRepository.save.mockResolvedValue(expectedConsent);

      const result = await service.logConsent(
        consentData.userId,
        consentData.type,
        consentData.granted,
        consentData.ipAddress,
        consentData.userAgent,
      );

      expect(result.granted).toBe(false);
    });

    it('should log essential consent', async () => {
      const consentData = {
        userId: mockUserId,
        type: ConsentType.ESSENTIAL,
        granted: true,
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      };

      const expectedConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ESSENTIAL,
        granted: true,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
      };

      mockRepository.create.mockReturnValue(expectedConsent);
      mockRepository.save.mockResolvedValue(expectedConsent);

      const result = await service.logConsent(
        consentData.userId,
        consentData.type,
        consentData.granted,
        consentData.ipAddress,
        consentData.userAgent,
      );

      expect(result.consent_type).toBe(ConsentType.ESSENTIAL);
    });

    it('should handle IPv6 addresses correctly', async () => {
      const ipv6Address = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';

      const expectedConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
        ip_address: ipv6Address,
        user_agent: 'Mozilla/5.0',
      };

      mockRepository.create.mockReturnValue(expectedConsent);
      mockRepository.save.mockResolvedValue(expectedConsent);

      const result = await service.logConsent(
        mockUserId,
        ConsentType.ANALYTICS,
        true,
        ipv6Address,
        'Mozilla/5.0',
      );

      expect(result.ip_address).toBe(ipv6Address);
    });

    it('should allow null IP address and user agent', async () => {
      const expectedConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
        ip_address: null,
        user_agent: null,
      };

      mockRepository.create.mockReturnValue(expectedConsent);
      mockRepository.save.mockResolvedValue(expectedConsent);

      const result = await service.logConsent(
        mockUserId,
        ConsentType.ANALYTICS,
        true,
        null,
        null,
      );

      expect(result.ip_address).toBeNull();
      expect(result.user_agent).toBeNull();
    });
  });

  describe('getConsents', () => {
    it('should return all consents for a user', async () => {
      const mockConsents: Partial<UserConsent>[] = [
        {
          id: '1',
          user_id: mockUserId,
          consent_type: ConsentType.ESSENTIAL,
          granted: true,
          created_at: new Date('2024-01-01'),
        },
        {
          id: '2',
          user_id: mockUserId,
          consent_type: ConsentType.ANALYTICS,
          granted: true,
          created_at: new Date('2024-01-02'),
        },
      ];

      mockRepository.find.mockResolvedValue(mockConsents);

      const result = await service.getConsents(mockUserId);

      expect(mockRepository.find).toHaveBeenCalledWith({
        where: { user_id: mockUserId },
        order: { created_at: 'DESC' },
      });
      expect(result).toEqual(mockConsents);
      expect(result.length).toBe(2);
    });

    it('should return empty array if user has no consents', async () => {
      mockRepository.find.mockResolvedValue([]);

      const result = await service.getConsents(mockUserId);

      expect(result).toEqual([]);
      expect(result.length).toBe(0);
    });

    it('should order consents by created_at DESC (newest first)', async () => {
      const mockConsents: Partial<UserConsent>[] = [
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
          consent_type: ConsentType.ESSENTIAL,
          granted: true,
          created_at: new Date('2024-01-01'),
        },
      ];

      mockRepository.find.mockResolvedValue(mockConsents);

      await service.getConsents(mockUserId);

      expect(mockRepository.find).toHaveBeenCalledWith({
        where: { user_id: mockUserId },
        order: { created_at: 'DESC' },
      });
    });
  });

  describe('getCurrentConsent', () => {
    it('should return the most recent consent for a specific type', async () => {
      const mockConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
        created_at: new Date(),
      };

      mockRepository.findOne.mockResolvedValue(mockConsent);

      const result = await service.getCurrentConsent(mockUserId, ConsentType.ANALYTICS);

      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { user_id: mockUserId, consent_type: ConsentType.ANALYTICS },
        order: { created_at: 'DESC' },
      });
      expect(result).toEqual(mockConsent);
    });

    it('should return null if no consent exists for the type', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.getCurrentConsent(mockUserId, ConsentType.MARKETING);

      expect(result).toBeNull();
    });

    it('should return the most recent consent when multiple exist', async () => {
      const mostRecentConsent: Partial<UserConsent> = {
        id: '2',
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: false,
        created_at: new Date('2024-01-02'),
      };

      mockRepository.findOne.mockResolvedValue(mostRecentConsent);

      const result = await service.getCurrentConsent(mockUserId, ConsentType.ANALYTICS);

      expect(result).toEqual(mostRecentConsent);
      expect(result?.granted).toBe(false);
    });
  });

  describe('updateConsent', () => {
    it('should create a new consent record when updating', async () => {
      const newConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: false,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
      };

      mockRepository.create.mockReturnValue(newConsent);
      mockRepository.save.mockResolvedValue(newConsent);

      const result = await service.updateConsent(
        mockUserId,
        ConsentType.ANALYTICS,
        false,
        '192.168.1.1',
        'Mozilla/5.0',
      );

      expect(mockRepository.create).toHaveBeenCalled();
      expect(mockRepository.save).toHaveBeenCalledWith(newConsent);
      expect(result.granted).toBe(false);
    });

    it('should throw BadRequestException when trying to revoke essential consent', async () => {
      await expect(
        service.updateConsent(
          mockUserId,
          ConsentType.ESSENTIAL,
          false,
          '192.168.1.1',
          'Mozilla/5.0',
        ),
      ).rejects.toThrow(BadRequestException);

      await expect(
        service.updateConsent(
          mockUserId,
          ConsentType.ESSENTIAL,
          false,
          '192.168.1.1',
          'Mozilla/5.0',
        ),
      ).rejects.toThrow('Essential consent cannot be revoked');

      expect(mockRepository.create).not.toHaveBeenCalled();
      expect(mockRepository.save).not.toHaveBeenCalled();
    });

    it('should allow granting essential consent', async () => {
      const newConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ESSENTIAL,
        granted: true,
        ip_address: '192.168.1.1',
        user_agent: 'Mozilla/5.0',
      };

      mockRepository.create.mockReturnValue(newConsent);
      mockRepository.save.mockResolvedValue(newConsent);

      const result = await service.updateConsent(
        mockUserId,
        ConsentType.ESSENTIAL,
        true,
        '192.168.1.1',
        'Mozilla/5.0',
      );

      expect(result.consent_type).toBe(ConsentType.ESSENTIAL);
      expect(result.granted).toBe(true);
    });

    it('should record IP and user agent when updating consent', async () => {
      const ipAddress = '203.0.113.0';
      const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';

      const newConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.MARKETING,
        granted: true,
        ip_address: ipAddress,
        user_agent: userAgent,
      };

      mockRepository.create.mockReturnValue(newConsent);
      mockRepository.save.mockResolvedValue(newConsent);

      const result = await service.updateConsent(
        mockUserId,
        ConsentType.MARKETING,
        true,
        ipAddress,
        userAgent,
      );

      expect(result.ip_address).toBe(ipAddress);
      expect(result.user_agent).toBe(userAgent);
    });
  });

  describe('getConsentHistory', () => {
    it('should return all consent history for a specific type', async () => {
      const mockHistory: Partial<UserConsent>[] = [
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

      mockRepository.find.mockResolvedValue(mockHistory);

      const result = await service.getConsentHistory(mockUserId, ConsentType.ANALYTICS);

      expect(mockRepository.find).toHaveBeenCalledWith({
        where: { user_id: mockUserId, consent_type: ConsentType.ANALYTICS },
        order: { created_at: 'DESC' },
      });
      expect(result).toEqual(mockHistory);
      expect(result.length).toBe(3);
    });

    it('should return empty array if no history exists', async () => {
      mockRepository.find.mockResolvedValue([]);

      const result = await service.getConsentHistory(mockUserId, ConsentType.MARKETING);

      expect(result).toEqual([]);
    });
  });

  describe('hasActiveConsent', () => {
    it('should return true if user has granted consent', async () => {
      const mockConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: true,
      };

      mockRepository.findOne.mockResolvedValue(mockConsent);

      const result = await service.hasActiveConsent(mockUserId, ConsentType.ANALYTICS);

      expect(result).toBe(true);
    });

    it('should return false if user has withdrawn consent', async () => {
      const mockConsent: Partial<UserConsent> = {
        id: mockConsentId,
        user_id: mockUserId,
        consent_type: ConsentType.ANALYTICS,
        granted: false,
      };

      mockRepository.findOne.mockResolvedValue(mockConsent);

      const result = await service.hasActiveConsent(mockUserId, ConsentType.ANALYTICS);

      expect(result).toBe(false);
    });

    it('should return false if no consent record exists', async () => {
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.hasActiveConsent(mockUserId, ConsentType.MARKETING);

      expect(result).toBe(false);
    });

    it('should always return true for essential consent (default behavior)', async () => {
      // Even if no record exists, essential consent is assumed to be granted
      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.hasActiveConsent(mockUserId, ConsentType.ESSENTIAL);

      // Essential consent should be true by default
      expect(result).toBe(true);
    });
  });
});
