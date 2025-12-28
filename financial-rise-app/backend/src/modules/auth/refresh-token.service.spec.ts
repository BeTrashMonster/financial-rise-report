import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { RefreshTokenService } from './refresh-token.service';
import { RefreshToken } from './entities/refresh-token.entity';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

describe('RefreshTokenService', () => {
  let service: RefreshTokenService;
  let repository: Repository<RefreshToken>;

  const mockRepository = {
    create: jest.fn(),
    save: jest.fn(),
    find: jest.fn(),
    findOne: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
    count: jest.fn(),
    createQueryBuilder: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RefreshTokenService,
        {
          provide: getRepositoryToken(RefreshToken),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<RefreshTokenService>(RefreshTokenService);
    repository = module.get<Repository<RefreshToken>>(getRepositoryToken(RefreshToken));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('createToken', () => {
    const userId = 'user-123';
    const token = 'raw-refresh-token';
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    const deviceInfo = 'Chrome on Windows';
    const ipAddress = '192.168.1.1';

    it('should create and save a new refresh token', async () => {
      const hashedToken = 'hashed-token';
      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedToken);

      const mockToken = {
        id: 'token-123',
        userId,
        token: hashedToken,
        expiresAt,
        deviceInfo,
        ipAddress,
        createdAt: new Date(),
        revokedAt: null,
      };

      mockRepository.create.mockReturnValue(mockToken);
      mockRepository.save.mockResolvedValue(mockToken);

      const result = await service.createToken(userId, token, expiresAt, deviceInfo, ipAddress);

      expect(bcrypt.hash).toHaveBeenCalledWith(token, 10);
      expect(repository.create).toHaveBeenCalledWith({
        userId,
        token: hashedToken,
        expiresAt,
        deviceInfo,
        ipAddress,
      });
      expect(repository.save).toHaveBeenCalledWith(mockToken);
      expect(result).toEqual(mockToken);
    });

    it('should hash the token before storing', async () => {
      const hashedToken = 'hashed-secure-token';
      (bcrypt.hash as jest.Mock).mockResolvedValue(hashedToken);

      mockRepository.create.mockReturnValue({});
      mockRepository.save.mockResolvedValue({});

      await service.createToken(userId, token, expiresAt);

      expect(bcrypt.hash).toHaveBeenCalledWith(token, 10);
      const createCall = mockRepository.create.mock.calls[0][0];
      expect(createCall.token).toBe(hashedToken);
      expect(createCall.token).not.toBe(token);
    });

    it('should store optional device info and IP address', async () => {
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed');
      mockRepository.create.mockReturnValue({});
      mockRepository.save.mockResolvedValue({});

      await service.createToken(userId, token, expiresAt, deviceInfo, ipAddress);

      const createCall = mockRepository.create.mock.calls[0][0];
      expect(createCall.deviceInfo).toBe(deviceInfo);
      expect(createCall.ipAddress).toBe(ipAddress);
    });

    it('should work without device info and IP address', async () => {
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed');
      mockRepository.create.mockReturnValue({});
      mockRepository.save.mockResolvedValue({});

      await service.createToken(userId, token, expiresAt);

      const createCall = mockRepository.create.mock.calls[0][0];
      expect(createCall.deviceInfo).toBeUndefined();
      expect(createCall.ipAddress).toBeUndefined();
    });
  });

  describe('findValidToken', () => {
    const userId = 'user-123';
    const rawToken = 'raw-refresh-token';

    it('should find and return a valid token', async () => {
      const hashedToken = 'hashed-token';
      const mockToken = {
        id: 'token-123',
        userId,
        token: hashedToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revokedAt: null,
      };

      mockRepository.find.mockResolvedValue([mockToken]);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      const result = await service.findValidToken(userId, rawToken);

      expect(repository.find).toHaveBeenCalledWith({
        where: {
          userId,
          revokedAt: null,
        },
      });
      expect(bcrypt.compare).toHaveBeenCalledWith(rawToken, hashedToken);
      expect(result).toEqual(mockToken);
    });

    it('should return null if no tokens found', async () => {
      mockRepository.find.mockResolvedValue([]);

      const result = await service.findValidToken(userId, rawToken);

      expect(result).toBeNull();
    });

    it('should skip expired tokens', async () => {
      const expiredToken = {
        id: 'token-123',
        userId,
        token: 'hashed-expired',
        expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
        revokedAt: null,
      };

      mockRepository.find.mockResolvedValue([expiredToken]);

      const result = await service.findValidToken(userId, rawToken);

      expect(result).toBeNull();
      expect(bcrypt.compare).not.toHaveBeenCalled();
    });

    it('should skip revoked tokens', async () => {
      mockRepository.find.mockResolvedValue([]);

      const result = await service.findValidToken(userId, rawToken);

      expect(repository.find).toHaveBeenCalledWith({
        where: {
          userId,
          revokedAt: null,
        },
      });
      expect(result).toBeNull();
    });

    it('should return null if token hash does not match', async () => {
      const mockToken = {
        id: 'token-123',
        userId,
        token: 'different-hash',
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        revokedAt: null,
      };

      mockRepository.find.mockResolvedValue([mockToken]);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      const result = await service.findValidToken(userId, rawToken);

      expect(result).toBeNull();
    });

    it('should check multiple tokens until match found', async () => {
      const tokens = [
        {
          id: 'token-1',
          userId,
          token: 'hash-1',
          expiresAt: new Date(Date.now() + 1000),
          revokedAt: null,
        },
        {
          id: 'token-2',
          userId,
          token: 'hash-2',
          expiresAt: new Date(Date.now() + 1000),
          revokedAt: null,
        },
      ];

      mockRepository.find.mockResolvedValue(tokens);
      (bcrypt.compare as jest.Mock)
        .mockResolvedValueOnce(false) // First token doesn't match
        .mockResolvedValueOnce(true); // Second token matches

      const result = await service.findValidToken(userId, rawToken);

      expect(bcrypt.compare).toHaveBeenCalledTimes(2);
      expect(result).toEqual(tokens[1]);
    });
  });

  describe('revokeToken', () => {
    it('should revoke a specific token', async () => {
      const tokenId = 'token-123';
      mockRepository.update.mockResolvedValue({ affected: 1 });

      await service.revokeToken(tokenId);

      expect(repository.update).toHaveBeenCalledWith(tokenId, {
        revokedAt: expect.any(Date),
      });
    });

    it('should set revokedAt to current timestamp', async () => {
      const tokenId = 'token-123';
      const beforeRevoke = Date.now();
      mockRepository.update.mockResolvedValue({ affected: 1 });

      await service.revokeToken(tokenId);

      const updateCall = mockRepository.update.mock.calls[0][1];
      const revokedAt = updateCall.revokedAt.getTime();
      expect(revokedAt).toBeGreaterThanOrEqual(beforeRevoke);
      expect(revokedAt).toBeLessThanOrEqual(Date.now());
    });
  });

  describe('revokeAllUserTokens', () => {
    it('should revoke all tokens for a user', async () => {
      const userId = 'user-123';
      mockRepository.update.mockResolvedValue({ affected: 3 });

      await service.revokeAllUserTokens(userId);

      expect(repository.update).toHaveBeenCalledWith(
        { userId, revokedAt: null },
        { revokedAt: expect.any(Date) },
      );
    });

    it('should only revoke non-revoked tokens', async () => {
      const userId = 'user-123';
      mockRepository.update.mockResolvedValue({ affected: 2 });

      await service.revokeAllUserTokens(userId);

      const whereCondition = mockRepository.update.mock.calls[0][0];
      expect(whereCondition.revokedAt).toBeNull();
    });
  });

  describe('getActiveTokens', () => {
    it('should return all active tokens for a user', async () => {
      const userId = 'user-123';
      const mockTokens = [
        {
          id: 'token-1',
          userId,
          deviceInfo: 'Chrome',
          createdAt: new Date('2024-01-01'),
        },
        {
          id: 'token-2',
          userId,
          deviceInfo: 'Firefox',
          createdAt: new Date('2024-01-02'),
        },
      ];

      mockRepository.find.mockResolvedValue(mockTokens);

      const result = await service.getActiveTokens(userId);

      expect(repository.find).toHaveBeenCalledWith({
        where: {
          userId,
          revokedAt: null,
        },
        order: {
          createdAt: 'DESC',
        },
      });
      expect(result).toEqual(mockTokens);
    });

    it('should order tokens by creation date descending', async () => {
      const userId = 'user-123';
      mockRepository.find.mockResolvedValue([]);

      await service.getActiveTokens(userId);

      const findOptions = mockRepository.find.mock.calls[0][0];
      expect(findOptions.order.createdAt).toBe('DESC');
    });
  });

  describe('cleanupExpiredTokens', () => {
    it('should delete expired tokens', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 5 });
      mockRepository.createQueryBuilder.mockReturnValue({
        delete: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 3 }),
      });

      const result = await service.cleanupExpiredTokens();

      expect(repository.delete).toHaveBeenCalledWith({
        expiresAt: expect.any(Object),
      });
      expect(result).toBe(8); // 5 expired + 3 old revoked
    });

    it('should delete old revoked tokens (>30 days)', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 2 });

      const queryBuilder = {
        delete: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 4 }),
      };

      mockRepository.createQueryBuilder.mockReturnValue(queryBuilder);

      const result = await service.cleanupExpiredTokens();

      expect(queryBuilder.delete).toHaveBeenCalled();
      expect(queryBuilder.where).toHaveBeenCalledWith('revoked_at < :date', {
        date: expect.any(Date),
      });
      expect(result).toBe(6); // 2 expired + 4 old revoked
    });

    it('should return total count of deleted tokens', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 10 });
      mockRepository.createQueryBuilder.mockReturnValue({
        delete: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 5 }),
      });

      const result = await service.cleanupExpiredTokens();

      expect(result).toBe(15);
    });

    it('should handle no tokens to delete', async () => {
      mockRepository.delete.mockResolvedValue({ affected: 0 });
      mockRepository.createQueryBuilder.mockReturnValue({
        delete: jest.fn().mockReturnThis(),
        where: jest.fn().mockReturnThis(),
        execute: jest.fn().mockResolvedValue({ affected: 0 }),
      });

      const result = await service.cleanupExpiredTokens();

      expect(result).toBe(0);
    });
  });

  describe('countActiveSessions', () => {
    it('should count active sessions for a user', async () => {
      const userId = 'user-123';
      mockRepository.count.mockResolvedValue(3);

      const result = await service.countActiveSessions(userId);

      expect(repository.count).toHaveBeenCalledWith({
        where: {
          userId,
          revokedAt: null,
        },
      });
      expect(result).toBe(3);
    });

    it('should return 0 if no active sessions', async () => {
      const userId = 'user-123';
      mockRepository.count.mockResolvedValue(0);

      const result = await service.countActiveSessions(userId);

      expect(result).toBe(0);
    });

    it('should only count non-revoked tokens', async () => {
      const userId = 'user-123';
      mockRepository.count.mockResolvedValue(2);

      await service.countActiveSessions(userId);

      const whereCondition = mockRepository.count.mock.calls[0][0].where;
      expect(whereCondition.revokedAt).toBeNull();
    });
  });
});
