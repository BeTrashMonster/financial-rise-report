import { Test, TestingModule } from '@nestjs/testing';
import { TokenBlacklistService } from './token-blacklist.service';

describe('TokenBlacklistService', () => {
  let service: TokenBlacklistService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TokenBlacklistService],
    }).compile();

    service = module.get<TokenBlacklistService>(TokenBlacklistService);
  });

  afterEach(async () => {
    // Clean up all blacklisted tokens after each test
    await service.clearAll();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('blacklistToken', () => {
    it('should successfully blacklist a token', async () => {
      const token = 'test.jwt.token';
      const expiresInSeconds = 900; // 15 minutes

      await service.blacklistToken(token, expiresInSeconds);

      const isBlacklisted = await service.isBlacklisted(token);
      expect(isBlacklisted).toBe(true);
    });

    it('should hash the token before storing', async () => {
      const token = 'test.jwt.token';
      const expiresInSeconds = 900;

      // Spy on the internal hash generation
      const hashSpy = jest.spyOn(service as any, 'hashToken');

      await service.blacklistToken(token, expiresInSeconds);

      expect(hashSpy).toHaveBeenCalledWith(token);
    });

    it('should store token with correct expiration time', async () => {
      const token = 'test.jwt.token';
      const expiresInSeconds = 1; // 1 second

      await service.blacklistToken(token, expiresInSeconds);

      // Token should be blacklisted immediately
      expect(await service.isBlacklisted(token)).toBe(true);

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Token should no longer be blacklisted after expiration
      expect(await service.isBlacklisted(token)).toBe(false);
    });

    it('should handle blacklisting multiple different tokens', async () => {
      const tokens = [
        'token1.jwt.value',
        'token2.jwt.value',
        'token3.jwt.value',
      ];

      for (const token of tokens) {
        await service.blacklistToken(token, 900);
      }

      for (const token of tokens) {
        expect(await service.isBlacklisted(token)).toBe(true);
      }
    });

    it('should overwrite existing token if blacklisted again', async () => {
      const token = 'test.jwt.token';

      await service.blacklistToken(token, 900);
      expect(await service.isBlacklisted(token)).toBe(true);

      // Blacklist again with different expiration
      await service.blacklistToken(token, 1800);
      expect(await service.isBlacklisted(token)).toBe(true);
    });

    it('should throw error if token is empty', async () => {
      await expect(service.blacklistToken('', 900)).rejects.toThrow(
        'Token cannot be empty',
      );
    });

    it('should throw error if expiration is negative', async () => {
      await expect(service.blacklistToken('test.token', -1)).rejects.toThrow(
        'Expiration time must be positive',
      );
    });

    it('should throw error if expiration is zero', async () => {
      await expect(service.blacklistToken('test.token', 0)).rejects.toThrow(
        'Expiration time must be positive',
      );
    });
  });

  describe('isBlacklisted', () => {
    it('should return false for non-blacklisted token', async () => {
      const token = 'non.blacklisted.token';
      expect(await service.isBlacklisted(token)).toBe(false);
    });

    it('should return true for blacklisted token', async () => {
      const token = 'blacklisted.jwt.token';
      await service.blacklistToken(token, 900);

      expect(await service.isBlacklisted(token)).toBe(true);
    });

    it('should return false for expired blacklisted token', async () => {
      const token = 'expired.blacklisted.token';
      await service.blacklistToken(token, 1); // 1 second

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 1100));

      expect(await service.isBlacklisted(token)).toBe(false);
    });

    it('should handle checking multiple tokens', async () => {
      const blacklistedToken = 'blacklisted.token';
      const validToken = 'valid.token';

      await service.blacklistToken(blacklistedToken, 900);

      expect(await service.isBlacklisted(blacklistedToken)).toBe(true);
      expect(await service.isBlacklisted(validToken)).toBe(false);
    });

    it('should throw error if token is empty', async () => {
      await expect(service.isBlacklisted('')).rejects.toThrow(
        'Token cannot be empty',
      );
    });

    it('should use consistent hashing for same token', async () => {
      const token = 'test.jwt.token';
      await service.blacklistToken(token, 900);

      // Check multiple times to ensure consistent hashing
      expect(await service.isBlacklisted(token)).toBe(true);
      expect(await service.isBlacklisted(token)).toBe(true);
      expect(await service.isBlacklisted(token)).toBe(true);
    });
  });

  describe('removeFromBlacklist', () => {
    it('should remove token from blacklist', async () => {
      const token = 'test.jwt.token';
      await service.blacklistToken(token, 900);

      expect(await service.isBlacklisted(token)).toBe(true);

      await service.removeFromBlacklist(token);

      expect(await service.isBlacklisted(token)).toBe(false);
    });

    it('should not throw error when removing non-existent token', async () => {
      const token = 'non.existent.token';

      await expect(service.removeFromBlacklist(token)).resolves.not.toThrow();
    });

    it('should throw error if token is empty', async () => {
      await expect(service.removeFromBlacklist('')).rejects.toThrow(
        'Token cannot be empty',
      );
    });
  });

  describe('clearAll', () => {
    it('should remove all blacklisted tokens', async () => {
      const tokens = [
        'token1.jwt.value',
        'token2.jwt.value',
        'token3.jwt.value',
      ];

      for (const token of tokens) {
        await service.blacklistToken(token, 900);
      }

      // Verify all are blacklisted
      for (const token of tokens) {
        expect(await service.isBlacklisted(token)).toBe(true);
      }

      await service.clearAll();

      // Verify all are removed
      for (const token of tokens) {
        expect(await service.isBlacklisted(token)).toBe(false);
      }
    });

    it('should not throw error when clearing empty blacklist', async () => {
      await expect(service.clearAll()).resolves.not.toThrow();
    });
  });

  describe('getBlacklistSize', () => {
    it('should return 0 for empty blacklist', async () => {
      expect(await service.getBlacklistSize()).toBe(0);
    });

    it('should return correct count of blacklisted tokens', async () => {
      const tokens = [
        'token1.jwt.value',
        'token2.jwt.value',
        'token3.jwt.value',
      ];

      for (const token of tokens) {
        await service.blacklistToken(token, 900);
      }

      expect(await service.getBlacklistSize()).toBe(3);
    });

    it('should not count expired tokens', async () => {
      await service.blacklistToken('token1', 900);
      await service.blacklistToken('token2', 1); // Will expire in 1 second

      expect(await service.getBlacklistSize()).toBe(2);

      // Wait for token2 to expire
      await new Promise((resolve) => setTimeout(resolve, 1100));

      expect(await service.getBlacklistSize()).toBe(1);
    });

    it('should update count when tokens are removed', async () => {
      await service.blacklistToken('token1', 900);
      await service.blacklistToken('token2', 900);

      expect(await service.getBlacklistSize()).toBe(2);

      await service.removeFromBlacklist('token1');

      expect(await service.getBlacklistSize()).toBe(1);
    });
  });

  describe('cleanupExpiredTokens', () => {
    it('should remove expired tokens from blacklist', async () => {
      // Add token that will expire
      await service.blacklistToken('expired-token', 1);
      // Add token that won't expire
      await service.blacklistToken('valid-token', 900);

      expect(await service.getBlacklistSize()).toBe(2);

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 1100));

      // Manually trigger cleanup
      await service.cleanupExpiredTokens();

      // Only valid token should remain
      expect(await service.getBlacklistSize()).toBe(1);
      expect(await service.isBlacklisted('expired-token')).toBe(false);
      expect(await service.isBlacklisted('valid-token')).toBe(true);
    });

    it('should not throw error when no expired tokens exist', async () => {
      await service.blacklistToken('valid-token', 900);

      await expect(service.cleanupExpiredTokens()).resolves.not.toThrow();
    });

    it('should handle cleanup of empty blacklist', async () => {
      await expect(service.cleanupExpiredTokens()).resolves.not.toThrow();
    });
  });

  describe('performance', () => {
    it('should blacklist token in less than 5ms', async () => {
      const token = 'performance.test.token';
      const start = Date.now();

      await service.blacklistToken(token, 900);

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(5);
    });

    it('should check blacklist in less than 5ms', async () => {
      const token = 'performance.test.token';
      await service.blacklistToken(token, 900);

      const start = Date.now();

      await service.isBlacklisted(token);

      const duration = Date.now() - start;
      expect(duration).toBeLessThan(5);
    });

    it('should handle 100 tokens without performance degradation', async () => {
      const tokens = Array.from({ length: 100 }, (_, i) => `token-${i}`);

      // Blacklist all tokens
      for (const token of tokens) {
        await service.blacklistToken(token, 900);
      }

      // Check each token - average should be less than 5ms
      const start = Date.now();
      for (const token of tokens) {
        await service.isBlacklisted(token);
      }
      const duration = Date.now() - start;
      const avgDuration = duration / tokens.length;

      expect(avgDuration).toBeLessThan(5);
    });
  });

  describe('security', () => {
    it('should use SHA-256 hashing for token storage', async () => {
      const token = 'security.test.token';
      const hashSpy = jest.spyOn(require('crypto'), 'createHash');

      await service.blacklistToken(token, 900);

      expect(hashSpy).toHaveBeenCalledWith('sha256');
    });

    it('should not expose original token in storage', async () => {
      const token = 'sensitive.jwt.token';
      await service.blacklistToken(token, 900);

      // Get internal storage (for testing purposes)
      const storage = (service as any).blacklist;
      const keys = Array.from(storage.keys());

      // No key should match the original token
      expect(keys).not.toContain(token);
    });

    it('should generate different hashes for different tokens', async () => {
      const token1 = 'token.one';
      const token2 = 'token.two';

      await service.blacklistToken(token1, 900);
      await service.blacklistToken(token2, 900);

      const storage = (service as any).blacklist;
      const keys = Array.from(storage.keys());

      // Should have two different hash keys
      expect(keys.length).toBe(2);
      expect(keys[0]).not.toBe(keys[1]);
    });
  });
});
