import {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  getTokenExpirationDate,
  AccessTokenPayload,
  RefreshTokenPayload
} from '../../../src/utils/jwt';
import { UserRole } from '../../../src/database/entities/User';

// Set test environment variables
process.env.JWT_SECRET = 'test-secret-key-minimum-32-characters-long';
process.env.JWT_REFRESH_SECRET = 'test-refresh-secret-key-minimum-32-characters';
process.env.ACCESS_TOKEN_EXPIRY = '15m';
process.env.REFRESH_TOKEN_EXPIRY = '7d';

describe('JWT Utilities', () => {
  describe('createAccessToken and verifyAccessToken', () => {
    it('should create and verify access token successfully', () => {
      const payload: AccessTokenPayload = {
        userId: '123e4567-e89b-12d3-a456-426614174000',
        email: 'test@example.com',
        role: UserRole.CONSULTANT
      };

      const token = createAccessToken(payload);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      const decoded = verifyAccessToken(token);
      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.email).toBe(payload.email);
      expect(decoded.role).toBe(payload.role);
    });

    it('should throw error for invalid token', () => {
      expect(() => {
        verifyAccessToken('invalid-token');
      }).toThrow('Invalid access token');
    });

    it('should throw error for tampered token', () => {
      const payload: AccessTokenPayload = {
        userId: '123e4567-e89b-12d3-a456-426614174000',
        email: 'test@example.com',
        role: UserRole.CONSULTANT
      };

      const token = createAccessToken(payload);
      const tamperedToken = token.slice(0, -5) + 'xxxxx';

      expect(() => {
        verifyAccessToken(tamperedToken);
      }).toThrow('Invalid access token');
    });
  });

  describe('createRefreshToken and verifyRefreshToken', () => {
    it('should create and verify refresh token successfully', () => {
      const payload: RefreshTokenPayload = {
        userId: '123e4567-e89b-12d3-a456-426614174000',
        tokenId: '987fcdeb-51a2-43f7-b123-456789abcdef'
      };

      const token = createRefreshToken(payload);
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');

      const decoded = verifyRefreshToken(token);
      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.tokenId).toBe(payload.tokenId);
    });

    it('should throw error for invalid refresh token', () => {
      expect(() => {
        verifyRefreshToken('invalid-refresh-token');
      }).toThrow('Invalid refresh token');
    });
  });

  describe('getTokenExpirationDate', () => {
    it('should calculate expiration for minutes', () => {
      const now = new Date();
      const expiry = getTokenExpirationDate('15m');

      const expectedTime = now.getTime() + 15 * 60 * 1000;
      const actualTime = expiry.getTime();

      expect(Math.abs(actualTime - expectedTime)).toBeLessThan(1000); // Within 1 second
    });

    it('should calculate expiration for hours', () => {
      const now = new Date();
      const expiry = getTokenExpirationDate('2h');

      const expectedTime = now.getTime() + 2 * 60 * 60 * 1000;
      const actualTime = expiry.getTime();

      expect(Math.abs(actualTime - expectedTime)).toBeLessThan(1000);
    });

    it('should calculate expiration for days', () => {
      const now = new Date();
      const expiry = getTokenExpirationDate('7d');

      const expectedTime = now.getTime() + 7 * 24 * 60 * 60 * 1000;
      const actualTime = expiry.getTime();

      expect(Math.abs(actualTime - expectedTime)).toBeLessThan(1000);
    });

    it('should throw error for invalid expiry unit', () => {
      expect(() => {
        getTokenExpirationDate('5x');
      }).toThrow('Invalid expiry unit: x');
    });
  });
});
