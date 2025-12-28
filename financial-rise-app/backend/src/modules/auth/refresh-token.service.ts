import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { RefreshToken } from './entities/refresh-token.entity';
import * as bcrypt from 'bcrypt';

/**
 * RefreshTokenService
 *
 * Manages refresh tokens stored in the database.
 * Supports multiple devices per user and token revocation.
 */
@Injectable()
export class RefreshTokenService {
  constructor(
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
  ) {}

  /**
   * Creates and stores a new refresh token
   * @param userId - User ID
   * @param token - Raw refresh token (will be hashed before storing)
   * @param expiresAt - Expiration date
   * @param deviceInfo - Optional device information
   * @param ipAddress - Optional IP address
   */
  async createToken(
    userId: string,
    token: string,
    expiresAt: Date,
    deviceInfo?: string,
    ipAddress?: string,
  ): Promise<RefreshToken> {
    // Hash the token before storing for security
    const hashedToken = await bcrypt.hash(token, 10);

    const refreshToken = this.refreshTokenRepository.create({
      userId,
      token: hashedToken,
      expiresAt,
      deviceInfo,
      ipAddress,
    });

    return this.refreshTokenRepository.save(refreshToken);
  }

  /**
   * Finds a valid refresh token by comparing with stored hashed tokens
   * @param userId - User ID
   * @param token - Raw refresh token to verify
   * @returns RefreshToken if found and valid, null otherwise
   */
  async findValidToken(userId: string, token: string): Promise<RefreshToken | null> {
    // Get all non-revoked, non-expired tokens for this user
    const tokens = await this.refreshTokenRepository.find({
      where: {
        userId,
        revokedAt: null as any,
      },
    });

    // Check each token to find a match (since tokens are hashed)
    for (const storedToken of tokens) {
      // Skip if expired
      if (new Date() > storedToken.expiresAt) {
        continue;
      }

      // Compare hashed tokens
      const isMatch = await bcrypt.compare(token, storedToken.token);
      if (isMatch) {
        return storedToken;
      }
    }

    return null;
  }

  /**
   * Revokes a specific refresh token
   * @param tokenId - Token ID to revoke
   */
  async revokeToken(tokenId: string): Promise<void> {
    await this.refreshTokenRepository.update(tokenId, {
      revokedAt: new Date(),
    });
  }

  /**
   * Revokes all refresh tokens for a user
   * Useful when user changes password or logs out from all devices
   * @param userId - User ID
   */
  async revokeAllUserTokens(userId: string): Promise<void> {
    await this.refreshTokenRepository.update(
      { userId, revokedAt: null as any },
      { revokedAt: new Date() },
    );
  }

  /**
   * Gets all active (non-revoked, non-expired) tokens for a user
   * Useful for displaying active sessions
   * @param userId - User ID
   */
  async getActiveTokens(userId: string): Promise<RefreshToken[]> {
    return this.refreshTokenRepository.find({
      where: {
        userId,
        revokedAt: null as any,
      },
      order: {
        createdAt: 'DESC',
      },
    });
  }

  /**
   * Deletes all expired and revoked tokens (cleanup task)
   * Should be run periodically (e.g., daily cron job)
   */
  async cleanupExpiredTokens(): Promise<number> {
    const result = await this.refreshTokenRepository.delete({
      expiresAt: LessThan(new Date()),
    });

    // Also delete revoked tokens older than 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const revokedResult = await this.refreshTokenRepository
      .createQueryBuilder()
      .delete()
      .where('revoked_at < :date', { date: thirtyDaysAgo })
      .execute();

    return (result.affected || 0) + (revokedResult.affected || 0);
  }

  /**
   * Counts active sessions for a user
   * @param userId - User ID
   */
  async countActiveSessions(userId: string): Promise<number> {
    return this.refreshTokenRepository.count({
      where: {
        userId,
        revokedAt: null as any,
      },
    });
  }
}
