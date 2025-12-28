import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

/**
 * Service for validating secret strength and detecting default/weak secrets
 * Critical security component - prevents deployment with insecure secrets
 */
@Injectable()
export class SecretsValidationService {
  private static readonly DEFAULT_SECRETS = [
    'dev-jwt-secret-change-in-production',
    'dev-refresh-secret-change-in-production',
    'financial_rise_dev',
  ];

  private static readonly REQUIRED_SECRETS_DEV = ['JWT_SECRET', 'REFRESH_TOKEN_SECRET'];
  private static readonly REQUIRED_SECRETS_PROD = [
    'JWT_SECRET',
    'REFRESH_TOKEN_SECRET',
    'DATABASE_PASSWORD',
  ];

  constructor(private readonly configService: ConfigService) {}

  /**
   * Validates all application secrets meet security requirements
   * Throws error if any secret is missing, weak, or uses default value
   */
  validateSecrets(): void {
    const nodeEnv = this.configService.get<string>('NODE_ENV') || 'development';
    const isProduction = nodeEnv === 'production';

    // Validate JWT_SECRET
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    this.validateJwtSecret(jwtSecret, isProduction);

    // Validate REFRESH_TOKEN_SECRET
    const refreshSecret = this.configService.get<string>('REFRESH_TOKEN_SECRET');
    this.validateRefreshSecret(refreshSecret, isProduction);

    // Validate DATABASE_PASSWORD in production
    if (isProduction) {
      const dbPassword = this.configService.get<string>('DATABASE_PASSWORD');
      this.validateDatabasePassword(dbPassword);
    }

    console.log('✅ Secret validation passed - All secrets meet security requirements');
  }

  /**
   * Validates JWT_SECRET strength
   */
  private validateJwtSecret(secret: string | undefined, isProduction: boolean): void {
    if (!secret || secret.trim() === '') {
      throw new Error('JWT_SECRET is required and must not be empty');
    }

    if (secret.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters long');
    }

    if (SecretsValidationService.DEFAULT_SECRETS.includes(secret)) {
      throw new Error(
        'Default JWT_SECRET detected. This secret must be changed before deployment!'
      );
    }

    if (isProduction && secret.length < 64) {
      throw new Error('Production JWT_SECRET must be at least 64 characters');
    }
  }

  /**
   * Validates REFRESH_TOKEN_SECRET strength
   */
  private validateRefreshSecret(secret: string | undefined, isProduction: boolean): void {
    if (!secret || secret.trim() === '') {
      throw new Error('REFRESH_TOKEN_SECRET is required and must not be empty');
    }

    if (secret.length < 32) {
      throw new Error('REFRESH_TOKEN_SECRET must be at least 32 characters long');
    }

    if (SecretsValidationService.DEFAULT_SECRETS.includes(secret)) {
      throw new Error(
        'Default REFRESH_TOKEN_SECRET detected. This secret must be changed before deployment!'
      );
    }

    if (isProduction && secret.length < 64) {
      throw new Error('Production REFRESH_TOKEN_SECRET must be at least 64 characters');
    }
  }

  /**
   * Validates DATABASE_PASSWORD (production only)
   */
  private validateDatabasePassword(password: string | undefined): void {
    if (!password || password.trim() === '') {
      throw new Error('DATABASE_PASSWORD is required in production');
    }

    if (SecretsValidationService.DEFAULT_SECRETS.includes(password)) {
      throw new Error(
        'Default DATABASE_PASSWORD detected. This must be changed before production deployment!'
      );
    }

    if (password.length < 16) {
      throw new Error('DATABASE_PASSWORD must be at least 16 characters in production');
    }
  }

  /**
   * Generates a cryptographically secure random secret
   * @param bytes Number of random bytes (default 32 = 64 hex characters)
   * @returns Hexadecimal string suitable for use as JWT secret
   */
  static generateSecureSecret(bytes: number = 32): string {
    return crypto.randomBytes(bytes).toString('hex');
  }
}
