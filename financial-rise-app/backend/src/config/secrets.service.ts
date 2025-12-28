import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';

/**
 * Service for loading secrets from GCP Secret Manager
 * Provides caching and secret rotation capabilities
 */
@Injectable()
export class SecretsService {
  private secretCache: Map<string, string> = new Map();

  private static readonly REQUIRED_SECRETS = [
    'JWT_SECRET',
    'REFRESH_TOKEN_SECRET',
    'DATABASE_PASSWORD',
  ];

  constructor(
    @Inject('SECRET_MANAGER_CLIENT')
    private readonly secretManager: SecretManagerServiceClient,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Retrieves a secret from GCP Secret Manager
   * Caches the result for performance
   */
  async getSecret(secretName: string): Promise<string> {
    // Check cache first
    if (this.secretCache.has(secretName)) {
      return this.secretCache.get(secretName)!;
    }

    try {
      const projectId = this.configService.get<string>('GCP_PROJECT_ID');
      const name = `projects/${projectId}/secrets/${secretName}/versions/latest`;

      const [version] = await this.secretManager.accessSecretVersion({ name });
      const secretValue = version.payload?.data?.toString() || '';

      // Cache the secret
      this.secretCache.set(secretName, secretValue);

      return secretValue;
    } catch (error) {
      throw new Error(
        `Failed to retrieve secret ${secretName}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Loads all required secrets on application startup
   * Throws error if any required secret is missing
   */
  async loadAllSecrets(): Promise<Record<string, string>> {
    const secrets: Record<string, string> = {};

    try {
      for (const secretName of SecretsService.REQUIRED_SECRETS) {
        secrets[secretName] = await this.getSecret(secretName);
      }

      return secrets;
    } catch (error) {
      throw new Error(
        `Failed to load required secrets: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }

  /**
   * Rotates a secret by creating a new version in GCP Secret Manager
   * Clears cache to force reload of new value
   */
  async rotateSecret(secretName: string, newValue: string): Promise<void> {
    try {
      const projectId = this.configService.get<string>('GCP_PROJECT_ID');
      const parent = `projects/${projectId}/secrets/${secretName}`;

      await this.secretManager.addSecretVersion({
        parent,
        payload: {
          data: Buffer.from(newValue),
        },
      });

      // Clear cache to force reload
      this.secretCache.delete(secretName);
    } catch (error) {
      throw new Error(
        `Failed to rotate secret ${secretName}: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
    }
  }
}
