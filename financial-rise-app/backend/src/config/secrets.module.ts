import { Module, Global, OnModuleInit } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { SecretsService } from './secrets.service';
import { SecretsValidationService } from './secrets-validation.service';

/**
 * Global module for secrets management
 * Provides SecretManagerServiceClient, SecretsService, and SecretsValidationService
 *
 * Security Features:
 * - Validates secrets on application startup
 * - Integrates with GCP Secret Manager
 * - Provides caching for performance
 * - Supports secret rotation
 */
@Global()
@Module({
  imports: [ConfigModule],
  providers: [
    // Provide GCP Secret Manager client
    {
      provide: 'SECRET_MANAGER_CLIENT',
      useFactory: (configService: ConfigService) => {
        const nodeEnv = configService.get<string>('NODE_ENV', 'development');

        // In production, require GCP_PROJECT_ID
        if (nodeEnv === 'production') {
          const projectId = configService.get<string>('GCP_PROJECT_ID');
          if (!projectId) {
            throw new Error(
              'GCP_PROJECT_ID is required in production for Secret Manager integration'
            );
          }
        }

        // Create Secret Manager client
        // In development, this may fail gracefully if GCP is not configured
        return new SecretManagerServiceClient();
      },
      inject: [ConfigService],
    },
    SecretsService,
    SecretsValidationService,
  ],
  exports: [SecretsService, SecretsValidationService, 'SECRET_MANAGER_CLIENT'],
})
export class SecretsModule implements OnModuleInit {
  constructor(
    private readonly validationService: SecretsValidationService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Validate secrets when module initializes
   * This runs before the application starts accepting requests
   */
  onModuleInit() {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');

    console.log(`[SecretsModule] Initializing in ${nodeEnv} mode`);

    // Always validate secrets on startup
    try {
      this.validationService.validateSecrets();
    } catch (error) {
      console.error('[SecretsModule] Secret validation failed!');
      console.error(error instanceof Error ? error.message : 'Unknown error');
      throw error; // Prevent application startup
    }
  }
}
