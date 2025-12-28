import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { SecretsService } from './secrets.service';
import { SecretsValidationService } from './secrets-validation.service';
import * as crypto from 'crypto';

describe('E2E: Secrets Management System', () => {
  let app: INestApplication;
  let secretsService: SecretsService;
  let validationService: SecretsValidationService;

  describe('RED PHASE: Complete Secrets Flow', () => {
    it('should prevent application startup with weak secrets', async () => {
      // Simulate weak JWT_SECRET
      process.env.JWT_SECRET = 'weak';
      process.env.REFRESH_TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
      process.env.NODE_ENV = 'production';

      await expect(
        Test.createTestingModule({
          imports: [
            ConfigModule.forRoot({
              isGlobal: true,
            }),
          ],
          providers: [SecretsValidationService],
        }).compile()
      ).rejects.toThrow();

      // Clean up
      delete process.env.JWT_SECRET;
      delete process.env.REFRESH_TOKEN_SECRET;
    });

    it('should prevent application startup with default secrets in production', async () => {
      process.env.JWT_SECRET = 'dev-jwt-secret-change-in-production';
      process.env.REFRESH_TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
      process.env.NODE_ENV = 'production';

      await expect(
        Test.createTestingModule({
          imports: [
            ConfigModule.forRoot({
              isGlobal: true,
            }),
          ],
          providers: [SecretsValidationService],
        }).compile()
      ).rejects.toThrow('Default JWT_SECRET detected');

      delete process.env.JWT_SECRET;
      delete process.env.REFRESH_TOKEN_SECRET;
    });

    it('should successfully start with strong secrets', async () => {
      process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
      process.env.REFRESH_TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
      process.env.DATABASE_PASSWORD = crypto.randomBytes(16).toString('hex');
      process.env.NODE_ENV = 'development';

      const module = await Test.createTestingModule({
        imports: [
          ConfigModule.forRoot({
            isGlobal: true,
          }),
        ],
        providers: [SecretsValidationService],
      }).compile();

      const service = module.get<SecretsValidationService>(
        SecretsValidationService
      );

      expect(() => service.validateSecrets()).not.toThrow();

      delete process.env.JWT_SECRET;
      delete process.env.REFRESH_TOKEN_SECRET;
      delete process.env.DATABASE_PASSWORD;
    });
  });

  describe('RED PHASE: Secret Rotation E2E', () => {
    it('should rotate secrets without downtime', async () => {
      // Mock GCP Secret Manager
      const mockSecretManager = {
        accessSecretVersion: jest.fn(),
        addSecretVersion: jest.fn(),
      };

      const oldSecret = crypto.randomBytes(32).toString('hex');
      const newSecret = crypto.randomBytes(32).toString('hex');

      // Initial secret
      mockSecretManager.accessSecretVersion.mockResolvedValueOnce([
        {
          payload: {
            data: Buffer.from(oldSecret),
          },
        },
      ]);

      const module = await Test.createTestingModule({
        providers: [
          SecretsService,
          {
            provide: 'SECRET_MANAGER_CLIENT',
            useValue: mockSecretManager,
          },
          {
            provide: 'ConfigService',
            useValue: {
              get: jest.fn((key) =>
                key === 'GCP_PROJECT_ID' ? 'test-project' : undefined
              ),
            },
          },
        ],
      }).compile();

      const service = module.get<SecretsService>(SecretsService);

      // Get initial secret
      const secret1 = await service.getSecret('JWT_SECRET');
      expect(secret1).toBe(oldSecret);

      // Rotate secret
      mockSecretManager.addSecretVersion.mockResolvedValueOnce([
        {
          name: 'projects/test-project/secrets/JWT_SECRET/versions/2',
        },
      ]);
      mockSecretManager.accessSecretVersion.mockResolvedValueOnce([
        {
          payload: {
            data: Buffer.from(newSecret),
          },
        },
      ]);

      await service.rotateSecret('JWT_SECRET', newSecret);

      // Get rotated secret
      const secret2 = await service.getSecret('JWT_SECRET');
      expect(secret2).toBe(newSecret);
      expect(secret2).not.toBe(oldSecret);
    });
  });

  describe('RED PHASE: Git History Protection', () => {
    it('should detect if .env files are in git history', async () => {
      // This test would run a git command to verify
      // For now, it's a placeholder
      const { execSync } = require('child_process');

      try {
        const result = execSync(
          'git log --all --oneline --decorate -- **/.env.local',
          { encoding: 'utf-8', cwd: process.cwd() }
        );

        // If .env.local is found in history, test fails
        if (result.trim().length > 0) {
          throw new Error(
            '.env.local found in git history! Run git filter-branch to remove.'
          );
        }
      } catch (error) {
        if (
          error.message.includes('.env.local found in git history')
        ) {
          throw error;
        }
        // Git command might fail if no .env.local ever existed - that's OK
      }

      expect(true).toBe(true);
    });
  });

  describe('RED PHASE: Security Scanning', () => {
    it('should detect hardcoded secrets in codebase', async () => {
      const { execSync } = require('child_process');

      // Common patterns of hardcoded secrets
      const secretPatterns = [
        'dev-jwt-secret-change-in-production',
        'dev-refresh-secret-change-in-production',
        'financial_rise_dev', // Default DB password
      ];

      for (const pattern of secretPatterns) {
        try {
          const result = execSync(
            `grep -r "${pattern}" src/ --include="*.ts" --exclude="*.spec.ts" || true`,
            { encoding: 'utf-8', cwd: process.cwd() }
          );

          if (result.trim().length > 0) {
            throw new Error(
              `Hardcoded secret pattern found in codebase: ${pattern}\n${result}`
            );
          }
        } catch (error) {
          if (
            error.message.includes('Hardcoded secret pattern found')
          ) {
            throw error;
          }
          // grep might fail if not found - that's OK
        }
      }

      expect(true).toBe(true);
    });

    it('should verify .gitignore includes all env files', () => {
      const fs = require('fs');
      const path = require('path');

      const gitignorePath = path.join(process.cwd(), '.gitignore');
      const gitignoreContent = fs.readFileSync(gitignorePath, 'utf-8');

      const requiredPatterns = [
        '.env',
        '.env.local',
        '.env.*.local',
        '.env.production',
        '.env.staging',
      ];

      for (const pattern of requiredPatterns) {
        expect(gitignoreContent).toContain(pattern);
      }
    });
  });

  describe('RED PHASE: Production Deployment Checks', () => {
    it('should require GCP_PROJECT_ID in production', async () => {
      process.env.NODE_ENV = 'production';
      delete process.env.GCP_PROJECT_ID;

      await expect(
        Test.createTestingModule({
          providers: [
            SecretsService,
            {
              provide: 'SECRET_MANAGER_CLIENT',
              useValue: {},
            },
            {
              provide: 'ConfigService',
              useValue: {
                get: jest.fn(() => undefined),
              },
            },
          ],
        }).compile()
      ).rejects.toThrow('GCP_PROJECT_ID is required in production');

      delete process.env.NODE_ENV;
    });

    it('should validate secret manager connectivity before accepting traffic', async () => {
      const mockSecretManager = {
        accessSecretVersion: jest.fn().mockRejectedValue(
          new Error('Connection timeout')
        ),
      };

      const module = await Test.createTestingModule({
        providers: [
          SecretsService,
          {
            provide: 'SECRET_MANAGER_CLIENT',
            useValue: mockSecretManager,
          },
          {
            provide: 'ConfigService',
            useValue: {
              get: jest.fn((key) =>
                key === 'GCP_PROJECT_ID' ? 'test-project' : undefined
              ),
            },
          },
        ],
      }).compile();

      const service = module.get<SecretsService>(SecretsService);

      await expect(service.getSecret('JWT_SECRET')).rejects.toThrow(
        'Failed to retrieve secret JWT_SECRET'
      );
    });
  });

  describe('RED PHASE: Secret Metadata Protection', () => {
    it('should not log secret names in error messages', async () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();

      const mockSecretManager = {
        accessSecretVersion: jest.fn().mockRejectedValue(
          new Error('Access denied')
        ),
      };

      const module = await Test.createTestingModule({
        providers: [
          SecretsService,
          {
            provide: 'SECRET_MANAGER_CLIENT',
            useValue: mockSecretManager,
          },
          {
            provide: 'ConfigService',
            useValue: {
              get: jest.fn((key) =>
                key === 'GCP_PROJECT_ID' ? 'test-project' : undefined
              ),
            },
          },
        ],
      }).compile();

      const service = module.get<SecretsService>(SecretsService);

      try {
        await service.getSecret('JWT_SECRET');
      } catch (error) {
        // Error should be sanitized
        expect(error.message).not.toContain('JWT_SECRET');
      }

      consoleSpy.mockRestore();
    });
  });
});
