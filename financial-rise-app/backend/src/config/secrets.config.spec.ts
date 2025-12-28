import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { SecretsService } from './secrets.service';
import { SecretsValidationService } from './secrets-validation.service';

describe('SecretsValidationService', () => {
  let service: SecretsValidationService;
  let configService: ConfigService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecretsValidationService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<SecretsValidationService>(SecretsValidationService);
    configService = module.get<ConfigService>(ConfigService);
  });

  describe('RED PHASE: validateSecretStrength', () => {
    it('should throw error if JWT_SECRET is undefined', () => {
      jest.spyOn(configService, 'get').mockReturnValue(undefined);

      expect(() => service.validateSecrets()).toThrow(
        'JWT_SECRET is required and must not be empty'
      );
    });

    it('should throw error if JWT_SECRET is empty string', () => {
      jest.spyOn(configService, 'get').mockReturnValue('');

      expect(() => service.validateSecrets()).toThrow(
        'JWT_SECRET is required and must not be empty'
      );
    });

    it('should throw error if JWT_SECRET is less than 32 characters', () => {
      jest.spyOn(configService, 'get').mockReturnValue('short-secret-12345');

      expect(() => service.validateSecrets()).toThrow(
        'JWT_SECRET must be at least 32 characters long'
      );
    });

    it('should throw error if JWT_SECRET is the default development value', () => {
      jest
        .spyOn(configService, 'get')
        .mockReturnValue('dev-jwt-secret-change-in-production');

      expect(() => service.validateSecrets()).toThrow(
        'Default JWT_SECRET detected. This secret must be changed before deployment!'
      );
    });

    it('should throw error if REFRESH_TOKEN_SECRET is default value', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(64);
        if (key === 'REFRESH_TOKEN_SECRET')
          return 'dev-refresh-secret-change-in-production';
        if (key === 'NODE_ENV') return 'production';
        return undefined;
      });

      expect(() => service.validateSecrets()).toThrow(
        'Default REFRESH_TOKEN_SECRET detected'
      );
    });

    it('should throw error if production JWT_SECRET is less than 64 characters', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(40);
        if (key === 'REFRESH_TOKEN_SECRET') return 'b'.repeat(64);
        if (key === 'NODE_ENV') return 'production';
        return undefined;
      });

      expect(() => service.validateSecrets()).toThrow(
        'Production JWT_SECRET must be at least 64 characters'
      );
    });

    it('should NOT throw if JWT_SECRET is valid (32+ chars, not default)', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(32);
        if (key === 'REFRESH_TOKEN_SECRET') return 'b'.repeat(32);
        if (key === 'NODE_ENV') return 'development';
        return undefined;
      });

      expect(() => service.validateSecrets()).not.toThrow();
    });

    it('should NOT throw if production secrets are valid (64+ chars)', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(64);
        if (key === 'REFRESH_TOKEN_SECRET') return 'b'.repeat(64);
        if (key === 'NODE_ENV') return 'production';
        if (key === 'DATABASE_PASSWORD') return 'c'.repeat(32);
        return undefined;
      });

      expect(() => service.validateSecrets()).not.toThrow();
    });

    it('should throw error if DATABASE_PASSWORD is missing in production', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(64);
        if (key === 'REFRESH_TOKEN_SECRET') return 'b'.repeat(64);
        if (key === 'NODE_ENV') return 'production';
        if (key === 'DATABASE_PASSWORD') return undefined;
        return undefined;
      });

      expect(() => service.validateSecrets()).toThrow(
        'DATABASE_PASSWORD is required in production'
      );
    });

    it('should throw error if DATABASE_PASSWORD is default value', () => {
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(64);
        if (key === 'REFRESH_TOKEN_SECRET') return 'b'.repeat(64);
        if (key === 'NODE_ENV') return 'production';
        if (key === 'DATABASE_PASSWORD') return 'financial_rise_dev';
        return undefined;
      });

      expect(() => service.validateSecrets()).toThrow(
        'Default DATABASE_PASSWORD detected'
      );
    });

    it('should log validation success when all secrets are valid', () => {
      const logSpy = jest.spyOn(console, 'log').mockImplementation();
      jest.spyOn(configService, 'get').mockImplementation((key: string) => {
        if (key === 'JWT_SECRET') return 'a'.repeat(64);
        if (key === 'REFRESH_TOKEN_SECRET') return 'b'.repeat(64);
        if (key === 'NODE_ENV') return 'production';
        if (key === 'DATABASE_PASSWORD') return 'secure-password-123';
        return undefined;
      });

      service.validateSecrets();

      expect(logSpy).toHaveBeenCalledWith(
        expect.stringContaining('Secret validation passed')
      );

      logSpy.mockRestore();
    });
  });

  describe('RED PHASE: generateSecureSecret', () => {
    it('should generate a secret of default length (32 bytes = 64 hex chars)', () => {
      const secret = SecretsValidationService.generateSecureSecret();

      expect(secret).toHaveLength(64);
      expect(secret).toMatch(/^[a-f0-9]{64}$/);
    });

    it('should generate a secret of custom length', () => {
      const secret = SecretsValidationService.generateSecureSecret(16);

      expect(secret).toHaveLength(32); // 16 bytes = 32 hex chars
      expect(secret).toMatch(/^[a-f0-9]{32}$/);
    });

    it('should generate unique secrets on each call', () => {
      const secret1 = SecretsValidationService.generateSecureSecret();
      const secret2 = SecretsValidationService.generateSecureSecret();

      expect(secret1).not.toBe(secret2);
    });
  });
});

describe('SecretsService (GCP Secret Manager Integration)', () => {
  let service: SecretsService;
  let mockSecretManagerClient: any;

  beforeEach(async () => {
    // Mock GCP Secret Manager client
    mockSecretManagerClient = {
      accessSecretVersion: jest.fn(),
      createSecret: jest.fn(),
      addSecretVersion: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecretsService,
        {
          provide: 'SECRET_MANAGER_CLIENT',
          useValue: mockSecretManagerClient,
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'GCP_PROJECT_ID') return 'test-project';
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<SecretsService>(SecretsService);
  });

  describe('RED PHASE: getSecret', () => {
    it('should retrieve secret from GCP Secret Manager', async () => {
      const mockPayload = Buffer.from('test-secret-value').toString('base64');
      mockSecretManagerClient.accessSecretVersion.mockResolvedValue([
        {
          payload: {
            data: Buffer.from('test-secret-value'),
          },
        },
      ]);

      const result = await service.getSecret('JWT_SECRET');

      expect(result).toBe('test-secret-value');
      expect(mockSecretManagerClient.accessSecretVersion).toHaveBeenCalledWith({
        name: 'projects/test-project/secrets/JWT_SECRET/versions/latest',
      });
    });

    it('should throw error if secret does not exist', async () => {
      mockSecretManagerClient.accessSecretVersion.mockRejectedValue(
        new Error('Secret not found')
      );

      await expect(service.getSecret('NONEXISTENT_SECRET')).rejects.toThrow(
        'Failed to retrieve secret NONEXISTENT_SECRET'
      );
    });

    it('should cache secret after first retrieval', async () => {
      mockSecretManagerClient.accessSecretVersion.mockResolvedValue([
        {
          payload: {
            data: Buffer.from('cached-secret'),
          },
        },
      ]);

      // First call
      await service.getSecret('JWT_SECRET');
      // Second call
      await service.getSecret('JWT_SECRET');

      // Should only call GCP once due to caching
      expect(mockSecretManagerClient.accessSecretVersion).toHaveBeenCalledTimes(
        1
      );
    });
  });

  describe('RED PHASE: loadAllSecrets', () => {
    it('should load all required secrets on application startup', async () => {
      mockSecretManagerClient.accessSecretVersion.mockImplementation(
        async ({ name }: { name: string }) => {
          const secretName = name.split('/')[3];
          return [
            {
              payload: {
                data: Buffer.from(`${secretName}-value`),
              },
            },
          ];
        }
      );

      const secrets = await service.loadAllSecrets();

      expect(secrets).toHaveProperty('JWT_SECRET');
      expect(secrets).toHaveProperty('REFRESH_TOKEN_SECRET');
      expect(secrets).toHaveProperty('DATABASE_PASSWORD');
      expect(secrets.JWT_SECRET).toBe('JWT_SECRET-value');
    });

    it('should throw error if any required secret is missing', async () => {
      mockSecretManagerClient.accessSecretVersion.mockImplementation(
        async ({ name }: { name: string }) => {
          const secretName = name.split('/')[3];
          if (secretName === 'REFRESH_TOKEN_SECRET') {
            throw new Error('Secret not found');
          }
          return [
            {
              payload: {
                data: Buffer.from(`${secretName}-value`),
              },
            },
          ];
        }
      );

      await expect(service.loadAllSecrets()).rejects.toThrow(
        'Failed to load required secrets'
      );
    });
  });

  describe('RED PHASE: rotateSecret', () => {
    it('should create new version of existing secret', async () => {
      const newSecretValue = 'new-rotated-secret-value';
      mockSecretManagerClient.addSecretVersion.mockResolvedValue([
        {
          name: 'projects/test-project/secrets/JWT_SECRET/versions/2',
        },
      ]);

      await service.rotateSecret('JWT_SECRET', newSecretValue);

      expect(mockSecretManagerClient.addSecretVersion).toHaveBeenCalledWith({
        parent: 'projects/test-project/secrets/JWT_SECRET',
        payload: {
          data: Buffer.from(newSecretValue),
        },
      });
    });

    it('should clear cache after rotation', async () => {
      mockSecretManagerClient.accessSecretVersion.mockResolvedValue([
        {
          payload: {
            data: Buffer.from('old-secret'),
          },
        },
      ]);
      mockSecretManagerClient.addSecretVersion.mockResolvedValue([
        {
          name: 'projects/test-project/secrets/JWT_SECRET/versions/2',
        },
      ]);

      // Load secret (gets cached)
      await service.getSecret('JWT_SECRET');

      // Rotate secret (should clear cache)
      await service.rotateSecret('JWT_SECRET', 'new-secret');

      // Next access should fetch new version
      mockSecretManagerClient.accessSecretVersion.mockResolvedValue([
        {
          payload: {
            data: Buffer.from('new-secret'),
          },
        },
      ]);

      const newSecret = await service.getSecret('JWT_SECRET');
      expect(newSecret).toBe('new-secret');
    });
  });
});

describe('Integration: Secrets Management with Auth Module', () => {
  it('should use secrets from Secret Manager in JWT module', async () => {
    // This will be implemented as an integration test
    // Testing that auth.module.ts correctly uses SecretsService
    expect(true).toBe(true); // Placeholder
  });

  it('should validate secrets on application bootstrap', async () => {
    // This will test that main.ts calls validateSecrets before starting
    expect(true).toBe(true); // Placeholder
  });
});
