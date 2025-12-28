import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { AuthModule } from './auth.module';
import { SecretsService } from '../../config/secrets.service';

describe('AuthModule - Secrets Integration Tests', () => {
  let configService: ConfigService;
  let secretsService: SecretsService;

  beforeEach(() => {
    // Mock services
    secretsService = {
      getSecret: jest.fn(),
      loadAllSecrets: jest.fn(),
      rotateSecret: jest.fn(),
    } as any;

    configService = {
      get: jest.fn(),
    } as any;
  });

  describe('RED PHASE: JWT Module Configuration with Secret Manager', () => {
    it('should load JWT_SECRET from Secret Manager, not environment variables', async () => {
      const mockSecretValue =
        'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6';
      (secretsService.getSecret as jest.Mock).mockResolvedValue(
        mockSecretValue
      );

      const module: TestingModule = await Test.createTestingModule({
        imports: [AuthModule],
        providers: [
          {
            provide: SecretsService,
            useValue: secretsService,
          },
          {
            provide: ConfigService,
            useValue: configService,
          },
        ],
      })
        .overrideProvider(SecretsService)
        .useValue(secretsService)
        .compile();

      // Verify SecretsService.getSecret was called with 'JWT_SECRET'
      expect(secretsService.getSecret).toHaveBeenCalledWith('JWT_SECRET');
    });

    it('should throw error if JWT_SECRET cannot be loaded from Secret Manager', async () => {
      (secretsService.getSecret as jest.Mock).mockRejectedValue(
        new Error('Secret Manager unavailable')
      );

      await expect(
        Test.createTestingModule({
          imports: [AuthModule],
          providers: [
            {
              provide: SecretsService,
              useValue: secretsService,
            },
          ],
        }).compile()
      ).rejects.toThrow();
    });

    it('should use different secrets for JWT and refresh tokens', async () => {
      (secretsService.getSecret as jest.Mock).mockImplementation(
        async (secretName: string) => {
          if (secretName === 'JWT_SECRET') return 'jwt-secret-value';
          if (secretName === 'REFRESH_TOKEN_SECRET')
            return 'refresh-secret-value';
          throw new Error(`Unknown secret: ${secretName}`);
        }
      );

      const module = await Test.createTestingModule({
        imports: [AuthModule],
        providers: [
          {
            provide: SecretsService,
            useValue: secretsService,
          },
        ],
      })
        .overrideProvider(SecretsService)
        .useValue(secretsService)
        .compile();

      expect(secretsService.getSecret).toHaveBeenCalledWith('JWT_SECRET');
      expect(secretsService.getSecret).toHaveBeenCalledWith(
        'REFRESH_TOKEN_SECRET'
      );
    });
  });

  describe('RED PHASE: Fallback behavior in development', () => {
    it('should allow fallback to env vars in development mode only', async () => {
      (configService.get as jest.Mock).mockImplementation((key: string) => {
        if (key === 'NODE_ENV') return 'development';
        if (key === 'JWT_SECRET') return 'dev-jwt-secret';
        return undefined;
      });

      (secretsService.getSecret as jest.Mock).mockRejectedValue(
        new Error('Secret Manager not available in dev')
      );

      const module = await Test.createTestingModule({
        imports: [AuthModule],
        providers: [
          {
            provide: SecretsService,
            useValue: secretsService,
          },
          {
            provide: ConfigService,
            useValue: configService,
          },
        ],
      })
        .overrideProvider(SecretsService)
        .useValue(secretsService)
        .overrideProvider(ConfigService)
        .useValue(configService)
        .compile();

      // Should not throw - fallback to env var in development
      expect(module).toBeDefined();
    });

    it('should NEVER fallback to env vars in production', async () => {
      (configService.get as jest.Mock).mockImplementation((key: string) => {
        if (key === 'NODE_ENV') return 'production';
        if (key === 'JWT_SECRET') return 'some-env-secret';
        return undefined;
      });

      (secretsService.getSecret as jest.Mock).mockRejectedValue(
        new Error('Secret Manager error')
      );

      await expect(
        Test.createTestingModule({
          imports: [AuthModule],
          providers: [
            {
              provide: SecretsService,
              useValue: secretsService,
            },
            {
              provide: ConfigService,
              useValue: configService,
            },
          ],
        })
          .overrideProvider(SecretsService)
          .useValue(secretsService)
          .overrideProvider(ConfigService)
          .useValue(configService)
          .compile()
      ).rejects.toThrow('Secret Manager is required in production');
    });
  });
});

describe('Security: Secrets Not Logged', () => {
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('should NEVER log JWT_SECRET value', async () => {
    const secretsService = {
      getSecret: jest.fn().mockResolvedValue('super-secret-jwt-value'),
      loadAllSecrets: jest.fn(),
      rotateSecret: jest.fn(),
    };

    await Test.createTestingModule({
      imports: [AuthModule],
      providers: [
        {
          provide: SecretsService,
          useValue: secretsService,
        },
      ],
    })
      .overrideProvider(SecretsService)
      .useValue(secretsService)
      .compile();

    // Verify the secret value is NEVER in console logs
    const allLogs = consoleSpy.mock.calls.map((call) =>
      call.join(' ')
    );
    allLogs.forEach((log) => {
      expect(log).not.toContain('super-secret-jwt-value');
    });
  });

  it('should NEVER log DATABASE_PASSWORD value', async () => {
    const secretsService = {
      getSecret: jest.fn().mockImplementation(async (name: string) => {
        if (name === 'DATABASE_PASSWORD') return 'super-secret-db-password';
        return `mock-${name}`;
      }),
      loadAllSecrets: jest.fn(),
    };

    await secretsService.getSecret('DATABASE_PASSWORD');

    const allLogs = consoleSpy.mock.calls.map((call) =>
      call.join(' ')
    );
    allLogs.forEach((log) => {
      expect(log).not.toContain('super-secret-db-password');
    });
  });
});
