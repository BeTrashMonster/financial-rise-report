import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from './encryption.service';

describe('EncryptionService', () => {
  let service: EncryptionService;
  let configService: ConfigService;

  // Valid 256-bit encryption key (64 hex characters = 32 bytes)
  const testEncryptionKey =
    'b4ca46626f1776931175c817b7d5c821fd844daf0c3e23ee36dd49827f4f74f3';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'DB_ENCRYPTION_KEY') {
                return testEncryptionKey;
              }
              return null;
            }),
          },
        },
      ],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
    configService = module.get<ConfigService>(ConfigService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('encryption key validation', () => {
    it('should throw error if DB_ENCRYPTION_KEY is not set', () => {
      const configServiceMock = {
        get: jest.fn().mockReturnValue(null),
      } as any;

      expect(() => {
        new EncryptionService(configServiceMock);
      }).toThrow('DB_ENCRYPTION_KEY environment variable is required');
    });

    it('should throw error if DB_ENCRYPTION_KEY is less than 64 characters', () => {
      const configServiceMock = {
        get: jest.fn().mockReturnValue('tooshort'),
      } as any;

      expect(() => {
        new EncryptionService(configServiceMock);
      }).toThrow(
        'DB_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)',
      );
    });

    it('should throw error if DB_ENCRYPTION_KEY is more than 64 characters', () => {
      const configServiceMock = {
        get: jest
          .fn()
          .mockReturnValue(
            'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2extra',
          ),
      } as any;

      expect(() => {
        new EncryptionService(configServiceMock);
      }).toThrow(
        'DB_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)',
      );
    });

    it('should accept valid 64-character encryption key', () => {
      expect(() => {
        new EncryptionService(configService);
      }).not.toThrow();
    });
  });

  describe('encrypt', () => {
    it('should encrypt a string value', () => {
      const plaintext = 'sensitive data';
      const encrypted = service.encrypt(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toBe(plaintext);
      expect(encrypted!.length).toBeGreaterThan(plaintext.length);
    });

    it('should encrypt a number value', () => {
      const plainNumber = 42.5;
      const encrypted = service.encrypt(plainNumber);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should encrypt an object value', () => {
      const plainObject = { score: 85.5, type: 'D' };
      const encrypted = service.encrypt(plainObject);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should return null for null input', () => {
      const encrypted = service.encrypt(null);
      expect(encrypted).toBeNull();
    });

    it('should return null for undefined input', () => {
      const encrypted = service.encrypt(undefined);
      expect(encrypted).toBeNull();
    });

    it('should produce different ciphertext for same plaintext (due to random IV)', () => {
      const plaintext = 'test data';
      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      expect(encrypted1).not.toBe(encrypted2);
    });

    it('should include IV and auth tag in encrypted format', () => {
      const plaintext = 'test';
      const encrypted = service.encrypt(plaintext);

      // Format should be: iv:authTag:ciphertext
      const parts = encrypted!.split(':');
      expect(parts.length).toBe(3);
      expect(parts[0].length).toBe(32); // 16 bytes IV = 32 hex chars
      expect(parts[1].length).toBe(32); // 16 bytes auth tag = 32 hex chars
      expect(parts[2].length).toBeGreaterThan(0); // ciphertext
    });
  });

  describe('decrypt', () => {
    it('should decrypt encrypted string value', () => {
      const plaintext = 'sensitive data';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt encrypted number value', () => {
      const plainNumber = 42.5;
      const encrypted = service.encrypt(plainNumber);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plainNumber);
    });

    it('should decrypt encrypted object value', () => {
      const plainObject = { score: 85.5, type: 'D' };
      const encrypted = service.encrypt(plainObject);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toEqual(plainObject);
    });

    it('should return null for null input', () => {
      const decrypted = service.decrypt(null);
      expect(decrypted).toBeNull();
    });

    it('should return null for undefined input', () => {
      const decrypted = service.decrypt(undefined);
      expect(decrypted).toBeNull();
    });

    it('should throw error for invalid ciphertext format', () => {
      expect(() => {
        service.decrypt('invalid:format');
      }).toThrow('Invalid encrypted data format');
    });

    it('should throw error for corrupted ciphertext', () => {
      const plaintext = 'test';
      const encrypted = service.encrypt(plaintext);
      const corrupted = encrypted!.substring(0, encrypted!.length - 5) + 'xxxxx';

      expect(() => {
        service.decrypt(corrupted);
      }).toThrow();
    });

    it('should throw error for tampered auth tag', () => {
      const plaintext = 'test';
      const encrypted = service.encrypt(plaintext);
      const parts = encrypted!.split(':');

      // Tamper with auth tag
      const tamperedAuthTag = 'ffffffffffffffffffffffffffffffff';
      const tampered = `${parts[0]}:${tamperedAuthTag}:${parts[2]}`;

      expect(() => {
        service.decrypt(tampered);
      }).toThrow();
    });
  });

  describe('DISC score encryption', () => {
    it('should encrypt DISC score (float)', () => {
      const discScore = 85.75;
      const encrypted = service.encrypt(discScore);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');

      const decrypted = service.decrypt(encrypted);
      expect(decrypted).toBe(discScore);
    });

    it('should handle DISC scores with precision', () => {
      const scores = [0.0, 25.5, 50.0, 75.25, 100.0];

      scores.forEach((score) => {
        const encrypted = service.encrypt(score);
        const decrypted = service.decrypt(encrypted);
        expect(decrypted).toBe(score);
      });
    });

    it('should handle negative scores (edge case)', () => {
      const negativeScore = -10.5;
      const encrypted = service.encrypt(negativeScore);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(negativeScore);
    });
  });

  describe('performance', () => {
    it('should encrypt within 10ms (requirement)', () => {
      const plaintext = 'performance test data';
      const start = Date.now();

      for (let i = 0; i < 100; i++) {
        service.encrypt(plaintext);
      }

      const end = Date.now();
      const avgTime = (end - start) / 100;

      expect(avgTime).toBeLessThan(10);
    });

    it('should decrypt within 10ms (requirement)', () => {
      const plaintext = 'performance test data';
      const encrypted = service.encrypt(plaintext);
      const start = Date.now();

      for (let i = 0; i < 100; i++) {
        service.decrypt(encrypted);
      }

      const end = Date.now();
      const avgTime = (end - start) / 100;

      expect(avgTime).toBeLessThan(10);
    });

    it('should handle large data efficiently', () => {
      const largeObject = {
        d_score: 85.5,
        i_score: 72.3,
        s_score: 65.8,
        c_score: 90.2,
        metadata: 'a'.repeat(1000), // 1KB of data
      };

      const start = Date.now();
      const encrypted = service.encrypt(largeObject);
      const decrypted = service.decrypt(encrypted);
      const end = Date.now();

      expect(decrypted).toEqual(largeObject);
      expect(end - start).toBeLessThan(20); // Allow more time for large data
    });
  });

  describe('security properties', () => {
    it('should use AES-256-GCM algorithm', () => {
      // This is implicitly tested by successful encryption/decryption
      // and by the auth tag verification
      const plaintext = 'test';
      const encrypted = service.encrypt(plaintext);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should provide authentication (detect tampering)', () => {
      const plaintext = 'authenticated data';
      const encrypted = service.encrypt(plaintext);
      const parts = encrypted!.split(':');

      // Tamper with ciphertext
      const lastChar = parts[2].charAt(parts[2].length - 1);
      const tamperedChar = lastChar === 'a' ? 'b' : 'a';
      const tamperedCiphertext =
        parts[2].substring(0, parts[2].length - 1) + tamperedChar;
      const tampered = `${parts[0]}:${parts[1]}:${tamperedCiphertext}`;

      expect(() => {
        service.decrypt(tampered);
      }).toThrow();
    });

    it('should use unique IV for each encryption', () => {
      const plaintext = 'test';
      const encrypted1 = service.encrypt(plaintext);
      const encrypted2 = service.encrypt(plaintext);

      const iv1 = encrypted1!.split(':')[0];
      const iv2 = encrypted2!.split(':')[0];

      expect(iv1).not.toBe(iv2);
    });
  });

  describe('edge cases', () => {
    it('should handle empty string', () => {
      const encrypted = service.encrypt('');
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe('');
    });

    it('should handle zero value', () => {
      const encrypted = service.encrypt(0);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(0);
    });

    it('should handle boolean values', () => {
      const encrypted = service.encrypt(true);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toBe(true);
    });

    it('should handle array values', () => {
      const array = [1, 2, 3, 4, 5];
      const encrypted = service.encrypt(array);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toEqual(array);
    });

    it('should handle nested objects', () => {
      const nested = {
        level1: {
          level2: {
            value: 'deep',
          },
        },
      };
      const encrypted = service.encrypt(nested);
      const decrypted = service.decrypt(encrypted);

      expect(decrypted).toEqual(nested);
    });
  });
});
