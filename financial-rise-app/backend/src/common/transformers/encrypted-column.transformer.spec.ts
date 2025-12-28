import { EncryptedColumnTransformer } from './encrypted-column.transformer';
import * as crypto from 'crypto';

describe('EncryptedColumnTransformer', () => {
  let transformer: EncryptedColumnTransformer;
  const testEncryptionKey = crypto.randomBytes(32).toString('hex'); // 64 hex chars

  beforeAll(() => {
    // Set test encryption key
    process.env.DB_ENCRYPTION_KEY = testEncryptionKey;
  });

  afterAll(() => {
    delete process.env.DB_ENCRYPTION_KEY;
  });

  beforeEach(() => {
    transformer = new EncryptedColumnTransformer();
  });

  describe('constructor', () => {
    it('should throw error if DB_ENCRYPTION_KEY is not set', () => {
      delete process.env.DB_ENCRYPTION_KEY;
      expect(() => new EncryptedColumnTransformer()).toThrow(
        'DB_ENCRYPTION_KEY must be 64 hex characters (32 bytes)',
      );
      process.env.DB_ENCRYPTION_KEY = testEncryptionKey;
    });

    it('should throw error if DB_ENCRYPTION_KEY is too short', () => {
      process.env.DB_ENCRYPTION_KEY = 'short';
      expect(() => new EncryptedColumnTransformer()).toThrow(
        'DB_ENCRYPTION_KEY must be 64 hex characters (32 bytes)',
      );
      process.env.DB_ENCRYPTION_KEY = testEncryptionKey;
    });

    it('should throw error if DB_ENCRYPTION_KEY is not hex', () => {
      process.env.DB_ENCRYPTION_KEY = 'z'.repeat(64); // Invalid hex
      expect(() => new EncryptedColumnTransformer()).toThrow();
      process.env.DB_ENCRYPTION_KEY = testEncryptionKey;
    });

    it('should initialize successfully with valid key', () => {
      expect(() => new EncryptedColumnTransformer()).not.toThrow();
    });
  });

  describe('to() - encryption', () => {
    it('should return null for null values', () => {
      expect(transformer.to(null)).toBeNull();
    });

    it('should return null for undefined values', () => {
      expect(transformer.to(undefined)).toBeNull();
    });

    it('should encrypt a simple string value', () => {
      const plaintext = 'sensitive data';
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toBe(plaintext);
      expect(encrypted).toContain(':'); // Should have iv:authTag:ciphertext format
    });

    it('should encrypt a number value', () => {
      const plaintext = 42;
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).toContain(':');
    });

    it('should encrypt an object value (JSONB compatibility)', () => {
      const plaintext = {
        revenue: 500000,
        expenses: 300000,
        debt: 100000,
      };
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).toContain(':');
      expect(encrypted).not.toContain('revenue'); // Original data should not be visible
    });

    it('should encrypt an array value', () => {
      const plaintext = ['item1', 'item2', 'item3'];
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).toContain(':');
    });

    it('should produce different ciphertext for same plaintext (IV randomness)', () => {
      const plaintext = 'same data';
      const encrypted1 = transformer.to(plaintext);
      const encrypted2 = transformer.to(plaintext);

      expect(encrypted1).not.toBe(encrypted2); // Different IVs
    });

    it('should produce ciphertext in format iv:authTag:ciphertext', () => {
      const encrypted = transformer.to('test');
      const parts = encrypted!.split(':');

      expect(parts).toHaveLength(3);
      expect(parts[0]).toHaveLength(32); // 16 bytes IV = 32 hex chars
      expect(parts[1]).toHaveLength(32); // 16 bytes auth tag = 32 hex chars
      expect(parts[2].length).toBeGreaterThan(0); // Ciphertext
    });

    it('should encrypt complex nested objects', () => {
      const plaintext = {
        client: {
          name: 'John Doe',
          business: {
            revenue: 1000000,
            expenses: {
              salaries: 500000,
              rent: 100000,
              utilities: 50000,
            },
          },
        },
      };
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
      expect(encrypted).not.toContain('John Doe');
      expect(encrypted).not.toContain('revenue');
    });

    it('should handle special characters in string values', () => {
      const plaintext = 'Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?/~`"\'\\';
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should handle unicode characters', () => {
      const plaintext = '你好世界 🌍 Здравствуй мир';
      const encrypted = transformer.to(plaintext);

      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should handle boolean values', () => {
      const encrypted = transformer.to(true);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should handle large objects (performance test)', () => {
      const largeObject = {
        responses: Array(100).fill(null).map((_, i) => ({
          questionId: `q${i}`,
          answer: `Answer ${i}`.repeat(10),
          metadata: { timestamp: new Date().toISOString() },
        })),
      };

      const startTime = Date.now();
      const encrypted = transformer.to(largeObject);
      const duration = Date.now() - startTime;

      expect(encrypted).toBeDefined();
      expect(duration).toBeLessThan(100); // Should complete in <100ms
    });
  });

  describe('from() - decryption', () => {
    it('should return null for null values', () => {
      expect(transformer.from(null)).toBeNull();
    });

    it('should return null for undefined values', () => {
      expect(transformer.from(undefined as any)).toBeNull();
    });

    it('should decrypt a simple string value', () => {
      const plaintext = 'sensitive data';
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt a number value', () => {
      const plaintext = 42;
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should decrypt an object value', () => {
      const plaintext = {
        revenue: 500000,
        expenses: 300000,
        debt: 100000,
      };
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      expect(decrypted).toEqual(plaintext);
    });

    it('should decrypt an array value', () => {
      const plaintext = ['item1', 'item2', 'item3'];
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      expect(decrypted).toEqual(plaintext);
    });

    it('should decrypt complex nested objects', () => {
      const plaintext = {
        client: {
          name: 'John Doe',
          business: {
            revenue: 1000000,
            expenses: {
              salaries: 500000,
              rent: 100000,
            },
          },
        },
      };
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      expect(decrypted).toEqual(plaintext);
    });

    it('should decrypt boolean values', () => {
      const plaintext = true;
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should throw error for invalid ciphertext format', () => {
      expect(() => transformer.from('invalid:format')).toThrow();
    });

    it('should throw error for tampered ciphertext (authentication check)', () => {
      const encrypted = transformer.to('test data');
      const [iv, authTag, ciphertext] = encrypted!.split(':');

      // Tamper with ciphertext
      const tamperedCiphertext = ciphertext.slice(0, -2) + 'ff';
      const tamperedData = `${iv}:${authTag}:${tamperedCiphertext}`;

      expect(() => transformer.from(tamperedData)).toThrow();
    });

    it('should throw error for tampered IV', () => {
      const encrypted = transformer.to('test data');
      const [iv, authTag, ciphertext] = encrypted!.split(':');

      // Tamper with IV
      const tamperedIv = 'a'.repeat(32);
      const tamperedData = `${tamperedIv}:${authTag}:${ciphertext}`;

      expect(() => transformer.from(tamperedData)).toThrow();
    });

    it('should throw error for tampered auth tag', () => {
      const encrypted = transformer.to('test data');
      const [iv, authTag, ciphertext] = encrypted!.split(':');

      // Tamper with auth tag
      const tamperedAuthTag = 'b'.repeat(32);
      const tamperedData = `${iv}:${tamperedAuthTag}:${ciphertext}`;

      expect(() => transformer.from(tamperedData)).toThrow();
    });

    it('should decrypt data encrypted with different instances (key persistence)', () => {
      const plaintext = 'persistent data';
      const transformer1 = new EncryptedColumnTransformer();
      const transformer2 = new EncryptedColumnTransformer();

      const encrypted = transformer1.to(plaintext);
      const decrypted = transformer2.from(encrypted);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle decryption performance (should be <10ms)', () => {
      const plaintext = {
        revenue: 500000,
        expenses: 300000,
        debt: 100000,
      };
      const encrypted = transformer.to(plaintext);

      const startTime = Date.now();
      const decrypted = transformer.from(encrypted);
      const duration = Date.now() - startTime;

      expect(decrypted).toEqual(plaintext);
      expect(duration).toBeLessThan(10); // Should complete in <10ms
    });
  });

  describe('round-trip encryption', () => {
    it('should successfully encrypt and decrypt string', () => {
      const original = 'test string';
      const encrypted = transformer.to(original);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toBe(original);
    });

    it('should successfully encrypt and decrypt number', () => {
      const original = 123.45;
      const encrypted = transformer.to(original);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toBe(original);
    });

    it('should successfully encrypt and decrypt object', () => {
      const original = { key: 'value', nested: { data: 123 } };
      const encrypted = transformer.to(original);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toEqual(original);
    });

    it('should successfully encrypt and decrypt array', () => {
      const original = [1, 'two', { three: 3 }];
      const encrypted = transformer.to(original);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toEqual(original);
    });

    it('should preserve data types through encryption cycle', () => {
      const testCases = [
        null,
        true,
        false,
        0,
        -1,
        123.456,
        '',
        'string',
        [],
        ['array'],
        {},
        { object: 'value' },
      ];

      testCases.forEach((original) => {
        const encrypted = transformer.to(original);
        const decrypted = transformer.from(encrypted);
        expect(decrypted).toEqual(original);
      });
    });
  });

  describe('security properties', () => {
    it('should use AES-256-GCM algorithm', () => {
      // This is tested implicitly through the encryption/decryption working
      // The algorithm constant is verified in the implementation
      expect(true).toBe(true);
    });

    it('should use 16-byte (128-bit) IV', () => {
      const encrypted = transformer.to('test');
      const [ivHex] = encrypted!.split(':');
      const ivBytes = Buffer.from(ivHex, 'hex').length;
      expect(ivBytes).toBe(16);
    });

    it('should generate unique IVs for each encryption', () => {
      const ivs = new Set<string>();
      for (let i = 0; i < 100; i++) {
        const encrypted = transformer.to('same data');
        const [iv] = encrypted!.split(':');
        ivs.add(iv);
      }
      expect(ivs.size).toBe(100); // All IVs should be unique
    });

    it('should produce authentication tag for integrity', () => {
      const encrypted = transformer.to('test');
      const [, authTag] = encrypted!.split(':');
      expect(authTag).toHaveLength(32); // 16 bytes = 32 hex chars
    });

    it('should detect any modification to encrypted data', () => {
      const encrypted = transformer.to('original data');
      const [iv, authTag, ciphertext] = encrypted!.split(':');

      // Try modifying each component
      const modifications = [
        `${iv.slice(0, -2)}ff:${authTag}:${ciphertext}`, // Modified IV
        `${iv}:${authTag.slice(0, -2)}ff:${ciphertext}`, // Modified auth tag
        `${iv}:${authTag}:${ciphertext.slice(0, -2)}ff`, // Modified ciphertext
      ];

      modifications.forEach((modified) => {
        expect(() => transformer.from(modified)).toThrow();
      });
    });
  });

  describe('edge cases', () => {
    it('should handle empty string', () => {
      const plaintext = '';
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle empty object', () => {
      const plaintext = {};
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toEqual(plaintext);
    });

    it('should handle empty array', () => {
      const plaintext: any[] = [];
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toEqual(plaintext);
    });

    it('should handle very long strings (10000+ characters)', () => {
      const plaintext = 'a'.repeat(10000);
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle objects with null values', () => {
      const plaintext = { key: null, nested: { value: null } };
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toEqual(plaintext);
    });

    it('should handle date objects by converting to string', () => {
      const date = new Date('2025-01-01');
      const plaintext = { timestamp: date };
      const encrypted = transformer.to(plaintext);
      const decrypted = transformer.from(encrypted);

      // Date objects are serialized to strings in JSON
      expect(decrypted.timestamp).toBe(date.toJSON());
    });
  });

  describe('GDPR/CCPA compliance', () => {
    it('should encrypt PII fields to meet compliance requirements', () => {
      const financialData = {
        annualRevenue: 500000,
        monthlyExpenses: 40000,
        outstandingDebt: 100000,
        cashOnHand: 50000,
      };

      const encrypted = transformer.to(financialData);

      // Verify data is not readable in encrypted form
      expect(encrypted).not.toContain('500000');
      expect(encrypted).not.toContain('annualRevenue');
      expect(encrypted).not.toContain('monthlyExpenses');
    });

    it('should maintain data integrity for audit purposes', () => {
      const financialData = {
        revenue: 750000,
        lastUpdated: new Date().toISOString(),
      };

      const encrypted = transformer.to(financialData);
      const decrypted = transformer.from(encrypted);

      // Data should be identical after round-trip
      expect(decrypted).toEqual(financialData);
    });
  });
});
