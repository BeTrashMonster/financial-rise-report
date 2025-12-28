import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { EncryptedColumnTransformer } from './encrypted-column.transformer';
import { EncryptionService } from '../services/encryption.service';

describe('EncryptedColumnTransformer', () => {
  let transformer: EncryptedColumnTransformer;

  const testEncryptionKey =
    'b4ca46626f1776931175c817b7d5c821fd844daf0c3e23ee36dd49827f4f74f3';

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        EncryptionService,
        EncryptedColumnTransformer,
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

    transformer = module.get<EncryptedColumnTransformer>(EncryptedColumnTransformer);
  });

  it('should be defined', () => {
    expect(transformer).toBeDefined();
  });

  describe('to', () => {
    it('should encrypt a value', () => {
      const value = 85.5;
      const encrypted = transformer.to(value);
      expect(encrypted).toBeDefined();
      expect(typeof encrypted).toBe('string');
    });

    it('should return null for null values', () => {
      expect(transformer.to(null)).toBeNull();
    });
  });

  describe('from', () => {
    it('should decrypt a value', () => {
      const value = 85.5;
      const encrypted = transformer.to(value);
      const decrypted = transformer.from(encrypted);
      expect(decrypted).toBe(value);
    });

    it('should return null for null values', () => {
      expect(transformer.from(null)).toBeNull();
    });
  });
});
