import { ValueTransformer } from 'typeorm';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

/**
 * EncryptedColumnTransformer
 *
 * Provides column-level encryption for TypeORM entities using AES-256-GCM.
 * Encrypts data at rest to meet GDPR/CCPA compliance requirements for PII.
 *
 * Security Properties:
 * - Algorithm: AES-256-GCM (authenticated encryption)
 * - Key Size: 256 bits (32 bytes)
 * - IV Size: 128 bits (16 bytes, randomly generated per encryption)
 * - Authentication: GCM provides built-in authentication tag
 *
 * Usage:
 * ```typescript
 * @Column({
 *   type: 'text',
 *   transformer: new EncryptedColumnTransformer()
 * })
 * sensitiveData: any;
 * ```
 *
 * Environment Variables Required:
 * - DB_ENCRYPTION_KEY: 64 hex characters (32 bytes)
 *
 * Format: iv:authTag:ciphertext (all hex-encoded)
 *
 * SECURITY FINDING: CRIT-005
 * Remediates: Financial data not encrypted at rest
 * Reference: SECURITY-AUDIT-REPORT.md Lines 983-1019
 */
export class EncryptedColumnTransformer implements ValueTransformer {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key: Buffer;
  private readonly ivLength = 16; // 128 bits
  private readonly authTagLength = 16; // 128 bits

  constructor() {
    const encryptionKey = process.env.DB_ENCRYPTION_KEY;

    // Validate encryption key
    if (!encryptionKey || encryptionKey.length !== 64) {
      throw new Error(
        'DB_ENCRYPTION_KEY must be 64 hex characters (32 bytes). ' +
          'Generate: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      );
    }

    // Convert hex string to Buffer
    try {
      this.key = Buffer.from(encryptionKey, 'hex');
      if (this.key.length !== 32) {
        throw new Error('Invalid key length after conversion');
      }
    } catch (error) {
      throw new Error(
        'DB_ENCRYPTION_KEY must be valid hex characters. ' +
          'Generate: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"',
      );
    }
  }

  /**
   * Encrypts data before storing in database
   *
   * @param value - Any value to encrypt (will be JSON serialized)
   * @returns Encrypted string in format: iv:authTag:ciphertext (hex-encoded)
   */
  to(value: any): string | null {
    if (value === null || value === undefined) {
      return null;
    }

    try {
      // Generate random IV for each encryption
      const iv = randomBytes(this.ivLength);

      // Create cipher
      const cipher = createCipheriv(this.algorithm, this.key, iv);

      // Encrypt data (JSON serialize first to handle objects/arrays)
      const plaintext = JSON.stringify(value);
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      // Get authentication tag
      const authTag = cipher.getAuthTag();

      // Return in format: iv:authTag:ciphertext
      return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
      throw new Error(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * Decrypts data when reading from database
   *
   * @param value - Encrypted string in format: iv:authTag:ciphertext
   * @returns Decrypted original value
   */
  from(value: string | null): any {
    if (!value) {
      return null;
    }

    try {
      // Parse encrypted data format
      const parts = value.split(':');
      if (parts.length !== 3) {
        throw new Error(
          'Invalid encrypted data format. Expected: iv:authTag:ciphertext',
        );
      }

      const [ivHex, authTagHex, encryptedHex] = parts;

      // Convert from hex
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const encrypted = encryptedHex;

      // Validate IV and auth tag lengths
      if (iv.length !== this.ivLength) {
        throw new Error(`Invalid IV length: expected ${this.ivLength} bytes`);
      }
      if (authTag.length !== this.authTagLength) {
        throw new Error(
          `Invalid auth tag length: expected ${this.authTagLength} bytes`,
        );
      }

      // Create decipher
      const decipher = createDecipheriv(this.algorithm, this.key, iv);
      decipher.setAuthTag(authTag);

      // Decrypt data
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      // Parse JSON back to original type
      return JSON.parse(decrypted);
    } catch (error) {
      // Authentication failures indicate tampering
      if (error instanceof Error && error.message.includes('auth')) {
        throw new Error(
          'Decryption failed: Data integrity check failed (possible tampering)',
        );
      }

      throw new Error(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }
}
