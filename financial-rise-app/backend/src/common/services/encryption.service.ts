import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

/**
 * EncryptionService provides AES-256-GCM encryption for sensitive data at rest.
 *
 * Security Properties:
 * - Algorithm: AES-256-GCM (Galois/Counter Mode)
 * - Key Size: 256 bits (32 bytes)
 * - IV Size: 128 bits (16 bytes) - unique per encryption
 * - Authentication: 128-bit auth tag prevents tampering
 *
 * Requirements:
 * - REQ-QUEST-003: DISC data must be confidential
 * - CRIT-004: DISC personality data encrypted at rest
 * - Performance: <10ms per operation
 *
 * Format: iv:authTag:ciphertext (all hex-encoded)
 */
@Injectable()
export class EncryptionService {
  private readonly algorithm = 'aes-256-gcm';
  private readonly key: Buffer;

  constructor(private readonly configService: ConfigService) {
    const encryptionKey = this.configService.get<string>('DB_ENCRYPTION_KEY');

    if (!encryptionKey) {
      throw new Error('DB_ENCRYPTION_KEY environment variable is required');
    }

    if (encryptionKey.length !== 64) {
      throw new Error(
        'DB_ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)',
      );
    }

    this.key = Buffer.from(encryptionKey, 'hex');
  }

  /**
   * Encrypts a value using AES-256-GCM.
   *
   * @param value - Value to encrypt (string, number, object, etc.)
   * @returns Encrypted string in format "iv:authTag:ciphertext" or null if input is null/undefined
   */
  encrypt(value: any): string | null {
    if (value === null || value === undefined) {
      return null;
    }

    try {
      // Generate unique IV for each encryption
      const iv = randomBytes(16);

      // Create cipher
      const cipher = createCipheriv(this.algorithm, this.key, iv);

      // Serialize value to JSON
      const plaintext = JSON.stringify(value);

      // Encrypt
      let encrypted = cipher.update(plaintext, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      // Get authentication tag (prevents tampering)
      const authTag = cipher.getAuthTag();

      // Return format: iv:authTag:ciphertext
      return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
    } catch (error) {
      throw new Error(
        `Encryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }

  /**
   * Decrypts a value encrypted with AES-256-GCM.
   *
   * @param encryptedValue - Encrypted string in format "iv:authTag:ciphertext"
   * @returns Decrypted original value or null if input is null/undefined
   * @throws Error if decryption fails or data has been tampered with
   */
  decrypt(encryptedValue: string | null | undefined): any {
    if (encryptedValue === null || encryptedValue === undefined) {
      return null;
    }

    try {
      // Parse encrypted format
      const parts = encryptedValue.split(':');
      if (parts.length !== 3) {
        throw new Error('Invalid encrypted data format');
      }

      const [ivHex, authTagHex, ciphertext] = parts;

      // Convert hex strings to buffers
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');

      // Create decipher
      const decipher = createDecipheriv(this.algorithm, this.key, iv);

      // Set authentication tag (will throw if tampered)
      decipher.setAuthTag(authTag);

      // Decrypt
      let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      // Parse JSON back to original value
      return JSON.parse(decrypted);
    } catch (error) {
      throw new Error(
        `Decryption failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      );
    }
  }
}
