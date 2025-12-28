import { Injectable } from '@nestjs/common';
import { ValueTransformer } from 'typeorm';
import { EncryptionService } from '../services/encryption.service';

/**
 * TypeORM Value Transformer for automatic column-level encryption.
 *
 * Usage in entity:
 * @Column({
 *   type: 'text',
 *   transformer: new EncryptedColumnTransformer(encryptionService)
 * })
 * sensitiveField: string;
 *
 * Requirements:
 * - CRIT-004: DISC data encryption at rest
 * - REQ-QUEST-003: DISC confidentiality
 */
@Injectable()
export class EncryptedColumnTransformer implements ValueTransformer {
  constructor(private readonly encryptionService: EncryptionService) {}

  /**
   * Encrypts value before saving to database.
   * Called by TypeORM during INSERT/UPDATE operations.
   */
  to(value: any): string | null {
    return this.encryptionService.encrypt(value);
  }

  /**
   * Decrypts value after loading from database.
   * Called by TypeORM during SELECT operations.
   */
  from(value: string | null): any {
    return this.encryptionService.decrypt(value);
  }
}
