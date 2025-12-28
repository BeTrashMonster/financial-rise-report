import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Migration: Encrypt DISC Scores at Rest (Work Stream 52: CRIT-004)
 *
 * Security Requirements:
 * - REQ-QUEST-003: DISC data must be confidential
 * - CRIT-004: DISC personality data encrypted at rest
 * - OWASP A02:2021: Cryptographic Failures
 * - CWE-311: Missing Encryption of Sensitive Data
 *
 * Changes:
 * 1. Convert d_score column from decimal → text (to store encrypted ciphertext)
 * 2. Convert i_score column from decimal → text (to store encrypted ciphertext)
 * 3. Convert s_score column from decimal → text (to store encrypted ciphertext)
 * 4. Convert c_score column from decimal → text (to store encrypted ciphertext)
 *
 * Data Migration Strategy:
 * - Existing DISC scores will be encrypted on next read/write by EncryptedColumnTransformer
 * - No manual data migration needed (TypeORM transformer handles encryption automatically)
 * - In production: Run migration during maintenance window
 *
 * Rollback Strategy:
 * - Converts text columns back to decimal
 * - WARNING: Rollback will LOSE encrypted data if encryption was applied
 * - Only rollback if migration fails immediately
 */
export class EncryptDISCScores1735387400000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Convert d_score column to text for encrypted storage
    await queryRunner.changeColumn(
      'disc_profiles',
      'd_score',
      new TableColumn({
        name: 'd_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Convert i_score column to text for encrypted storage
    await queryRunner.changeColumn(
      'disc_profiles',
      'i_score',
      new TableColumn({
        name: 'i_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Convert s_score column to text for encrypted storage
    await queryRunner.changeColumn(
      'disc_profiles',
      's_score',
      new TableColumn({
        name: 's_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Convert c_score column to text for encrypted storage
    await queryRunner.changeColumn(
      'disc_profiles',
      'c_score',
      new TableColumn({
        name: 'c_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Add comment documenting encryption
    await queryRunner.query(`
      COMMENT ON COLUMN disc_profiles.d_score IS 'ENCRYPTED: Dominance score - AES-256-GCM encrypted at rest (CRIT-004)';
      COMMENT ON COLUMN disc_profiles.i_score IS 'ENCRYPTED: Influence score - AES-256-GCM encrypted at rest (CRIT-004)';
      COMMENT ON COLUMN disc_profiles.s_score IS 'ENCRYPTED: Steadiness score - AES-256-GCM encrypted at rest (CRIT-004)';
      COMMENT ON COLUMN disc_profiles.c_score IS 'ENCRYPTED: Compliance score - AES-256-GCM encrypted at rest (CRIT-004)';
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // WARNING: This rollback will convert text back to decimal
    // If data was encrypted, it will be LOST during rollback

    // Revert d_score column to decimal
    await queryRunner.changeColumn(
      'disc_profiles',
      'd_score',
      new TableColumn({
        name: 'd_score',
        type: 'decimal',
        precision: 5,
        scale: 2,
        isNullable: false,
      }),
    );

    // Revert i_score column to decimal
    await queryRunner.changeColumn(
      'disc_profiles',
      'i_score',
      new TableColumn({
        name: 'i_score',
        type: 'decimal',
        precision: 5,
        scale: 2,
        isNullable: false,
      }),
    );

    // Revert s_score column to decimal
    await queryRunner.changeColumn(
      'disc_profiles',
      's_score',
      new TableColumn({
        name: 's_score',
        type: 'decimal',
        precision: 5,
        scale: 2,
        isNullable: false,
      }),
    );

    // Revert c_score column to decimal
    await queryRunner.changeColumn(
      'disc_profiles',
      'c_score',
      new TableColumn({
        name: 'c_score',
        type: 'decimal',
        precision: 5,
        scale: 2,
        isNullable: false,
      }),
    );

    // Remove encryption comments
    await queryRunner.query(`
      COMMENT ON COLUMN disc_profiles.d_score IS NULL;
      COMMENT ON COLUMN disc_profiles.i_score IS NULL;
      COMMENT ON COLUMN disc_profiles.s_score IS NULL;
      COMMENT ON COLUMN disc_profiles.c_score IS NULL;
    `);
  }
}
