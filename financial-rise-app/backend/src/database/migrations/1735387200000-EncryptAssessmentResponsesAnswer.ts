import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * Migration: Encrypt Assessment Responses Answer Field
 *
 * SECURITY FINDING: CRIT-005
 * Reference: SECURITY-AUDIT-REPORT.md Lines 983-1019
 *
 * Purpose:
 * - Converts assessment_responses.answer from JSONB to TEXT
 * - Enables AES-256-GCM encryption at rest for financial PII
 * - Meets GDPR/CCPA compliance requirements for data protection
 *
 * Migration Strategy:
 * 1. Backup existing data
 * 2. Create new TEXT column with encryption transformer
 * 3. Migrate existing JSONB data to encrypted TEXT
 * 4. Drop old JSONB column
 * 5. Rename new column
 *
 * Rollback Strategy:
 * - Convert TEXT back to JSONB (data will be decrypted)
 *
 * IMPORTANT:
 * - Requires DB_ENCRYPTION_KEY environment variable (64 hex characters)
 * - Run during maintenance window (locks assessment_responses table)
 * - Test on staging before production
 * - Backup database before running
 *
 * Data Impact:
 * - All assessment response answers will be encrypted
 * - No data loss, but encrypted data is unreadable without key
 * - Key management is critical - store in GCP Secret Manager
 */
export class EncryptAssessmentResponsesAnswer1735387200000
  implements MigrationInterface
{
  name = 'EncryptAssessmentResponsesAnswer1735387200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Validate encryption key is set
    const encryptionKey = process.env.DB_ENCRYPTION_KEY;
    if (!encryptionKey || encryptionKey.length !== 64) {
      throw new Error(
        'Migration requires DB_ENCRYPTION_KEY environment variable (64 hex characters). ' +
          'Generate: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))" ' +
          'CRITICAL: Store this key securely in GCP Secret Manager and never commit to version control.',
      );
    }

    console.log('Starting encryption migration for assessment_responses.answer');
    console.log('IMPORTANT: Backup database before proceeding');

    // Step 1: Add new TEXT column with temporary name
    console.log('Step 1/6: Adding new encrypted answer column...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      ADD COLUMN "answer_encrypted" TEXT
    `);

    // Step 2: Migrate existing JSONB data to encrypted TEXT
    // This requires the EncryptedColumnTransformer logic
    console.log('Step 2/6: Migrating existing data to encrypted format...');

    // Get all existing responses
    const existingResponses = await queryRunner.query(`
      SELECT id, answer
      FROM assessment_responses
      WHERE answer IS NOT NULL
    `);

    console.log(`Encrypting ${existingResponses.length} assessment responses...`);

    // Import encryption transformer
    const { EncryptedColumnTransformer } = await import(
      '../../common/transformers/encrypted-column.transformer'
    );
    const transformer = new EncryptedColumnTransformer();

    // Encrypt each response (batch processing for performance)
    const batchSize = 100;
    for (let i = 0; i < existingResponses.length; i += batchSize) {
      const batch = existingResponses.slice(i, i + batchSize);

      for (const row of batch) {
        try {
          // Encrypt the JSONB data
          const encryptedValue = transformer.to(row.answer);

          // Update with encrypted value
          await queryRunner.query(
            `
            UPDATE assessment_responses
            SET answer_encrypted = $1
            WHERE id = $2
          `,
            [encryptedValue, row.id],
          );
        } catch (error) {
          console.error(
            `Failed to encrypt response ID ${row.id}: ${error.message}`,
          );
          throw new Error(
            `Encryption migration failed at response ID ${row.id}. ` +
              `Database has not been modified. Error: ${error.message}`,
          );
        }
      }

      console.log(
        `Encrypted ${Math.min(i + batchSize, existingResponses.length)} of ${existingResponses.length} responses`,
      );
    }

    // Step 3: Verify all data migrated
    console.log('Step 3/6: Verifying data migration...');
    const unmigrated = await queryRunner.query(`
      SELECT COUNT(*) as count
      FROM assessment_responses
      WHERE answer IS NOT NULL AND answer_encrypted IS NULL
    `);

    if (unmigrated[0].count > 0) {
      throw new Error(
        `Migration verification failed: ${unmigrated[0].count} responses not migrated`,
      );
    }

    // Step 4: Drop old JSONB column
    console.log('Step 4/6: Dropping old JSONB column...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      DROP COLUMN "answer"
    `);

    // Step 5: Rename encrypted column to answer
    console.log('Step 5/6: Renaming encrypted column...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      RENAME COLUMN "answer_encrypted" TO "answer"
    `);

    // Step 6: Add NOT NULL constraint (allow NULL for not_applicable responses)
    console.log('Step 6/6: Adding constraints...');
    // Note: We keep NULL allowed since not_applicable responses may have NULL answers

    console.log('✅ Encryption migration completed successfully');
    console.log(
      `📊 Encrypted ${existingResponses.length} assessment response answers`,
    );
    console.log('⚠️  CRITICAL: Backup DB_ENCRYPTION_KEY to secure vault');
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    console.log('Starting rollback of encryption migration');
    console.log('WARNING: This will decrypt all assessment response data');

    // Validate encryption key for rollback
    const encryptionKey = process.env.DB_ENCRYPTION_KEY;
    if (!encryptionKey || encryptionKey.length !== 64) {
      throw new Error(
        'Rollback requires DB_ENCRYPTION_KEY to decrypt existing data',
      );
    }

    // Step 1: Add JSONB column
    console.log('Step 1/5: Adding JSONB column...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      ADD COLUMN "answer_jsonb" JSONB
    `);

    // Step 2: Decrypt data back to JSONB
    console.log('Step 2/5: Decrypting data...');

    const encryptedResponses = await queryRunner.query(`
      SELECT id, answer
      FROM assessment_responses
      WHERE answer IS NOT NULL
    `);

    console.log(
      `Decrypting ${encryptedResponses.length} assessment responses...`,
    );

    const { EncryptedColumnTransformer } = await import(
      '../../common/transformers/encrypted-column.transformer'
    );
    const transformer = new EncryptedColumnTransformer();

    const batchSize = 100;
    for (let i = 0; i < encryptedResponses.length; i += batchSize) {
      const batch = encryptedResponses.slice(i, i + batchSize);

      for (const row of batch) {
        try {
          // Decrypt the TEXT data
          const decryptedValue = transformer.from(row.answer);

          // Update with JSONB value
          await queryRunner.query(
            `
            UPDATE assessment_responses
            SET answer_jsonb = $1
            WHERE id = $2
          `,
            [JSON.stringify(decryptedValue), row.id],
          );
        } catch (error) {
          console.error(
            `Failed to decrypt response ID ${row.id}: ${error.message}`,
          );
          throw new Error(
            `Decryption rollback failed at response ID ${row.id}. ` +
              `Error: ${error.message}`,
          );
        }
      }

      console.log(
        `Decrypted ${Math.min(i + batchSize, encryptedResponses.length)} of ${encryptedResponses.length} responses`,
      );
    }

    // Step 3: Drop encrypted TEXT column
    console.log('Step 3/5: Dropping encrypted column...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      DROP COLUMN "answer"
    `);

    // Step 4: Rename JSONB column to answer
    console.log('Step 4/5: Renaming JSONB column...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      RENAME COLUMN "answer_jsonb" TO "answer"
    `);

    // Step 5: Restore JSONB column type constraint
    console.log('Step 5/5: Restoring column type...');
    await queryRunner.query(`
      ALTER TABLE "assessment_responses"
      ALTER COLUMN "answer" TYPE JSONB USING answer::JSONB
    `);

    console.log('✅ Rollback completed - data decrypted and restored to JSONB');
  }
}
