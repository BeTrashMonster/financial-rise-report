import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * GDPR Article 18 - Right to Restriction of Processing
 *
 * This migration adds fields to support the GDPR Article 18 right, which allows
 * data subjects to request restriction of processing of their personal data.
 *
 * New fields:
 * - processing_restricted: Boolean flag indicating if processing is restricted
 * - restriction_reason: Optional text field for the user to explain why they're restricting processing
 *
 * When processing is restricted, users can still:
 * - View their data (Article 15)
 * - Export their data (Article 20)
 * - Delete their data (Article 17)
 * - Update their profile information
 *
 * But they cannot:
 * - Create new assessments
 * - Update existing assessments
 * - Perform other data processing operations
 */
export class AddProcessingRestrictionFields1735400000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add processing_restricted boolean column
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'processing_restricted',
        type: 'boolean',
        default: false,
        isNullable: false,
        comment: 'GDPR Article 18: Indicates if user has restricted data processing',
      }),
    );

    // Add restriction_reason text column
    await queryRunner.addColumn(
      'users',
      new TableColumn({
        name: 'restriction_reason',
        type: 'text',
        isNullable: true,
        comment: 'GDPR Article 18: Optional reason provided by user for restricting processing',
      }),
    );

    // Add index for faster queries on restricted users
    await queryRunner.query(`
      CREATE INDEX idx_users_processing_restricted
      ON users (processing_restricted)
      WHERE processing_restricted = true;
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop index first
    await queryRunner.query(`DROP INDEX IF EXISTS idx_users_processing_restricted;`);

    // Remove columns
    await queryRunner.dropColumn('users', 'restriction_reason');
    await queryRunner.dropColumn('users', 'processing_restricted');
  }
}
