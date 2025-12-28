import { MigrationInterface, QueryRunner, TableColumn, TableForeignKey } from 'typeorm';

/**
 * Migration: Add consultant_id to reports table for ownership validation
 *
 * Security: Enables IDOR protection by linking reports to consultants
 * Related: Work Stream 62 - IDOR Protection & Ownership Guards
 */
export class AddConsultantIdToReports1735390000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add consultant_id column to reports table
    await queryRunner.addColumn(
      'reports',
      new TableColumn({
        name: 'consultant_id',
        type: 'uuid',
        isNullable: true, // Make nullable for migration, will populate from assessments
      }),
    );

    // Populate consultant_id from associated assessment
    await queryRunner.query(`
      UPDATE reports r
      SET consultant_id = a.consultant_id
      FROM assessments a
      WHERE r.assessment_id = a.id
    `);

    // Now make it NOT NULL after population
    await queryRunner.changeColumn(
      'reports',
      'consultant_id',
      new TableColumn({
        name: 'consultant_id',
        type: 'uuid',
        isNullable: false,
      }),
    );

    // Add foreign key constraint to users table
    await queryRunner.createForeignKey(
      'reports',
      new TableForeignKey({
        name: 'FK_reports_consultant',
        columnNames: ['consultant_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      }),
    );

    // Add index for performance on ownership queries
    await queryRunner.query(`
      CREATE INDEX "IDX_reports_consultant_id" ON "reports" ("consultant_id")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop index
    await queryRunner.query(`DROP INDEX "IDX_reports_consultant_id"`);

    // Drop foreign key
    await queryRunner.dropForeignKey('reports', 'FK_reports_consultant');

    // Drop column
    await queryRunner.dropColumn('reports', 'consultant_id');
  }
}
