import { MigrationInterface, QueryRunner, Table, TableIndex, TableForeignKey } from 'typeorm';

/**
 * GDPR Article 21 - Right to Object to Processing
 *
 * This migration creates the user_objections table to store user objections
 * to specific types of data processing (marketing, analytics, profiling).
 */
export class CreateUserObjectionsTable1735410000000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create user_objections table
    await queryRunner.createTable(
      new Table({
        name: 'user_objections',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isPrimary: true,
            generationStrategy: 'uuid',
            default: 'uuid_generate_v4()',
          },
          {
            name: 'user_id',
            type: 'uuid',
            isNullable: false,
          },
          {
            name: 'objection_type',
            type: 'enum',
            enum: ['marketing', 'analytics', 'profiling'],
            isNullable: false,
          },
          {
            name: 'reason',
            type: 'text',
            isNullable: false,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );

    // Create unique index on user_id + objection_type to prevent duplicates
    await queryRunner.createIndex(
      'user_objections',
      new TableIndex({
        name: 'IDX_USER_OBJECTION_TYPE',
        columnNames: ['user_id', 'objection_type'],
        isUnique: true,
      }),
    );

    // Create index on user_id for faster lookups
    await queryRunner.createIndex(
      'user_objections',
      new TableIndex({
        name: 'IDX_USER_OBJECTIONS_USER_ID',
        columnNames: ['user_id'],
      }),
    );

    // Add foreign key constraint to users table
    await queryRunner.createForeignKey(
      'user_objections',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE', // Delete objections when user is deleted
        name: 'FK_USER_OBJECTIONS_USER_ID',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key
    await queryRunner.dropForeignKey('user_objections', 'FK_USER_OBJECTIONS_USER_ID');

    // Drop indexes
    await queryRunner.dropIndex('user_objections', 'IDX_USER_OBJECTIONS_USER_ID');
    await queryRunner.dropIndex('user_objections', 'IDX_USER_OBJECTION_TYPE');

    // Drop table
    await queryRunner.dropTable('user_objections');
  }
}
