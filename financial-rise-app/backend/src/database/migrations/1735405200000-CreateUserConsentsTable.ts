import { MigrationInterface, QueryRunner, Table, TableForeignKey, TableIndex } from 'typeorm';

export class CreateUserConsentsTable1735405200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create user_consents table
    await queryRunner.createTable(
      new Table({
        name: 'user_consents',
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
            name: 'consent_type',
            type: 'enum',
            enum: ['essential', 'analytics', 'marketing'],
            isNullable: false,
          },
          {
            name: 'granted',
            type: 'boolean',
            default: false,
            isNullable: false,
          },
          {
            name: 'ip_address',
            type: 'varchar',
            length: '45', // IPv6 support
            isNullable: true,
          },
          {
            name: 'user_agent',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'CURRENT_TIMESTAMP',
          },
        ],
      }),
      true,
    );

    // Create foreign key to users table
    await queryRunner.createForeignKey(
      'user_consents',
      new TableForeignKey({
        columnNames: ['user_id'],
        referencedTableName: 'users',
        referencedColumnNames: ['id'],
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE',
      }),
    );

    // Create composite index on user_id and consent_type for efficient lookups
    await queryRunner.createIndex(
      'user_consents',
      new TableIndex({
        name: 'IDX_USER_CONSENT_TYPE',
        columnNames: ['user_id', 'consent_type'],
      }),
    );

    // Create index on created_at for consent history queries
    await queryRunner.createIndex(
      'user_consents',
      new TableIndex({
        name: 'IDX_USER_CONSENTS_CREATED_AT',
        columnNames: ['created_at'],
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop indexes
    await queryRunner.dropIndex('user_consents', 'IDX_USER_CONSENTS_CREATED_AT');
    await queryRunner.dropIndex('user_consents', 'IDX_USER_CONSENT_TYPE');

    // Drop table (foreign key will be dropped automatically)
    await queryRunner.dropTable('user_consents');
  }
}
