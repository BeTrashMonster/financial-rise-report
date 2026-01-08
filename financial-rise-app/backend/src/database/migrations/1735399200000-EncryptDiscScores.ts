import { MigrationInterface, QueryRunner, TableColumn } from 'typeorm';

/**
 * Migration: Encrypt DISC Profile Scores (CRIT-004)
 *
 * Changes DISC score columns from float to text to support encrypted storage.
 * All existing data will be lost - this should be run before any production data exists.
 *
 * Security: REQ-QUEST-003 - DISC data must be confidential
 * Finding: CRIT-004 - DISC personality data not encrypted at rest
 */
export class EncryptDiscScores1735399200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Change d_score from float to text
    await queryRunner.changeColumn(
      'disc_profiles',
      'd_score',
      new TableColumn({
        name: 'd_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Change i_score from float to text
    await queryRunner.changeColumn(
      'disc_profiles',
      'i_score',
      new TableColumn({
        name: 'i_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Change s_score from float to text
    await queryRunner.changeColumn(
      'disc_profiles',
      's_score',
      new TableColumn({
        name: 's_score',
        type: 'text',
        isNullable: false,
      }),
    );

    // Change c_score from float to text
    await queryRunner.changeColumn(
      'disc_profiles',
      'c_score',
      new TableColumn({
        name: 'c_score',
        type: 'text',
        isNullable: false,
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Revert c_score to float
    await queryRunner.changeColumn(
      'disc_profiles',
      'c_score',
      new TableColumn({
        name: 'c_score',
        type: 'float',
        isNullable: false,
      }),
    );

    // Revert s_score to float
    await queryRunner.changeColumn(
      'disc_profiles',
      's_score',
      new TableColumn({
        name: 's_score',
        type: 'float',
        isNullable: false,
      }),
    );

    // Revert i_score to float
    await queryRunner.changeColumn(
      'disc_profiles',
      'i_score',
      new TableColumn({
        name: 'i_score',
        type: 'float',
        isNullable: false,
      }),
    );

    // Revert d_score to float
    await queryRunner.changeColumn(
      'disc_profiles',
      'd_score',
      new TableColumn({
        name: 'd_score',
        type: 'float',
        isNullable: false,
      }),
    );
  }
}
