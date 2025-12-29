import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddDeviceInfoToRefreshTokens1735500000000
  implements MigrationInterface
{
  name = 'AddDeviceInfoToRefreshTokens1735500000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Add device_info column to refresh_tokens table
    await queryRunner.query(`
      ALTER TABLE "refresh_tokens"
      ADD COLUMN "device_info" VARCHAR(50)
    `);

    // Add ip_address column to refresh_tokens table
    await queryRunner.query(`
      ALTER TABLE "refresh_tokens"
      ADD COLUMN "ip_address" VARCHAR(45)
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove columns
    await queryRunner.query(`
      ALTER TABLE "refresh_tokens"
      DROP COLUMN "ip_address"
    `);

    await queryRunner.query(`
      ALTER TABLE "refresh_tokens"
      DROP COLUMN "device_info"
    `);
  }
}
