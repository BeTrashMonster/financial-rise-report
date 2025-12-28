import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddRefreshTokensAndReportsTables1703700000002
  implements MigrationInterface
{
  name = 'AddRefreshTokensAndReportsTables1703700000002';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create refresh_tokens table for multi-device support
    await queryRunner.query(`
      CREATE TABLE "refresh_tokens" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "user_id" uuid NOT NULL,
        "token" VARCHAR(255) NOT NULL,
        "expires_at" TIMESTAMP NOT NULL,
        "revoked_at" TIMESTAMP,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_refresh_tokens_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_refresh_tokens_token" UNIQUE ("token"),
        CONSTRAINT "FK_refresh_tokens_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_refresh_tokens_user" ON "refresh_tokens" ("user_id")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_refresh_tokens_token" ON "refresh_tokens" ("token")
    `);

    // Create report_type enum
    await queryRunner.query(`
      CREATE TYPE "report_type_enum" AS ENUM ('consultant', 'client');
    `);

    await queryRunner.query(`
      CREATE TYPE "report_status_enum" AS ENUM ('generating', 'completed', 'failed');
    `);

    // Create reports table for tracking generated PDFs
    await queryRunner.query(`
      CREATE TABLE "reports" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "assessment_id" uuid NOT NULL,
        "report_type" "report_type_enum" NOT NULL,
        "status" "report_status_enum" NOT NULL DEFAULT 'generating',
        "file_url" TEXT,
        "file_size_bytes" INT,
        "generated_at" TIMESTAMP,
        "expires_at" TIMESTAMP,
        "error" TEXT,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_reports_id" PRIMARY KEY ("id"),
        CONSTRAINT "FK_reports_assessment" FOREIGN KEY ("assessment_id") REFERENCES "assessments"("id") ON DELETE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_reports_assessment" ON "reports" ("assessment_id")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_reports_type" ON "reports" ("report_type")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_reports_status" ON "reports" ("status")
    `);

    // Add reset_password_used_at column to users table for security
    await queryRunner.query(`
      ALTER TABLE "users"
      ADD COLUMN "reset_password_used_at" TIMESTAMP
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Remove added column
    await queryRunner.query(`
      ALTER TABLE "users"
      DROP COLUMN "reset_password_used_at"
    `);

    // Drop reports table
    await queryRunner.query(`DROP INDEX "IDX_reports_status"`);
    await queryRunner.query(`DROP INDEX "IDX_reports_type"`);
    await queryRunner.query(`DROP INDEX "IDX_reports_assessment"`);
    await queryRunner.query(`DROP TABLE "reports"`);
    await queryRunner.query(`DROP TYPE "report_status_enum"`);
    await queryRunner.query(`DROP TYPE "report_type_enum"`);

    // Drop refresh_tokens table
    await queryRunner.query(`DROP INDEX "IDX_refresh_tokens_token"`);
    await queryRunner.query(`DROP INDEX "IDX_refresh_tokens_user"`);
    await queryRunner.query(`DROP TABLE "refresh_tokens"`);
  }
}
