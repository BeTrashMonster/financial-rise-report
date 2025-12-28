import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1703700000001 implements MigrationInterface {
  name = 'InitialSchema1703700000001';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create ENUM types
    await queryRunner.query(`
      CREATE TYPE "user_role_enum" AS ENUM ('consultant', 'admin');
    `);

    await queryRunner.query(`
      CREATE TYPE "user_status_enum" AS ENUM ('active', 'inactive', 'locked');
    `);

    await queryRunner.query(`
      CREATE TYPE "assessment_status_enum" AS ENUM ('draft', 'in_progress', 'completed');
    `);

    await queryRunner.query(`
      CREATE TYPE "question_type_enum" AS ENUM ('single_choice', 'multiple_choice', 'rating', 'text');
    `);

    // Create users table
    await queryRunner.query(`
      CREATE TABLE "users" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "email" VARCHAR(255) NOT NULL,
        "password_hash" VARCHAR(255) NOT NULL,
        "first_name" VARCHAR(100) NOT NULL,
        "last_name" VARCHAR(100) NOT NULL,
        "role" "user_role_enum" NOT NULL DEFAULT 'consultant',
        "status" "user_status_enum" NOT NULL DEFAULT 'active',
        "failed_login_attempts" INT NOT NULL DEFAULT 0,
        "locked_until" TIMESTAMP,
        "reset_password_token" VARCHAR(255),
        "reset_password_expires" TIMESTAMP,
        "refresh_token" VARCHAR(255),
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        "last_login_at" TIMESTAMP,
        CONSTRAINT "PK_users_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_users_email" UNIQUE ("email")
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_users_email" ON "users" ("email")
    `);

    // Create questions table
    await queryRunner.query(`
      CREATE TABLE "questions" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "question_key" VARCHAR(50) NOT NULL,
        "question_text" TEXT NOT NULL,
        "question_type" "question_type_enum" NOT NULL,
        "options" JSONB,
        "required" BOOLEAN NOT NULL DEFAULT true,
        "display_order" INT NOT NULL,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_questions_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_questions_key" UNIQUE ("question_key")
      )
    `);

    await queryRunner.query(`
      CREATE UNIQUE INDEX "IDX_questions_key" ON "questions" ("question_key")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_questions_type" ON "questions" ("question_type")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_questions_order" ON "questions" ("display_order")
    `);

    // Create assessments table
    await queryRunner.query(`
      CREATE TABLE "assessments" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "consultant_id" uuid NOT NULL,
        "client_name" VARCHAR(100) NOT NULL,
        "business_name" VARCHAR(100) NOT NULL,
        "client_email" VARCHAR(255) NOT NULL,
        "status" "assessment_status_enum" NOT NULL DEFAULT 'draft',
        "progress" DECIMAL(5,2) NOT NULL DEFAULT 0,
        "notes" TEXT,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        "started_at" TIMESTAMP,
        "completed_at" TIMESTAMP,
        "deleted_at" TIMESTAMP,
        CONSTRAINT "PK_assessments_id" PRIMARY KEY ("id"),
        CONSTRAINT "FK_assessments_consultant" FOREIGN KEY ("consultant_id") REFERENCES "users"("id") ON DELETE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_assessments_consultant" ON "assessments" ("consultant_id")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_assessments_status" ON "assessments" ("status")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_assessments_updated" ON "assessments" ("updated_at")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_assessments_email" ON "assessments" ("client_email")
    `);

    // Create assessment_responses table
    await queryRunner.query(`
      CREATE TABLE "assessment_responses" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "assessment_id" uuid NOT NULL,
        "question_id" VARCHAR(50) NOT NULL,
        "answer" JSONB NOT NULL,
        "not_applicable" BOOLEAN NOT NULL DEFAULT false,
        "consultant_notes" TEXT,
        "answered_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_assessment_responses_id" PRIMARY KEY ("id"),
        CONSTRAINT "FK_assessment_responses_assessment" FOREIGN KEY ("assessment_id") REFERENCES "assessments"("id") ON DELETE CASCADE,
        CONSTRAINT "FK_assessment_responses_question" FOREIGN KEY ("question_id") REFERENCES "questions"("question_key") ON DELETE RESTRICT
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_assessment_responses_assessment" ON "assessment_responses" ("assessment_id")
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_assessment_responses_question" ON "assessment_responses" ("question_id")
    `);

    // Create disc_profiles table
    await queryRunner.query(`
      CREATE TABLE "disc_profiles" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "assessment_id" uuid NOT NULL,
        "d_score" FLOAT NOT NULL,
        "i_score" FLOAT NOT NULL,
        "s_score" FLOAT NOT NULL,
        "c_score" FLOAT NOT NULL,
        "primary_type" VARCHAR(1) NOT NULL,
        "secondary_type" VARCHAR(1),
        "confidence_level" VARCHAR(10) NOT NULL,
        "calculated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_disc_profiles_id" PRIMARY KEY ("id"),
        CONSTRAINT "FK_disc_profiles_assessment" FOREIGN KEY ("assessment_id") REFERENCES "assessments"("id") ON DELETE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_disc_profiles_assessment" ON "disc_profiles" ("assessment_id")
    `);

    // Create phase_results table
    await queryRunner.query(`
      CREATE TABLE "phase_results" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "assessment_id" uuid NOT NULL,
        "stabilize_score" FLOAT NOT NULL,
        "organize_score" FLOAT NOT NULL,
        "build_score" FLOAT NOT NULL,
        "grow_score" FLOAT NOT NULL,
        "systemic_score" FLOAT NOT NULL,
        "primary_phase" VARCHAR(10) NOT NULL,
        "secondary_phases" TEXT NOT NULL,
        "transition_state" BOOLEAN NOT NULL DEFAULT false,
        "calculated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_phase_results_id" PRIMARY KEY ("id"),
        CONSTRAINT "FK_phase_results_assessment" FOREIGN KEY ("assessment_id") REFERENCES "assessments"("id") ON DELETE CASCADE
      )
    `);

    await queryRunner.query(`
      CREATE INDEX "IDX_phase_results_assessment" ON "phase_results" ("assessment_id")
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop tables in reverse order
    await queryRunner.query(`DROP INDEX "IDX_phase_results_assessment"`);
    await queryRunner.query(`DROP TABLE "phase_results"`);

    await queryRunner.query(`DROP INDEX "IDX_disc_profiles_assessment"`);
    await queryRunner.query(`DROP TABLE "disc_profiles"`);

    await queryRunner.query(`DROP INDEX "IDX_assessment_responses_question"`);
    await queryRunner.query(`DROP INDEX "IDX_assessment_responses_assessment"`);
    await queryRunner.query(`DROP TABLE "assessment_responses"`);

    await queryRunner.query(`DROP INDEX "IDX_assessments_email"`);
    await queryRunner.query(`DROP INDEX "IDX_assessments_updated"`);
    await queryRunner.query(`DROP INDEX "IDX_assessments_status"`);
    await queryRunner.query(`DROP INDEX "IDX_assessments_consultant"`);
    await queryRunner.query(`DROP TABLE "assessments"`);

    await queryRunner.query(`DROP INDEX "IDX_questions_order"`);
    await queryRunner.query(`DROP INDEX "IDX_questions_type"`);
    await queryRunner.query(`DROP INDEX "IDX_questions_key"`);
    await queryRunner.query(`DROP TABLE "questions"`);

    await queryRunner.query(`DROP INDEX "IDX_users_email"`);
    await queryRunner.query(`DROP TABLE "users"`);

    // Drop ENUM types
    await queryRunner.query(`DROP TYPE "question_type_enum"`);
    await queryRunner.query(`DROP TYPE "assessment_status_enum"`);
    await queryRunner.query(`DROP TYPE "user_status_enum"`);
    await queryRunner.query(`DROP TYPE "user_role_enum"`);
  }
}
