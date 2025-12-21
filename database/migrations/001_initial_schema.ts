import { MigrationInterface, QueryRunner } from 'typeorm';

export class InitialSchema1734625200000 implements MigrationInterface {
  name = 'InitialSchema1734625200000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Enable UUID extension
    await queryRunner.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`);

    // Create users table
    await queryRunner.query(`
      CREATE TABLE "users" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "email" VARCHAR(255) NOT NULL UNIQUE,
        "password_hash" VARCHAR(255) NOT NULL,
        "role" VARCHAR(50) NOT NULL CHECK (role IN ('consultant', 'admin')),
        "first_name" VARCHAR(100) NOT NULL,
        "last_name" VARCHAR(100) NOT NULL,
        "is_active" BOOLEAN NOT NULL DEFAULT true,
        "failed_login_attempts" INTEGER NOT NULL DEFAULT 0,
        "account_locked_until" TIMESTAMP,
        "last_login_at" TIMESTAMP,
        "password_reset_token" VARCHAR(255),
        "password_reset_expires" TIMESTAMP,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "deleted_at" TIMESTAMP
      )
    `);

    // Create assessments table
    await queryRunner.query(`
      CREATE TABLE "assessments" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "consultant_id" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        "client_name" VARCHAR(100) NOT NULL,
        "client_business_name" VARCHAR(200) NOT NULL,
        "client_email" VARCHAR(255) NOT NULL,
        "status" VARCHAR(50) NOT NULL CHECK (status IN ('draft', 'in_progress', 'completed')) DEFAULT 'draft',
        "entity_type" VARCHAR(100),
        "is_s_corp_on_payroll" BOOLEAN,
        "confidence_before" INTEGER CHECK (confidence_before >= 1 AND confidence_before <= 10),
        "confidence_after" INTEGER CHECK (confidence_after >= 1 AND confidence_after <= 10),
        "progress_percentage" DECIMAL(5,2) NOT NULL DEFAULT 0.00 CHECK (progress_percentage >= 0 AND progress_percentage <= 100),
        "started_at" TIMESTAMP,
        "completed_at" TIMESTAMP,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "deleted_at" TIMESTAMP,
        "archived_at" TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_assessments_consultant_id" ON "assessments" ("consultant_id")`);
    await queryRunner.query(`CREATE INDEX "idx_assessments_status" ON "assessments" ("status")`);
    await queryRunner.query(`CREATE INDEX "idx_assessments_client_email" ON "assessments" ("client_email")`);
    await queryRunner.query(`CREATE INDEX "idx_assessments_created_at" ON "assessments" ("created_at" DESC)`);

    // Create questions table
    await queryRunner.query(`
      CREATE TABLE "questions" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "question_text" TEXT NOT NULL,
        "question_type" VARCHAR(50) NOT NULL CHECK (question_type IN ('single_choice', 'multiple_choice', 'rating', 'text')),
        "section" VARCHAR(100) NOT NULL CHECK (section IN ('stabilize', 'organize', 'build', 'grow', 'systemic', 'disc', 'metadata')),
        "order_index" INTEGER NOT NULL,
        "is_required" BOOLEAN NOT NULL DEFAULT true,
        "is_conditional" BOOLEAN NOT NULL DEFAULT false,
        "conditional_parent_id" UUID REFERENCES questions(id),
        "conditional_trigger_value" TEXT,
        "disc_trait_mapping" JSONB,
        "phase_weight_mapping" JSONB,
        "answer_options" JSONB,
        "help_text" TEXT,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "deleted_at" TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_questions_section" ON "questions" ("section")`);
    await queryRunner.query(`CREATE INDEX "idx_questions_order" ON "questions" ("order_index")`);
    await queryRunner.query(`CREATE INDEX "idx_questions_conditional_parent" ON "questions" ("conditional_parent_id")`);

    // Create responses table
    await queryRunner.query(`
      CREATE TABLE "responses" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "assessment_id" UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        "question_id" UUID NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
        "answer_value" TEXT,
        "answer_numeric" INTEGER,
        "is_not_applicable" BOOLEAN NOT NULL DEFAULT false,
        "consultant_notes" TEXT,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(assessment_id, question_id)
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_responses_assessment_id" ON "responses" ("assessment_id")`);
    await queryRunner.query(`CREATE INDEX "idx_responses_question_id" ON "responses" ("question_id")`);

    // Create disc_profiles table
    await queryRunner.query(`
      CREATE TABLE "disc_profiles" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "assessment_id" UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
        "dominance_score" DECIMAL(5,2) NOT NULL CHECK (dominance_score >= 0 AND dominance_score <= 100),
        "influence_score" DECIMAL(5,2) NOT NULL CHECK (influence_score >= 0 AND influence_score <= 100),
        "steadiness_score" DECIMAL(5,2) NOT NULL CHECK (steadiness_score >= 0 AND steadiness_score <= 100),
        "compliance_score" DECIMAL(5,2) NOT NULL CHECK (compliance_score >= 0 AND compliance_score <= 100),
        "primary_type" VARCHAR(20) NOT NULL CHECK (primary_type IN ('D', 'I', 'S', 'C')),
        "secondary_type" VARCHAR(20) CHECK (secondary_type IN ('D', 'I', 'S', 'C')),
        "calculated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_disc_profiles_assessment_id" ON "disc_profiles" ("assessment_id")`);
    await queryRunner.query(`CREATE INDEX "idx_disc_profiles_primary_type" ON "disc_profiles" ("primary_type")`);

    // Create phase_results table
    await queryRunner.query(`
      CREATE TABLE "phase_results" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "assessment_id" UUID NOT NULL UNIQUE REFERENCES assessments(id) ON DELETE CASCADE,
        "stabilize_score" DECIMAL(5,2) NOT NULL CHECK (stabilize_score >= 0 AND stabilize_score <= 100),
        "organize_score" DECIMAL(5,2) NOT NULL CHECK (organize_score >= 0 AND organize_score <= 100),
        "build_score" DECIMAL(5,2) NOT NULL CHECK (build_score >= 0 AND build_score <= 100),
        "grow_score" DECIMAL(5,2) NOT NULL CHECK (grow_score >= 0 AND grow_score <= 100),
        "systemic_score" DECIMAL(5,2) NOT NULL CHECK (systemic_score >= 0 AND systemic_score <= 100),
        "primary_phase" VARCHAR(50) NOT NULL CHECK (primary_phase IN ('stabilize', 'organize', 'build', 'grow', 'systemic')),
        "secondary_phases" TEXT[],
        "calculated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_phase_results_assessment_id" ON "phase_results" ("assessment_id")`);
    await queryRunner.query(`CREATE INDEX "idx_phase_results_primary_phase" ON "phase_results" ("primary_phase")`);

    // Create reports table
    await queryRunner.query(`
      CREATE TABLE "reports" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "assessment_id" UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        "report_type" VARCHAR(50) NOT NULL CHECK (report_type IN ('consultant', 'client')),
        "file_url" TEXT NOT NULL,
        "file_size_bytes" BIGINT,
        "page_count" INTEGER,
        "generated_by_id" UUID NOT NULL REFERENCES users(id),
        "is_shared" BOOLEAN NOT NULL DEFAULT false,
        "share_token" VARCHAR(255) UNIQUE,
        "share_expires_at" TIMESTAMP,
        "view_count" INTEGER NOT NULL DEFAULT 0,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_reports_assessment_id" ON "reports" ("assessment_id")`);
    await queryRunner.query(`CREATE INDEX "idx_reports_type" ON "reports" ("report_type")`);
    await queryRunner.query(`CREATE INDEX "idx_reports_share_token" ON "reports" ("share_token")`);
    await queryRunner.query(`CREATE INDEX "idx_reports_created_at" ON "reports" ("created_at" DESC)`);

    // Create activity_logs table
    await queryRunner.query(`
      CREATE TABLE "activity_logs" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "user_id" UUID REFERENCES users(id) ON DELETE SET NULL,
        "event_type" VARCHAR(100) NOT NULL,
        "event_category" VARCHAR(50) NOT NULL CHECK (event_category IN ('auth', 'assessment', 'report', 'admin', 'system')),
        "description" TEXT NOT NULL,
        "ip_address" INET,
        "user_agent" TEXT,
        "metadata" JSONB,
        "severity" VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')) DEFAULT 'info',
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_activity_logs_user_id" ON "activity_logs" ("user_id")`);
    await queryRunner.query(`CREATE INDEX "idx_activity_logs_event_type" ON "activity_logs" ("event_type")`);
    await queryRunner.query(`CREATE INDEX "idx_activity_logs_event_category" ON "activity_logs" ("event_category")`);
    await queryRunner.query(`CREATE INDEX "idx_activity_logs_severity" ON "activity_logs" ("severity")`);
    await queryRunner.query(`CREATE INDEX "idx_activity_logs_created_at" ON "activity_logs" ("created_at" DESC)`);

    // Create updated_at trigger function
    await queryRunner.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = CURRENT_TIMESTAMP;
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;
    `);

    // Apply triggers
    const tablesWithUpdatedAt = [
      'users',
      'assessments',
      'questions',
      'responses',
      'disc_profiles',
      'phase_results',
      'reports',
    ];

    for (const table of tablesWithUpdatedAt) {
      await queryRunner.query(`
        CREATE TRIGGER update_${table}_updated_at
        BEFORE UPDATE ON ${table}
        FOR EACH ROW
        EXECUTE FUNCTION update_updated_at_column();
      `);
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop triggers
    const tablesWithUpdatedAt = [
      'users',
      'assessments',
      'questions',
      'responses',
      'disc_profiles',
      'phase_results',
      'reports',
    ];

    for (const table of tablesWithUpdatedAt) {
      await queryRunner.query(`DROP TRIGGER IF EXISTS update_${table}_updated_at ON ${table}`);
    }

    await queryRunner.query(`DROP FUNCTION IF EXISTS update_updated_at_column()`);

    // Drop tables in reverse order (respecting foreign keys)
    await queryRunner.query(`DROP TABLE IF EXISTS "activity_logs"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "reports"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "phase_results"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "disc_profiles"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "responses"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "questions"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "assessments"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "users"`);
  }
}
