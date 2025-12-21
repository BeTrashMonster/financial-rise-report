import { MigrationInterface, QueryRunner } from 'typeorm';

export class Phase2Features1734625300000 implements MigrationInterface {
  name = 'Phase2Features1734625300000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create checklist_items table
    await queryRunner.query(`
      CREATE TABLE "checklist_items" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "assessment_id" UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
        "item_text" TEXT NOT NULL,
        "item_order" INTEGER NOT NULL,
        "phase_category" VARCHAR(50) CHECK (phase_category IN ('stabilize', 'organize', 'build', 'grow', 'systemic')),
        "is_completed" BOOLEAN NOT NULL DEFAULT false,
        "completed_at" TIMESTAMP,
        "completed_by" VARCHAR(50) CHECK (completed_by IN ('consultant', 'client')),
        "priority" VARCHAR(20) CHECK (priority IN ('low', 'medium', 'high')),
        "due_date" DATE,
        "created_by_id" UUID NOT NULL REFERENCES users(id),
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "deleted_at" TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_checklist_items_assessment_id" ON "checklist_items" ("assessment_id")`);
    await queryRunner.query(`CREATE INDEX "idx_checklist_items_phase" ON "checklist_items" ("phase_category")`);
    await queryRunner.query(`CREATE INDEX "idx_checklist_items_completed" ON "checklist_items" ("is_completed")`);

    // Create consultant_settings table
    await queryRunner.query(`
      CREATE TABLE "consultant_settings" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "consultant_id" UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        "company_name" VARCHAR(200),
        "logo_url" TEXT,
        "brand_color" VARCHAR(7),
        "email_signature" TEXT,
        "email_templates" JSONB,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_consultant_settings_consultant_id" ON "consultant_settings" ("consultant_id")`);

    // Create scheduler_links table
    await queryRunner.query(`
      CREATE TABLE "scheduler_links" (
        "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        "consultant_id" UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        "meeting_type_label" VARCHAR(100) NOT NULL,
        "scheduler_url" TEXT NOT NULL,
        "duration_minutes" INTEGER,
        "recommended_for_phases" TEXT[],
        "is_active" BOOLEAN NOT NULL DEFAULT true,
        "display_order" INTEGER NOT NULL DEFAULT 0,
        "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        "deleted_at" TIMESTAMP
      )
    `);

    await queryRunner.query(`CREATE INDEX "idx_scheduler_links_consultant_id" ON "scheduler_links" ("consultant_id")`);
    await queryRunner.query(`CREATE INDEX "idx_scheduler_links_active" ON "scheduler_links" ("is_active")`);

    // Apply updated_at triggers to new tables
    await queryRunner.query(`
      CREATE TRIGGER update_checklist_items_updated_at
      BEFORE UPDATE ON checklist_items
      FOR EACH ROW
      EXECUTE FUNCTION update_updated_at_column();
    `);

    await queryRunner.query(`
      CREATE TRIGGER update_consultant_settings_updated_at
      BEFORE UPDATE ON consultant_settings
      FOR EACH ROW
      EXECUTE FUNCTION update_updated_at_column();
    `);

    await queryRunner.query(`
      CREATE TRIGGER update_scheduler_links_updated_at
      BEFORE UPDATE ON scheduler_links
      FOR EACH ROW
      EXECUTE FUNCTION update_updated_at_column();
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop triggers
    await queryRunner.query(`DROP TRIGGER IF EXISTS update_scheduler_links_updated_at ON scheduler_links`);
    await queryRunner.query(`DROP TRIGGER IF EXISTS update_consultant_settings_updated_at ON consultant_settings`);
    await queryRunner.query(`DROP TRIGGER IF EXISTS update_checklist_items_updated_at ON checklist_items`);

    // Drop tables
    await queryRunner.query(`DROP TABLE IF EXISTS "scheduler_links"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "consultant_settings"`);
    await queryRunner.query(`DROP TABLE IF EXISTS "checklist_items"`);
  }
}
