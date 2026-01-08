import { MigrationInterface, QueryRunner } from "typeorm";

export class FixDatabaseSchema1767906953082 implements MigrationInterface {

    public async up(queryRunner: QueryRunner): Promise<void> {
        // Fix disc_profiles table - ensure assessment_id column exists
        await queryRunner.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'disc_profiles' AND column_name = 'assessment_id'
                ) THEN
                    ALTER TABLE disc_profiles
                    ADD COLUMN assessment_id UUID NOT NULL;
                END IF;
            END $$;
        `);

        // Fix reports table - add missing columns

        // Add status column if it doesn't exist
        await queryRunner.query(`
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_name = 'reports' AND column_name = 'status'
                ) THEN
                    CREATE TYPE report_status AS ENUM ('generating', 'completed', 'failed');
                    ALTER TABLE reports
                    ADD COLUMN status report_status DEFAULT 'generating';
                END IF;
            END $$;
        `);

        // Add file_url column if it doesn't exist
        await queryRunner.query(`
            ALTER TABLE reports
            ADD COLUMN IF NOT EXISTS file_url TEXT;
        `);

        // Add file_size_bytes column if it doesn't exist
        await queryRunner.query(`
            ALTER TABLE reports
            ADD COLUMN IF NOT EXISTS file_size_bytes INTEGER;
        `);

        // Add generated_at column if it doesn't exist
        await queryRunner.query(`
            ALTER TABLE reports
            ADD COLUMN IF NOT EXISTS generated_at TIMESTAMP;
        `);

        // Add expires_at column if it doesn't exist
        await queryRunner.query(`
            ALTER TABLE reports
            ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP;
        `);

        // Add error column if it doesn't exist
        await queryRunner.query(`
            ALTER TABLE reports
            ADD COLUMN IF NOT EXISTS error TEXT;
        `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        // Remove added columns in reverse order
        await queryRunner.query(`ALTER TABLE reports DROP COLUMN IF EXISTS error;`);
        await queryRunner.query(`ALTER TABLE reports DROP COLUMN IF EXISTS expires_at;`);
        await queryRunner.query(`ALTER TABLE reports DROP COLUMN IF EXISTS generated_at;`);
        await queryRunner.query(`ALTER TABLE reports DROP COLUMN IF EXISTS file_size_bytes;`);
        await queryRunner.query(`ALTER TABLE reports DROP COLUMN IF EXISTS file_url;`);
        await queryRunner.query(`ALTER TABLE reports DROP COLUMN IF EXISTS status;`);
        await queryRunner.query(`DROP TYPE IF EXISTS report_status;`);

        // Note: We don't remove assessment_id from disc_profiles as it might break data
    }

}
