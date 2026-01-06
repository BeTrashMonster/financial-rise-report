import { MigrationInterface, QueryRunner } from 'typeorm';

/**
 * DEPRECATED: This migration is kept for historical purposes only.
 *
 * DO NOT USE - Questions are now managed via:
 * - Source: backend/content/assessment-questions.json (47 questions)
 * - Seeding: npm run seed:questions (backend/scripts/seed-questions.ts)
 *
 * This migration was overwritten by manual SQL execution and is no longer accurate.
 * Left in place so TypeORM doesn't complain about missing migrations.
 */
export class SeedQuestions1703700000003 implements MigrationInterface {
  name = 'SeedQuestions1703700000003';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // DEPRECATED: See class comment above
    // Seed questions with DISC and Phase scoring
    // This is based on the requirements and questionnaire service

    const questions = [
      // Confidence Assessment (Rating - Before)
      {
        question_key: 'CONF-001',
        question_text:
          'How confident do you feel about your business finances right now?',
        question_type: 'rating',
        options: JSON.stringify({
          min: 1,
          max: 10,
          labels: { 1: 'Not confident at all', 10: 'Extremely confident' },
        }),
        required: true,
        display_order: 1,
      },

      // Financial Stability Questions (Stabilize Phase)
      {
        question_key: 'FIN-001',
        question_text: 'How frequently do you review your financial statements?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'weekly',
              text: 'Weekly',
              discScores: { D: 15, I: 5, S: 0, C: 20 },
              phaseScores: {
                stabilize: 20,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 15,
              },
            },
            {
              value: 'monthly',
              text: 'Monthly',
              discScores: { D: 10, I: 10, S: 10, C: 15 },
              phaseScores: {
                stabilize: 15,
                organize: 10,
                build: 5,
                grow: 0,
                systemic: 10,
              },
            },
            {
              value: 'quarterly',
              text: 'Quarterly',
              discScores: { D: 5, I: 15, S: 15, C: 5 },
              phaseScores: {
                stabilize: 10,
                organize: 5,
                build: 0,
                grow: 0,
                systemic: 5,
              },
            },
            {
              value: 'annually',
              text: 'Annually or less',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 0,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 2,
      },

      {
        question_key: 'FIN-002',
        question_text: 'Do you have a current bookkeeping system in place?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_current',
              text: 'Yes, and it is up to date',
              discScores: { D: 15, I: 5, S: 10, C: 20 },
              phaseScores: {
                stabilize: 20,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 'yes_behind',
              text: 'Yes, but it is behind',
              discScores: { D: 5, I: 15, S: 15, C: 10 },
              phaseScores: {
                stabilize: 10,
                organize: 5,
                build: 0,
                grow: 0,
                systemic: 5,
              },
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 0,
                organize: 0,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 3,
      },

      {
        question_key: 'FIN-003',
        question_text: 'What is your business entity type?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'sole_proprietor',
              text: 'Sole Proprietor',
              discScores: { D: 10, I: 15, S: 15, C: 5 },
              phaseScores: {
                stabilize: 5,
                organize: 5,
                build: 0,
                grow: 0,
                systemic: 5,
              },
            },
            {
              value: 'llc',
              text: 'LLC',
              discScores: { D: 15, I: 10, S: 10, C: 15 },
              phaseScores: {
                stabilize: 15,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 's_corp',
              text: 'S-Corp',
              discScores: { D: 20, I: 5, S: 5, C: 20 },
              phaseScores: {
                stabilize: 20,
                organize: 20,
                build: 15,
                grow: 10,
                systemic: 15,
              },
            },
            {
              value: 'c_corp',
              text: 'C-Corp',
              discScores: { D: 20, I: 0, S: 0, C: 20 },
              phaseScores: {
                stabilize: 20,
                organize: 20,
                build: 20,
                grow: 15,
                systemic: 20,
              },
            },
          ],
        }),
        required: true,
        display_order: 4,
      },

      // Financial Organization Questions (Organize Phase)
      {
        question_key: 'ORG-001',
        question_text: 'Do you have a documented Chart of Accounts (COA)?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_customized',
              text: 'Yes, customized for my business',
              discScores: { D: 15, I: 5, S: 10, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 15,
                grow: 10,
                systemic: 15,
              },
            },
            {
              value: 'yes_default',
              text: 'Yes, using default template',
              discScores: { D: 5, I: 10, S: 15, C: 10 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 0,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 5,
      },

      {
        question_key: 'ORG-002',
        question_text:
          'Do you have a system for tracking accounts receivable (money owed to you)?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_automated',
              text: 'Yes, automated system',
              discScores: { D: 20, I: 5, S: 5, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 20,
                grow: 15,
                systemic: 15,
              },
            },
            {
              value: 'yes_manual',
              text: 'Yes, manual tracking',
              discScores: { D: 10, I: 10, S: 15, C: 15 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 'no',
              text: 'No formal system',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 0,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 6,
      },

      {
        question_key: 'ORG-003',
        question_text:
          'Do you have a system for tracking accounts payable (money you owe)?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_automated',
              text: 'Yes, automated system',
              discScores: { D: 20, I: 5, S: 5, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 20,
                grow: 15,
                systemic: 15,
              },
            },
            {
              value: 'yes_manual',
              text: 'Yes, manual tracking',
              discScores: { D: 10, I: 10, S: 15, C: 15 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 'no',
              text: 'No formal system',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 0,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 7,
      },

      // Build Phase Questions
      {
        question_key: 'BUILD-001',
        question_text:
          'Do you have documented Standard Operating Procedures (SOPs) for financial processes?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_comprehensive',
              text: 'Yes, comprehensive and up to date',
              discScores: { D: 20, I: 0, S: 10, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 20,
                grow: 15,
                systemic: 15,
              },
            },
            {
              value: 'yes_basic',
              text: 'Yes, but basic or outdated',
              discScores: { D: 10, I: 10, S: 15, C: 15 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 15,
                grow: 10,
                systemic: 10,
              },
            },
            {
              value: 'in_progress',
              text: 'In progress',
              discScores: { D: 15, I: 15, S: 10, C: 10 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 5,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 8,
      },

      {
        question_key: 'BUILD-002',
        question_text:
          'Do you have a process for monthly financial close and reconciliation?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_automated',
              text: 'Yes, mostly automated',
              discScores: { D: 20, I: 5, S: 5, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 20,
                grow: 15,
                systemic: 15,
              },
            },
            {
              value: 'yes_manual',
              text: 'Yes, manual process',
              discScores: { D: 10, I: 10, S: 15, C: 15 },
              phaseScores: {
                stabilize: 15,
                organize: 15,
                build: 15,
                grow: 10,
                systemic: 10,
              },
            },
            {
              value: 'sometimes',
              text: 'Sometimes',
              discScores: { D: 5, I: 15, S: 15, C: 10 },
              phaseScores: {
                stabilize: 10,
                organize: 10,
                build: 5,
                grow: 0,
                systemic: 5,
              },
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 0,
                build: 0,
                grow: 0,
                systemic: 0,
              },
            },
          ],
        }),
        required: true,
        display_order: 9,
      },

      // Grow Phase Questions
      {
        question_key: 'GROW-001',
        question_text: 'Do you have a formal budgeting process?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_detailed',
              text: 'Yes, detailed annual budget with monthly reviews',
              discScores: { D: 20, I: 0, S: 5, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 20,
                grow: 20,
                systemic: 20,
              },
            },
            {
              value: 'yes_basic',
              text: 'Yes, basic budget',
              discScores: { D: 15, I: 10, S: 10, C: 15 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 15,
                grow: 15,
                systemic: 15,
              },
            },
            {
              value: 'informal',
              text: 'Informal planning only',
              discScores: { D: 5, I: 15, S: 15, C: 5 },
              phaseScores: {
                stabilize: 10,
                organize: 10,
                build: 10,
                grow: 5,
                systemic: 10,
              },
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 5,
                build: 5,
                grow: 0,
                systemic: 5,
              },
            },
          ],
        }),
        required: true,
        display_order: 10,
      },

      {
        question_key: 'GROW-002',
        question_text:
          'Do you regularly create cash flow forecasts for the next 3-12 months?',
        question_type: 'single_choice',
        options: JSON.stringify({
          options: [
            {
              value: 'yes_monthly',
              text: 'Yes, updated monthly',
              discScores: { D: 20, I: 0, S: 5, C: 20 },
              phaseScores: {
                stabilize: 15,
                organize: 20,
                build: 20,
                grow: 20,
                systemic: 20,
              },
            },
            {
              value: 'yes_quarterly',
              text: 'Yes, updated quarterly',
              discScores: { D: 15, I: 10, S: 10, C: 15 },
              phaseScores: {
                stabilize: 10,
                organize: 15,
                build: 15,
                grow: 15,
                systemic: 15,
              },
            },
            {
              value: 'occasionally',
              text: 'Occasionally',
              discScores: { D: 5, I: 15, S: 15, C: 10 },
              phaseScores: {
                stabilize: 10,
                organize: 10,
                build: 10,
                grow: 10,
                systemic: 10,
              },
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 20, S: 20, C: 0 },
              phaseScores: {
                stabilize: 5,
                organize: 5,
                build: 5,
                grow: 0,
                systemic: 5,
              },
            },
          ],
        }),
        required: true,
        display_order: 11,
      },

      // Systemic (Financial Literacy) Questions
      {
        question_key: 'SYS-001',
        question_text:
          'How well do you understand your Profit & Loss (Income) Statement?',
        question_type: 'rating',
        options: JSON.stringify({
          min: 1,
          max: 10,
          labels: {
            1: 'Not at all',
            10: 'Completely understand and use regularly',
          },
          discScores: { D: 2, I: 1, S: 1, C: 2 },
          phaseScores: {
            stabilize: 2,
            organize: 2,
            build: 2,
            grow: 2,
            systemic: 4,
          },
        }),
        required: true,
        display_order: 12,
      },

      {
        question_key: 'SYS-002',
        question_text: 'How well do you understand your Balance Sheet?',
        question_type: 'rating',
        options: JSON.stringify({
          min: 1,
          max: 10,
          labels: {
            1: 'Not at all',
            10: 'Completely understand and use regularly',
          },
          discScores: { D: 2, I: 1, S: 1, C: 2 },
          phaseScores: {
            stabilize: 2,
            organize: 2,
            build: 2,
            grow: 2,
            systemic: 4,
          },
        }),
        required: true,
        display_order: 13,
      },

      {
        question_key: 'SYS-003',
        question_text: 'How well do you understand your Cash Flow Statement?',
        question_type: 'rating',
        options: JSON.stringify({
          min: 1,
          max: 10,
          labels: {
            1: 'Not at all',
            10: 'Completely understand and use regularly',
          },
          discScores: { D: 2, I: 1, S: 1, C: 2 },
          phaseScores: {
            stabilize: 2,
            organize: 2,
            build: 2,
            grow: 2,
            systemic: 4,
          },
        }),
        required: true,
        display_order: 14,
      },

      // Confidence Assessment (After)
      {
        question_key: 'CONF-002',
        question_text:
          'After reviewing these areas, how confident do you feel about working on your business finances?',
        question_type: 'rating',
        options: JSON.stringify({
          min: 1,
          max: 10,
          labels: { 1: 'Not confident at all', 10: 'Extremely confident' },
        }),
        required: true,
        display_order: 42,
      },
    ];

    for (const question of questions) {
      await queryRunner.query(
        `
        INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
        VALUES ($1, $2, $3, $4, $5, $6)
      `,
        [
          question.question_key,
          question.question_text,
          question.question_type,
          question.options,
          question.required,
          question.display_order,
        ],
      );
    }
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Delete all seeded questions
    await queryRunner.query(`DELETE FROM questions WHERE question_key LIKE 'CONF-%'`);
    await queryRunner.query(`DELETE FROM questions WHERE question_key LIKE 'FIN-%'`);
    await queryRunner.query(`DELETE FROM questions WHERE question_key LIKE 'ORG-%'`);
    await queryRunner.query(`DELETE FROM questions WHERE question_key LIKE 'BUILD-%'`);
    await queryRunner.query(`DELETE FROM questions WHERE question_key LIKE 'GROW-%'`);
    await queryRunner.query(`DELETE FROM questions WHERE question_key LIKE 'SYS-%'`);
  }
}
