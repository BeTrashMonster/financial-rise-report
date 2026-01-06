import { DataSource } from 'typeorm';
import * as fs from 'fs';
import * as path from 'path';
import { config } from 'dotenv';

// Load environment variables
config();

/**
 * Script to seed assessment questions from assessment-questions.json
 * Run: npm run seed:questions
 */

interface QuestionOption {
  value: string;
  label: string;
  stabilize_score?: number;
  organize_score?: number;
  build_score?: number;
  grow_score?: number;
  systemic_score?: number;
  disc_d_score?: number;
  disc_i_score?: number;
  disc_s_score?: number;
  disc_c_score?: number;
}

interface Question {
  id: string;
  text: string;
  type: 'phase' | 'disc' | 'confidence_before' | 'confidence_after' | 'rating';
  section?: string;
  display_order: number;
  options?: QuestionOption[];
  min?: number;
  max?: number;
  labels?: Record<number, string>;
}

interface QuestionData {
  questions: Question[];
}

async function seedQuestions() {
  console.log('🌱 Starting question seeding process...\n');

  // Create database connection
  const dataSource = new DataSource({
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    username: process.env.DB_USERNAME || 'postgres',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'financial_rise',
    ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
  });

  try {
    await dataSource.initialize();
    console.log('✅ Database connected\n');

    // Load questions from JSON
    const questionsPath = path.join(__dirname, '..', 'content', 'assessment-questions.json');
    const questionsData: QuestionData = JSON.parse(fs.readFileSync(questionsPath, 'utf-8'));

    console.log(`📚 Loaded ${questionsData.questions.length} questions from JSON\n`);

    // Delete existing questions
    console.log('🗑️  Deleting existing questions...');
    await dataSource.query('DELETE FROM assessment_responses WHERE TRUE');
    await dataSource.query('DELETE FROM questions WHERE TRUE');
    console.log('✅ Old questions deleted\n');

    // Transform and insert new questions
    console.log('📝 Inserting new questions...\n');

    for (const question of questionsData.questions) {
      let questionType: string;
      let options: any;

      // Determine question type and format options
      if (question.type === 'confidence_before' || question.type === 'confidence_after') {
        questionType = 'rating';
        options = {
          min: question.min || 1,
          max: question.max || 10,
          labels: question.labels || {},
        };
      } else if (question.type === 'rating') {
        questionType = 'rating';
        options = {
          min: question.min || 1,
          max: question.max || 10,
          labels: question.labels || {},
        };
      } else {
        questionType = 'single_choice';
        options = {
          options: (question.options || []).map(opt => ({
            value: opt.value,
            text: opt.label,
            // Phase scores
            phase_scores: {
              stabilize: opt.stabilize_score || 0,
              organize: opt.organize_score || 0,
              build: opt.build_score || 0,
              grow: opt.grow_score || 0,
              systemic: opt.systemic_score || 0,
            },
            // DISC scores (only for disc-type questions)
            ...(opt.disc_d_score !== undefined && {
              disc_scores: {
                disc_d_score: opt.disc_d_score || 0,
                disc_i_score: opt.disc_i_score || 0,
                disc_s_score: opt.disc_s_score || 0,
                disc_c_score: opt.disc_c_score || 0,
              },
            }),
          })),
        };
      }

      await dataSource.query(
        `
        INSERT INTO questions (question_key, question_text, question_type, options, required, display_order, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
        `,
        [
          question.id,
          question.text,
          questionType,
          JSON.stringify(options),
          true,
          question.display_order,
        ]
      );

      console.log(`  ✓ ${question.id}: ${question.text.substring(0, 60)}...`);
    }

    console.log(`\n✅ Successfully seeded ${questionsData.questions.length} questions!\n`);
    console.log('📊 Question breakdown:');

    const phaseCounts = questionsData.questions.reduce((acc, q) => {
      const type = q.type === 'phase' ? q.section || 'unknown' : q.type;
      acc[type] = (acc[type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    Object.entries(phaseCounts).forEach(([type, count]) => {
      console.log(`  - ${type}: ${count} questions`);
    });

  } catch (error) {
    console.error('❌ Error seeding questions:', error);
    throw error;
  } finally {
    await dataSource.destroy();
    console.log('\n✅ Database connection closed');
  }
}

// Run the seeding
seedQuestions()
  .then(() => {
    console.log('\n🎉 Question seeding completed successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('\n💥 Question seeding failed:', error);
    process.exit(1);
  });
