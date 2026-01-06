/**
 * Generate SQL seed file from assessment-questions.json
 *
 * This script reads the unified question bank JSON and generates
 * SQL INSERT statements compatible with the PostgreSQL schema.
 *
 * Usage: node generate-seed.js
 * Output: seed-assessment-questions.sql
 */

const fs = require('fs');
const path = require('path');

// Read the unified question bank
const questionsPath = path.join(__dirname, 'assessment-questions.json');
const questionsData = JSON.parse(fs.readFileSync(questionsPath, 'utf8'));

// Map our JSON types to database enum values
function mapQuestionType(jsonType) {
  const typeMap = {
    'phase': 'single_choice',
    'phase_and_disc': 'single_choice',
    'metadata': 'single_choice',
    'multiple_choice': 'multiple_choice',
    'rating': 'rating',
    'text': 'text'
  };

  return typeMap[jsonType] || 'single_choice';
}

// Escape single quotes for SQL
function escapeSql(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/'/g, "''");
}

// Convert JSON to SQL-safe string
function toSqlJson(obj) {
  return escapeSql(JSON.stringify(obj));
}

// Generate SQL for a single question
function generateQuestionSql(question, displayOrder) {
  const questionKey = question.id;
  const questionText = escapeSql(question.text);
  const questionType = mapQuestionType(question.type);

  // For rating questions, structure options differently
  let options;
  if (question.type === 'rating') {
    options = {
      min: question.min,
      max: question.max,
      min_label: question.min_label,
      max_label: question.max_label,
      phase_scoring: question.phase_scoring
    };
  } else {
    // Store the complete question metadata in options
    options = {
      type: question.type,
      section: question.section,
      options: question.options
    };

    // Add conditional trigger if present
    if (question.conditional_trigger) {
      options.conditional_trigger = question.conditional_trigger;
    }

    // Add max_score for multiple choice
    if (question.max_score !== undefined) {
      options.max_score = question.max_score;
    }
  }

  const optionsJson = toSqlJson(options);
  const required = true; // All assessment questions are required

  return `INSERT INTO questions (question_key, question_text, question_type, options, required, display_order)
VALUES ('${questionKey}', '${questionText}', '${questionType}', '${optionsJson}', ${required}, ${displayOrder});`;
}

// Generate complete seed file
function generateSeedFile() {
  const lines = [];

  lines.push('-- =====================================================');
  lines.push('-- Financial RISE Assessment - Question Bank Seed');
  lines.push('-- =====================================================');
  lines.push('-- Generated: ' + new Date().toISOString());
  lines.push('-- Total Questions: ' + questionsData.questions.length);
  lines.push('-- =====================================================');
  lines.push('');
  lines.push('-- Clear existing questions');
  lines.push('TRUNCATE TABLE questions RESTART IDENTITY CASCADE;');
  lines.push('');
  lines.push('-- Insert all questions');
  lines.push('');

  questionsData.questions.forEach((question, index) => {
    const displayOrder = index + 1;
    const sql = generateQuestionSql(question, displayOrder);
    lines.push(sql);
    lines.push('');
  });

  lines.push('-- =====================================================');
  lines.push('-- Verification');
  lines.push('-- =====================================================');
  lines.push('SELECT COUNT(*) as total_questions FROM questions;');
  lines.push('');
  lines.push('-- Expected: ' + questionsData.questions.length + ' questions');
  lines.push('-- - 10 Stabilize');
  lines.push('-- - 9 Organize');
  lines.push('-- - 8 Build');
  lines.push('-- - 4 Metadata');
  lines.push('-- - 6 Grow');
  lines.push('-- - 10 Systemic');
  lines.push('');

  return lines.join('\n');
}

// Write seed file
const seedSql = generateSeedFile();
const outputPath = path.join(__dirname, 'seed-assessment-questions.sql');
fs.writeFileSync(outputPath, seedSql, 'utf8');

console.log(`✅ Generated ${outputPath}`);
console.log(`   Total questions: ${questionsData.questions.length}`);
console.log(`   File size: ${(seedSql.length / 1024).toFixed(2)} KB`);
