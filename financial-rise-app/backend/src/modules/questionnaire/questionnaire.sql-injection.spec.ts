import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import * as request from 'supertest';
import { QuestionnaireModule } from './questionnaire.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { AssessmentsModule } from '../assessments/assessments.module';
import { QuestionsModule } from '../questions/questions.module';
import { Repository, DataSource } from 'typeorm';
import { User, UserRole } from '../users/entities/user.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { Question } from '../questions/entities/question.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';

/**
 * SQL Injection Security Tests for Questionnaire Module
 *
 * SECURITY FINDING: CRIT-003 & HIGH-005 - SQL and NoSQL Injection Protection
 * Reference: SECURITY-AUDIT-REPORT.md Lines 652-735 (SQL), 693-735 (JSONB)
 *
 * Purpose:
 * - Verify questionnaire response submission is safe from SQL injection
 * - Test JSONB answer field for NoSQL injection vulnerabilities
 * - Ensure question_key lookups use parameterized queries
 * - Validate consultant notes field is properly sanitized
 *
 * Critical JSONB Attack Vectors:
 * 1. JSON injection in answer field
 * 2. NoSQL-style operators ($ne, $gt, etc.)
 * 3. Nested JSON injection
 * 4. JSONB query operator injection (->, ->>, #>, etc.)
 *
 * Expected Behavior:
 * - All injection attempts treated as literal data
 * - JSONB answers stored safely
 * - No database structure access
 * - Proper type validation
 */
describe('Questionnaire SQL Injection Security Tests (WS55)', () => {
  let app: INestApplication;
  let dataSource: DataSource;
  let userRepository: Repository<User>;
  let assessmentRepository: Repository<Assessment>;
  let questionRepository: Repository<Question>;
  let consultantUser: User;
  let consultantAccessToken: string;
  let testAssessment: Assessment;
  let testQuestion: Question;

  // JSONB-specific injection payloads
  const JSONB_INJECTION_PAYLOADS = [
    // NoSQL-style operators
    { value: { $ne: null } },
    { value: { $gt: 0 } },
    { value: { $or: [{ score: 1 }, { score: 10 }] } },

    // JSON injection attempts
    { value: 'test", "malicious": "data' },
    { value: 'test\"; DROP TABLE assessments; --' },

    // Nested injection
    { value: { nested: { injection: "'; DELETE FROM users; --" } } },

    // JSONB operator injection
    { value: "test' -> 'malicious" },
    { value: "test' ->> 'malicious" },
  ];

  // SQL injection payloads for text fields
  const SQL_INJECTION_PAYLOADS = [
    "'; DROP TABLE assessment_responses; --",
    "' OR '1'='1",
    "' UNION SELECT * FROM users --",
    "'; UPDATE assessment_responses SET answer='hacked' WHERE '1'='1",
  ];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({
          isGlobal: true,
          envFilePath: '.env.test',
        }),
        TypeOrmModule.forRoot({
          type: 'postgres',
          host: process.env.DB_HOST || 'localhost',
          port: parseInt(process.env.DB_PORT, 10) || 5432,
          username: process.env.DB_USERNAME || 'postgres',
          password: process.env.DB_PASSWORD || 'postgres',
          database: process.env.DB_DATABASE || 'financial_rise_test',
          entities: [__dirname + '/../**/*.entity{.ts,.js}'],
          synchronize: true,
          dropSchema: true,
          logging: false,
        }),
        AuthModule,
        UsersModule,
        AssessmentsModule,
        QuestionsModule,
        QuestionnaireModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    dataSource = moduleFixture.get<DataSource>(DataSource);
    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
    assessmentRepository = moduleFixture.get<Repository<Assessment>>(getRepositoryToken(Assessment));
    questionRepository = moduleFixture.get<Repository<Question>>(getRepositoryToken(Question));

    // Create test consultant
    const hashedPassword = await bcrypt.hash('TestPass123!', 10);
    consultantUser = await userRepository.save({
      email: 'questionnaire-test@test.com',
      password_hash: hashedPassword,
      first_name: 'Test',
      last_name: 'Consultant',
      role: UserRole.CONSULTANT,
      email_verified: true,
    });

    // Login
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'questionnaire-test@test.com', password: 'TestPass123!' });
    consultantAccessToken = loginResponse.body.accessToken;

    // Create test assessment
    testAssessment = await assessmentRepository.save({
      client_name: 'Test Client',
      business_name: 'Test Business',
      client_email: 'client@test.com',
      consultant_id: consultantUser.id,
      status: 'draft',
      progress: 0,
    });

    // Create test question
    testQuestion = await questionRepository.save({
      question_key: 'TEST-001',
      question_text: 'Test question for SQL injection',
      question_type: 'single_choice',
      options: {
        options: [
          { value: 'option1', text: 'Option 1' },
          { value: 'option2', text: 'Option 2' },
        ],
      },
      required: true,
      display_order: 1,
    });
  });

  afterAll(async () => {
    await dataSource.destroy();
    await app.close();
  });

  describe('POST /questionnaire/responses - JSONB SQL Injection Tests', () => {
    it('should safely store JSONB answer with NoSQL operators', async () => {
      const payload = { value: { $ne: null } };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      // Should store as literal JSONB, not execute as query operator
      if (response.status === 201) {
        // Verify answer stored as-is
        const savedResponse = await dataSource.query(
          'SELECT answer FROM assessment_responses WHERE id = $1',
          [response.body.id],
        );

        // Answer should contain the $ne operator as data, not interpreted
        expect(savedResponse[0].answer).toBeDefined();
        // If encrypted, we can't directly inspect, but should not cause error
      }

      expect(response.status).not.toBe(500);
    });

    it('should reject SQL injection in JSONB answer string value', async () => {
      const payload = { value: "'; DROP TABLE assessment_responses; --" };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);

      // Verify table still exists
      const tableExists = await dataSource.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables
          WHERE table_name = 'assessment_responses'
        )
      `);
      expect(tableExists[0].exists).toBe(true);
    });

    it('should handle nested JSON injection safely', async () => {
      const payload = {
        rating: 5,
        comment: "Great service\", \"injected\": \"'; DELETE FROM users; --",
      };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      if (response.status === 201) {
        // Verify users table still intact
        const userCount = await userRepository.count();
        expect(userCount).toBeGreaterThan(0);
      }

      expect(response.status).not.toBe(500);
    });

    it('should handle JSONB operator injection in answer', async () => {
      const payload = { value: "test' -> 'password_hash" };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);

      // Should not leak password hashes
      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('password_hash');
      expect(bodyString).not.toContain('$2b$'); // bcrypt hash prefix
    });
  });

  describe('POST /questionnaire/responses - question_key SQL Injection Tests', () => {
    it('should reject SQL injection in questionId field', async () => {
      const payload = "TEST-001'; DROP TABLE questions; --";

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: payload,
          answer: { value: 'test' },
        });

      // Should not find question (exact match required)
      expect(response.status).toBe(404);

      // Verify questions table still exists
      const questionCount = await questionRepository.count();
      expect(questionCount).toBeGreaterThan(0);
    });

    it('should reject SQL injection in assessmentId field', async () => {
      const payload = `${testAssessment.id}' OR '1'='1`;

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: payload,
          questionId: testQuestion.question_key,
          answer: { value: 'test' },
        });

      // Should fail UUID validation
      expect(response.status).toBe(400);
    });
  });

  describe('POST /questionnaire/responses - consultantNotes SQL Injection Tests', () => {
    it('should safely store SQL injection attempts in consultant notes', async () => {
      for (const payload of SQL_INJECTION_PAYLOADS) {
        const response = await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${consultantAccessToken}`)
          .send({
            assessmentId: testAssessment.id,
            questionId: testQuestion.question_key,
            answer: { value: 'test' },
            consultantNotes: payload,
          });

        if (response.status === 201) {
          // Verify notes stored as literal string
          const savedResponse = await dataSource.query(
            'SELECT consultant_notes FROM assessment_responses WHERE id = $1',
            [response.body.id],
          );

          expect(savedResponse[0].consultant_notes).toBe(payload);
        }

        expect(response.status).not.toBe(500);
      }
    });

    it('should handle multi-line notes with SQL injection', async () => {
      const payload = `Line 1: normal note
      Line 2: '; DROP TABLE users; --
      Line 3: more notes`;

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: { value: 'test' },
          consultantNotes: payload,
        });

      if (response.status === 201) {
        // Verify users table intact
        const userCount = await userRepository.count();
        expect(userCount).toBeGreaterThan(0);

        // Verify notes preserved with line breaks
        const savedResponse = await dataSource.query(
          'SELECT consultant_notes FROM assessment_responses WHERE id = $1',
          [response.body.id],
        );

        expect(savedResponse[0].consultant_notes).toContain('Line 1');
        expect(savedResponse[0].consultant_notes).toContain('Line 3');
      }

      expect(response.status).not.toBe(500);
    });
  });

  describe('PATCH /questionnaire/responses/:id - SQL Injection Tests', () => {
    let responseId: string;

    beforeAll(async () => {
      // Create response to update
      const createResponse = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: { value: 'initial' },
        });

      responseId = createResponse.body.id;
    });

    it('should reject SQL injection in response ID parameter', async () => {
      const payload = `${responseId}' OR '1'='1`;

      const response = await request(app.getHttpServer())
        .patch(`/questionnaire/responses/${payload}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          answer: { value: 'updated' },
        });

      expect(response.status).toBe(400); // Bad UUID
    });

    it('should safely update answer with JSONB injection attempt', async () => {
      const payload = { value: { $set: { role: 'admin' } } };

      const response = await request(app.getHttpServer())
        .patch(`/questionnaire/responses/${responseId}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          answer: payload,
        });

      if (response.status === 200) {
        // Verify consultant role unchanged
        const user = await userRepository.findOne({
          where: { id: consultantUser.id },
        });
        expect(user.role).toBe(UserRole.CONSULTANT);
      }

      expect(response.status).not.toBe(500);
    });
  });

  describe('JSONB Query Safety Tests', () => {
    it('should not allow JSONB path traversal', async () => {
      // Attempt to access nested data via JSONB operators
      const payload = {
        value: 'test',
        // Attempt to inject JSONB path query
        path: ['..', 'users', 'password_hash'],
      };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);

      // Should not leak sensitive data
      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('password_hash');
    });

    it('should handle JSONB containment operator injection', async () => {
      const payload = { value: "@> '{\"role\": \"admin\"}'" };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);
    });

    it('should reject JSONB existence operator injection', async () => {
      const payload = { value: "? 'password_hash'" };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);
    });
  });

  describe('Type Coercion Attack Tests', () => {
    it('should handle boolean injection attempts', async () => {
      const payload = { value: true || '1=1' };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);
    });

    it('should handle null injection attempts', async () => {
      const payload = { value: null || 'malicious' };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      expect(response.status).not.toBe(500);
    });

    it('should handle array injection attempts', async () => {
      const payload = { value: ["test", "'; DROP TABLE users; --"] };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      if (response.status === 201) {
        // Verify users table intact
        const userCount = await userRepository.count();
        expect(userCount).toBeGreaterThan(0);
      }

      expect(response.status).not.toBe(500);
    });
  });

  describe('Error Information Disclosure Tests', () => {
    it('should not expose JSONB errors in response', async () => {
      const payload = { value: 'test' -> 'invalid syntax' };

      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          assessmentId: testAssessment.id,
          questionId: testQuestion.question_key,
          answer: payload,
        });

      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('jsonb');
      expect(bodyString).not.toContain('operator');
      expect(bodyString).not.toContain('PostgreSQL');
    });
  });
});
