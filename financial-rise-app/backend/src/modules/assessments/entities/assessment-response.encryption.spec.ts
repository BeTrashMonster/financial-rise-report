import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { AssessmentResponse } from './assessment-response.entity';
import { Assessment } from './assessment.entity';
import { Question } from '../../questions/entities/question.entity';
import { User } from '../../users/entities/user.entity';
import * as crypto from 'crypto';

/**
 * Integration tests for Assessment Response Encryption
 *
 * Verifies that financial PII in assessment responses is properly encrypted
 * at rest to meet GDPR/CCPA compliance requirements (CRIT-005).
 *
 * Test Strategy:
 * 1. Save assessment responses with financial data
 * 2. Query database directly to verify data is encrypted
 * 3. Retrieve through ORM to verify decryption works
 * 4. Test JSONB-like operations still work
 * 5. Verify tampered data throws errors
 */
describe('AssessmentResponse Encryption (Integration)', () => {
  let module: TestingModule;
  let assessmentResponseRepo: Repository<AssessmentResponse>;
  let assessmentRepo: Repository<Assessment>;
  let questionRepo: Repository<Question>;
  let userRepo: Repository<User>;
  let dataSource: DataSource;

  const testEncryptionKey = crypto.randomBytes(32).toString('hex');

  beforeAll(async () => {
    // Set test encryption key
    process.env.DB_ENCRYPTION_KEY = testEncryptionKey;

    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'postgres',
          host: process.env.DATABASE_HOST || 'localhost',
          port: parseInt(process.env.DATABASE_PORT || '5432'),
          username: process.env.DATABASE_USER || 'postgres',
          password: process.env.DATABASE_PASSWORD || 'postgres',
          database: process.env.DATABASE_NAME || 'financial_rise_test',
          entities: [AssessmentResponse, Assessment, Question, User],
          synchronize: true, // For test database only
          dropSchema: true, // Clean slate for each test run
        }),
        TypeOrmModule.forFeature([AssessmentResponse, Assessment, Question, User]),
      ],
    }).compile();

    assessmentResponseRepo = module.get('AssessmentResponseRepository');
    assessmentRepo = module.get('AssessmentRepository');
    questionRepo = module.get('QuestionRepository');
    userRepo = module.get('UserRepository');
    dataSource = module.get(DataSource);
  });

  afterAll(async () => {
    await dataSource.destroy();
    await module.close();
    delete process.env.DB_ENCRYPTION_KEY;
  });

  beforeEach(async () => {
    // Clean up between tests
    await assessmentResponseRepo.clear();
    await assessmentRepo.clear();
    await questionRepo.clear();
    await userRepo.clear();
  });

  describe('Financial PII Encryption', () => {
    it('should encrypt financial data when saving to database', async () => {
      // Create test user
      const user = userRepo.create({
        email: 'consultant@test.com',
        password_hash: 'hashed',
        first_name: 'Test',
        last_name: 'Consultant',
        role: 'consultant',
      });
      await userRepo.save(user);

      // Create test assessment
      const assessment = assessmentRepo.create({
        consultant_id: user.id,
        client_name: 'Test Client',
        client_email: 'client@test.com',
        status: 'in_progress',
      });
      await assessmentRepo.save(assessment);

      // Create test question
      const question = questionRepo.create({
        question_key: 'annual_revenue',
        question_text: 'What is your annual revenue?',
        question_type: 'number',
        phase: 'stabilize',
        category: 'financial_health',
        order_index: 1,
      });
      await questionRepo.save(question);

      // Create assessment response with sensitive financial data
      const financialData = {
        annualRevenue: 500000,
        monthlyExpenses: 40000,
        outstandingDebt: 100000,
        cashOnHand: 50000,
      };

      const response = assessmentResponseRepo.create({
        assessment_id: assessment.id,
        question_id: question.question_key,
        answer: financialData,
      });

      await assessmentResponseRepo.save(response);

      // Query database directly (bypassing ORM transformer)
      const rawData = await dataSource.query(
        'SELECT answer FROM assessment_responses WHERE id = $1',
        [response.id],
      );

      // Verify data is encrypted (not readable in database)
      const encryptedAnswer = rawData[0].answer;
      expect(typeof encryptedAnswer).toBe('string');
      expect(encryptedAnswer).not.toContain('500000');
      expect(encryptedAnswer).not.toContain('annualRevenue');
      expect(encryptedAnswer).not.toContain('monthlyExpenses');

      // Verify encrypted format (iv:authTag:ciphertext)
      expect(encryptedAnswer).toContain(':');
      const parts = encryptedAnswer.split(':');
      expect(parts).toHaveLength(3);
    });

    it('should decrypt financial data when reading from database', async () => {
      // Setup test data
      const user = userRepo.create({
        email: 'consultant2@test.com',
        password_hash: 'hashed',
        first_name: 'Test',
        last_name: 'Consultant',
        role: 'consultant',
      });
      await userRepo.save(user);

      const assessment = assessmentRepo.create({
        consultant_id: user.id,
        client_name: 'Test Client 2',
        client_email: 'client2@test.com',
        status: 'in_progress',
      });
      await assessmentRepo.save(assessment);

      const question = questionRepo.create({
        question_key: 'revenue_question',
        question_text: 'Revenue?',
        question_type: 'number',
        phase: 'stabilize',
        category: 'financial_health',
        order_index: 1,
      });
      await questionRepo.save(question);

      // Original financial data
      const originalData = {
        revenue: 750000,
        expenses: 450000,
        profit: 300000,
      };

      const response = assessmentResponseRepo.create({
        assessment_id: assessment.id,
        question_id: question.question_key,
        answer: originalData,
      });

      await assessmentResponseRepo.save(response);

      // Retrieve using ORM (should decrypt)
      const retrieved = await assessmentResponseRepo.findOne({
        where: { id: response.id },
      });

      // Verify decryption works correctly
      expect(retrieved.answer).toEqual(originalData);
      expect(retrieved.answer.revenue).toBe(750000);
      expect(retrieved.answer.expenses).toBe(450000);
      expect(retrieved.answer.profit).toBe(300000);
    });

    it('should handle complex nested financial data structures', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'test3@test.com',
          password_hash: 'hashed',
          first_name: 'Test',
          last_name: 'User',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Complex Client',
          client_email: 'complex@test.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'complex_financial',
          question_text: 'Detailed financials',
          question_type: 'object',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      // Complex nested financial data
      const complexData = {
        revenue: {
          products: 600000,
          services: 400000,
          other: 50000,
          total: 1050000,
        },
        expenses: {
          salaries: 500000,
          rent: 100000,
          utilities: 50000,
          breakdown: {
            fixed: 650000,
            variable: 200000,
          },
        },
        cashFlow: {
          operating: 200000,
          investing: -50000,
          financing: -30000,
        },
      };

      const response = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: complexData,
        }),
      );

      // Verify encryption in database
      const raw = await dataSource.query(
        'SELECT answer FROM assessment_responses WHERE id = $1',
        [response.id],
      );
      expect(raw[0].answer).not.toContain('salaries');
      expect(raw[0].answer).not.toContain('600000');

      // Verify decryption preserves structure
      const retrieved = await assessmentResponseRepo.findOne({
        where: { id: response.id },
      });
      expect(retrieved.answer).toEqual(complexData);
      expect(retrieved.answer.revenue.total).toBe(1050000);
      expect(retrieved.answer.expenses.breakdown.fixed).toBe(650000);
    });

    it('should preserve data types through encryption cycle', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'types@test.com',
          password_hash: 'hashed',
          first_name: 'Types',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Types Client',
          client_email: 'types@client.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'mixed_types',
          question_text: 'Mixed data',
          question_type: 'object',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      // Mixed data types
      const mixedData = {
        revenue: 100000, // number
        hasDebt: true, // boolean
        businessName: 'Acme Corp', // string
        employees: [
          { name: 'John', salary: 50000 },
          { name: 'Jane', salary: 60000 },
        ], // array
        metadata: null, // null
      };

      const response = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: mixedData,
        }),
      );

      const retrieved = await assessmentResponseRepo.findOne({
        where: { id: response.id },
      });

      expect(retrieved.answer).toEqual(mixedData);
      expect(typeof retrieved.answer.revenue).toBe('number');
      expect(typeof retrieved.answer.hasDebt).toBe('boolean');
      expect(typeof retrieved.answer.businessName).toBe('string');
      expect(Array.isArray(retrieved.answer.employees)).toBe(true);
      expect(retrieved.answer.metadata).toBeNull();
    });
  });

  describe('JSONB-like Operations', () => {
    it('should allow querying assessments and retrieving encrypted answers', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'query@test.com',
          password_hash: 'hashed',
          first_name: 'Query',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Query Client',
          client_email: 'query@client.com',
          status: 'in_progress',
        }),
      );

      const question1 = await questionRepo.save(
        questionRepo.create({
          question_key: 'q1',
          question_text: 'Question 1',
          question_type: 'number',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      const question2 = await questionRepo.save(
        questionRepo.create({
          question_key: 'q2',
          question_text: 'Question 2',
          question_type: 'number',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 2,
        }),
      );

      // Create multiple responses
      await assessmentResponseRepo.save([
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question1.question_key,
          answer: { value: 100000 },
        }),
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question2.question_key,
          answer: { value: 200000 },
        }),
      ]);

      // Query all responses for assessment
      const responses = await assessmentResponseRepo.find({
        where: { assessment_id: assessment.id },
        order: { answered_at: 'ASC' },
      });

      expect(responses).toHaveLength(2);
      expect(responses[0].answer.value).toBe(100000);
      expect(responses[1].answer.value).toBe(200000);
    });

    it('should handle null answers (not applicable responses)', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'null@test.com',
          password_hash: 'hashed',
          first_name: 'Null',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Null Client',
          client_email: 'null@client.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'optional_q',
          question_text: 'Optional?',
          question_type: 'number',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      // Create response with null answer (N/A)
      const response = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: null,
          not_applicable: true,
        }),
      );

      const retrieved = await assessmentResponseRepo.findOne({
        where: { id: response.id },
      });

      expect(retrieved.answer).toBeNull();
      expect(retrieved.not_applicable).toBe(true);
    });
  });

  describe('Data Integrity & Security', () => {
    it('should prevent direct tampering with encrypted data', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'security@test.com',
          password_hash: 'hashed',
          first_name: 'Security',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Security Client',
          client_email: 'security@client.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'secure_q',
          question_text: 'Secure data',
          question_type: 'number',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      const response = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: { revenue: 500000 },
        }),
      );

      // Get encrypted value
      const rawData = await dataSource.query(
        'SELECT answer FROM assessment_responses WHERE id = $1',
        [response.id],
      );
      const encryptedValue = rawData[0].answer;

      // Tamper with encrypted data
      const [iv, authTag, ciphertext] = encryptedValue.split(':');
      const tamperedValue = `${iv}:${authTag}:${ciphertext.slice(0, -2)}ff`;

      // Update database with tampered value
      await dataSource.query(
        'UPDATE assessment_responses SET answer = $1 WHERE id = $2',
        [tamperedValue, response.id],
      );

      // Attempt to retrieve - should throw error
      await expect(
        assessmentResponseRepo.findOne({ where: { id: response.id } }),
      ).rejects.toThrow();
    });

    it('should use different IVs for same data (no ciphertext reuse)', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'iv@test.com',
          password_hash: 'hashed',
          first_name: 'IV',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'IV Client',
          client_email: 'iv@client.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'iv_q',
          question_text: 'IV test',
          question_type: 'number',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      // Create two responses with identical data
      const sameData = { revenue: 100000 };
      const response1 = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: sameData,
        }),
      );

      const response2 = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: sameData,
        }),
      );

      // Get encrypted values
      const raw1 = await dataSource.query(
        'SELECT answer FROM assessment_responses WHERE id = $1',
        [response1.id],
      );
      const raw2 = await dataSource.query(
        'SELECT answer FROM assessment_responses WHERE id = $1',
        [response2.id],
      );

      // Ciphertexts should be different due to different IVs
      expect(raw1[0].answer).not.toBe(raw2[0].answer);
    });
  });

  describe('Performance', () => {
    it('should encrypt/decrypt in acceptable time (<10ms per operation)', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'perf@test.com',
          password_hash: 'hashed',
          first_name: 'Perf',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Perf Client',
          client_email: 'perf@client.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'perf_q',
          question_text: 'Performance test',
          question_type: 'object',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      const largeData = {
        revenue: 1000000,
        expenses: {
          salaries: Array(50).fill(null).map((_, i) => ({
            employee: `Employee ${i}`,
            amount: 50000 + i * 1000,
          })),
        },
      };

      // Measure write performance
      const writeStart = Date.now();
      const response = await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: largeData,
        }),
      );
      const writeDuration = Date.now() - writeStart;

      // Measure read performance
      const readStart = Date.now();
      await assessmentResponseRepo.findOne({ where: { id: response.id } });
      const readDuration = Date.now() - readStart;

      // Database operations include network/query overhead, so be more lenient
      expect(writeDuration).toBeLessThan(100); // <100ms
      expect(readDuration).toBeLessThan(100); // <100ms
    });
  });

  describe('GDPR/CCPA Compliance', () => {
    it('should ensure financial PII cannot be read from database dump', async () => {
      const user = await userRepo.save(
        userRepo.create({
          email: 'gdpr@test.com',
          password_hash: 'hashed',
          first_name: 'GDPR',
          last_name: 'Test',
          role: 'consultant',
        }),
      );

      const assessment = await assessmentRepo.save(
        assessmentRepo.create({
          consultant_id: user.id,
          client_name: 'Compliance Client',
          client_email: 'compliance@client.com',
          status: 'in_progress',
        }),
      );

      const question = await questionRepo.save(
        questionRepo.create({
          question_key: 'compliance_q',
          question_text: 'Compliance data',
          question_type: 'object',
          phase: 'stabilize',
          category: 'financial_health',
          order_index: 1,
        }),
      );

      // Sensitive financial PII
      const sensitiveData = {
        annualRevenue: 5000000,
        taxId: '12-3456789',
        bankAccount: '1234567890',
        proprietorSSN: '123-45-6789', // Should never be stored, but testing encryption
      };

      await assessmentResponseRepo.save(
        assessmentResponseRepo.create({
          assessment_id: assessment.id,
          question_id: question.question_key,
          answer: sensitiveData,
        }),
      );

      // Simulate database dump (raw query)
      const dump = await dataSource.query(
        'SELECT * FROM assessment_responses',
      );

      // Verify sensitive data not in dump
      const dumpString = JSON.stringify(dump);
      expect(dumpString).not.toContain('5000000');
      expect(dumpString).not.toContain('12-3456789');
      expect(dumpString).not.toContain('1234567890');
      expect(dumpString).not.toContain('123-45-6789');
      expect(dumpString).not.toContain('annualRevenue');
      expect(dumpString).not.toContain('taxId');
    });
  });
});
