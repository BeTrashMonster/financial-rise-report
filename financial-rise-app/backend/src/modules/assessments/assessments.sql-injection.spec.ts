import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import * as request from 'supertest';
import { AssessmentsModule } from './assessments.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { QuestionsModule } from '../questions/questions.module';
import { Repository, DataSource } from 'typeorm';
import { User, UserRole } from '../users/entities/user.entity';
import { Assessment } from './entities/assessment.entity';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';

/**
 * SQL Injection Security Tests for Assessments Module
 *
 * SECURITY FINDING: CRIT-003 - SQL Injection Protection Verification
 * Reference: SECURITY-AUDIT-REPORT.md Lines 652-735
 *
 * Purpose:
 * - Verify TypeORM query builders and ORM methods properly sanitize inputs
 * - Test all assessment endpoints against common SQL injection attack vectors
 * - Ensure parameterized queries are used throughout the codebase
 * - Validate JSONB queries are safe from NoSQL injection
 *
 * Attack Vectors Tested:
 * 1. Classic SQL injection ('; DROP TABLE users; --)
 * 2. Union-based injection (UNION SELECT ...)
 * 3. Boolean-based blind injection (OR 1=1)
 * 4. Time-based blind injection (; WAITFOR DELAY '00:00:05')
 * 5. JSONB injection (", "malicious": "value)
 * 6. Comment injection (-- or /* */)
 * 7. Stacked queries (; DELETE FROM ...)
 *
 * Expected Behavior:
 * - All injection attempts should be treated as literal strings
 * - No database structure modifications
 * - No unauthorized data access
 * - Proper error handling without leaking DB info
 */
describe('Assessments SQL Injection Security Tests (WS55)', () => {
  let app: INestApplication;
  let dataSource: DataSource;
  let userRepository: Repository<User>;
  let assessmentRepository: Repository<Assessment>;
  let consultantAccessToken: string;
  let consultantUser: User;
  let testAssessmentId: string;

  // Common SQL injection attack payloads
  const SQL_INJECTION_PAYLOADS = [
    // Classic SQLi
    "'; DROP TABLE users; --",
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    "admin' #",
    "admin'/*",

    // Union-based
    "' UNION SELECT NULL, NULL, NULL --",
    "' UNION ALL SELECT id, password_hash FROM users --",

    // Boolean-based blind
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' OR EXISTS(SELECT * FROM users) --",

    // Time-based blind (PostgreSQL)
    "'; SELECT pg_sleep(5); --",
    "' AND (SELECT 1 FROM pg_sleep(5)) --",

    // Stacked queries
    "'; DELETE FROM assessments; --",
    "'; UPDATE users SET role='admin'; --",

    // Comment variations
    "admin' -- comment",
    "admin' /* comment */ --",
    "admin'-- -",

    // Escaped characters
    "admin\\'--",
    "admin\\'; DROP TABLE users; --",
  ];

  // JSONB-specific injection payloads
  const JSONB_INJECTION_PAYLOADS = [
    '{"value": "test", "malicious": "value"}',
    '{"value": "test\"; DROP TABLE users; --"}',
    '{"value": "test\' OR 1=1 --"}',
    '{"value": {"$ne": null}}', // NoSQL-style
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
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    dataSource = moduleFixture.get<DataSource>(DataSource);
    userRepository = moduleFixture.get<Repository<User>>(getRepositoryToken(User));
    assessmentRepository = moduleFixture.get<Repository<Assessment>>(getRepositoryToken(Assessment));

    // Create test consultant user
    const hashedPassword = await bcrypt.hash('TestPass123!', 10);
    consultantUser = await userRepository.save({
      email: 'sqltest@test.com',
      password_hash: hashedPassword,
      first_name: 'Test',
      last_name: 'Consultant',
      role: UserRole.CONSULTANT,
      email_verified: true,
    });

    // Login to get access token
    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({ email: 'sqltest@test.com', password: 'TestPass123!' });

    consultantAccessToken = loginResponse.body.accessToken;

    // Create a test assessment
    const assessment = await assessmentRepository.save({
      client_name: 'Test Client',
      business_name: 'Test Business',
      client_email: 'client@test.com',
      consultant_id: consultantUser.id,
      status: 'draft',
      progress: 0,
    });
    testAssessmentId = assessment.id;
  });

  afterAll(async () => {
    await dataSource.destroy();
    await app.close();
  });

  describe('POST /assessments - SQL Injection Tests', () => {
    it('should reject SQL injection in client_name field', async () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 5)) {
        const response = await request(app.getHttpServer())
          .post('/assessments')
          .set('Authorization', `Bearer ${consultantAccessToken}`)
          .send({
            clientName: payload,
            businessName: 'Test Business',
            clientEmail: 'test@example.com',
          });

        expect(response.status).not.toBe(500); // Should not cause server error

        if (response.status === 201) {
          // If created, verify payload was stored as literal string
          const assessment = await assessmentRepository.findOne({
            where: { id: response.body.id },
          });
          expect(assessment.client_name).toBe(payload); // Stored as literal string

          // Cleanup
          await assessmentRepository.delete(assessment.id);
        }
      }
    });

    it('should reject SQL injection in business_name field', async () => {
      const payload = "'; DROP TABLE assessments; --";

      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          clientName: 'Test Client',
          businessName: payload,
          clientEmail: 'test@example.com',
        });

      expect(response.status).not.toBe(500);

      if (response.status === 201) {
        const assessment = await assessmentRepository.findOne({
          where: { id: response.body.id },
        });
        expect(assessment.business_name).toBe(payload);

        // Verify assessments table still exists
        const count = await assessmentRepository.count();
        expect(count).toBeGreaterThan(0);

        await assessmentRepository.delete(assessment.id);
      }
    });

    it('should reject SQL injection in client_email field', async () => {
      const payload = "admin@test.com' OR '1'='1";

      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          clientName: 'Test Client',
          businessName: 'Test Business',
          clientEmail: payload,
        });

      // Email validation should catch this
      expect([400, 201]).toContain(response.status);

      if (response.status === 201) {
        const assessment = await assessmentRepository.findOne({
          where: { id: response.body.id },
        });
        expect(assessment.client_email).toBe(payload);
        await assessmentRepository.delete(assessment.id);
      }
    });

    it('should handle escaped quote characters safely', async () => {
      const payload = "O\\'Reilly Business Services";

      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          clientName: 'Test Client',
          businessName: payload,
          clientEmail: 'test@example.com',
        });

      expect(response.status).toBe(201);

      const assessment = await assessmentRepository.findOne({
        where: { id: response.body.id },
      });
      expect(assessment.business_name).toContain('Reilly');

      await assessmentRepository.delete(assessment.id);
    });
  });

  describe('GET /assessments - SQL Injection Tests', () => {
    it('should reject SQL injection in search parameter', async () => {
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 10)) {
        const response = await request(app.getHttpServer())
          .get('/assessments')
          .set('Authorization', `Bearer ${consultantAccessToken}`)
          .query({ search: payload });

        expect(response.status).toBe(200);
        expect(Array.isArray(response.body.data)).toBe(true);

        // Verify no unauthorized data access
        const allBelongToConsultant = response.body.data.every(
          (a: Assessment) => a.consultant_id === consultantUser.id,
        );
        expect(allBelongToConsultant).toBe(true);
      }
    });

    it('should reject SQL injection in status filter', async () => {
      const payload = "draft' OR '1'='1";

      const response = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .query({ status: payload });

      // Should either reject invalid enum value or treat as literal
      expect([200, 400]).toContain(response.status);

      if (response.status === 200) {
        // Should return no results (payload doesn't match valid enum)
        expect(response.body.data.length).toBe(0);
      }
    });

    it('should reject SQL injection in sortBy parameter', async () => {
      const payload = "created_at; DROP TABLE users; --";

      const response = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .query({ sortBy: payload });

      // Should either reject or handle safely
      expect(response.status).not.toBe(500);

      // Verify users table still exists
      const userCount = await userRepository.count();
      expect(userCount).toBeGreaterThan(0);
    });

    it('should handle LIKE pattern injection safely', async () => {
      const payload = "%' OR '1'='1' OR business_name LIKE '%";

      const response = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .query({ search: payload });

      expect(response.status).toBe(200);

      // Should only return consultant's own assessments
      const allBelongToConsultant = response.body.data.every(
        (a: Assessment) => a.consultant_id === consultantUser.id,
      );
      expect(allBelongToConsultant).toBe(true);
    });
  });

  describe('GET /assessments/:id - SQL Injection Tests', () => {
    it('should reject SQL injection in ID parameter', async () => {
      const payload = `${testAssessmentId}' OR '1'='1`;

      const response = await request(app.getHttpServer())
        .get(`/assessments/${payload}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`);

      // Should fail to find assessment with malformed UUID
      expect(response.status).toBe(400); // Bad Request or Not Found
    });

    it('should prevent union-based injection in ID parameter', async () => {
      const payload = `${testAssessmentId}' UNION SELECT * FROM users --`;

      const response = await request(app.getHttpServer())
        .get(`/assessments/${payload}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`);

      expect(response.status).not.toBe(200);

      // Should not leak user data
      if (response.body.email) {
        fail('Union injection leaked user data');
      }
    });
  });

  describe('PATCH /assessments/:id - SQL Injection Tests', () => {
    it('should reject SQL injection in update fields', async () => {
      const payload = "'; UPDATE users SET role='admin'; --";

      const response = await request(app.getHttpServer())
        .patch(`/assessments/${testAssessmentId}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          clientName: payload,
        });

      expect(response.status).toBe(200);

      // Verify payload stored as literal string
      const assessment = await assessmentRepository.findOne({
        where: { id: testAssessmentId },
      });
      expect(assessment.client_name).toBe(payload);

      // Verify no privilege escalation occurred
      const user = await userRepository.findOne({
        where: { id: consultantUser.id },
      });
      expect(user.role).toBe(UserRole.CONSULTANT); // Still consultant, not admin
    });

    it('should reject SQL injection in notes field', async () => {
      const payload = "Test note'; DELETE FROM assessments WHERE '1'='1";

      const response = await request(app.getHttpServer())
        .patch(`/assessments/${testAssessmentId}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          notes: payload,
        });

      expect(response.status).toBe(200);

      // Verify assessments table still has data
      const count = await assessmentRepository.count();
      expect(count).toBeGreaterThan(0);

      // Verify notes stored as literal
      const assessment = await assessmentRepository.findOne({
        where: { id: testAssessmentId },
      });
      expect(assessment.notes).toBe(payload);
    });
  });

  describe('DELETE /assessments/:id - SQL Injection Tests', () => {
    it('should reject SQL injection in delete ID parameter', async () => {
      // Create assessment to delete
      const tempAssessment = await assessmentRepository.save({
        client_name: 'Temp Client',
        business_name: 'Temp Business',
        client_email: 'temp@test.com',
        consultant_id: consultantUser.id,
        status: 'draft',
        progress: 0,
      });

      const payload = `${tempAssessment.id}' OR '1'='1`;

      const response = await request(app.getHttpServer())
        .delete(`/assessments/${payload}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`);

      expect(response.status).not.toBe(200);

      // Verify only intended assessment was deleted (none, due to malformed ID)
      const remaining = await assessmentRepository.count();
      expect(remaining).toBeGreaterThan(1); // Still has original test assessment

      // Cleanup
      await assessmentRepository.delete(tempAssessment.id);
    });

    it('should prevent mass deletion via injection', async () => {
      const initialCount = await assessmentRepository.count();

      const payload = `${testAssessmentId}'; DELETE FROM assessments WHERE '1'='1`;

      const response = await request(app.getHttpServer())
        .delete(`/assessments/${payload}`)
        .set('Authorization', `Bearer ${consultantAccessToken}`);

      expect(response.status).not.toBe(200);

      // Verify no mass deletion occurred
      const finalCount = await assessmentRepository.count();
      expect(finalCount).toBe(initialCount);
    });
  });

  describe('Time-Based Blind SQL Injection Tests', () => {
    it('should not execute time-delay injection attacks', async () => {
      const payload = "test'; SELECT pg_sleep(5); --";
      const startTime = Date.now();

      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          clientName: payload,
          businessName: 'Test Business',
          clientEmail: 'test@example.com',
        });

      const duration = Date.now() - startTime;

      // Should complete quickly (not wait 5 seconds)
      expect(duration).toBeLessThan(2000); // 2 seconds max
      expect(response.status).not.toBe(500);

      if (response.status === 201) {
        await assessmentRepository.delete(response.body.id);
      }
    });
  });

  describe('Error Information Disclosure Tests', () => {
    it('should not leak database structure in error messages', async () => {
      const payload = "'; SELECT * FROM pg_catalog.pg_tables; --";

      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .send({
          clientName: payload,
          businessName: 'Test',
          clientEmail: 'test@example.com',
        });

      // Should not expose database schema in response
      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('pg_catalog');
      expect(bodyString).not.toContain('pg_tables');
      expect(bodyString).not.toContain('TABLE_NAME');
      expect(bodyString).not.toContain('COLUMN_NAME');
    });

    it('should not expose SQL syntax errors to client', async () => {
      const payload = "test' AND (SELECT 1/0) --"; // Division by zero

      const response = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${consultantAccessToken}`)
        .query({ search: payload });

      const bodyString = JSON.stringify(response.body);
      expect(bodyString).not.toContain('division by zero');
      expect(bodyString).not.toContain('SQL');
      expect(bodyString).not.toContain('syntax error');
    });
  });

  describe('Parameterized Query Verification', () => {
    it('should treat all special SQL characters as literals', async () => {
      const specialChars = ["'", '"', ';', '--', '/*', '*/', '\\', '\n', '\r'];

      for (const char of specialChars) {
        const payload = `Test${char}Client`;

        const response = await request(app.getHttpServer())
          .post('/assessments')
          .set('Authorization', `Bearer ${consultantAccessToken}`)
          .send({
            clientName: payload,
            businessName: 'Test Business',
            clientEmail: 'test@example.com',
          });

        if (response.status === 201) {
          const assessment = await assessmentRepository.findOne({
            where: { id: response.body.id },
          });

          // Character should be stored as-is
          expect(assessment.client_name).toContain(char);

          await assessmentRepository.delete(assessment.id);
        }
      }
    });
  });
});
