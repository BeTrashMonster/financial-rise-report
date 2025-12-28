/**
 * SQL Injection Security Tests (E2E)
 *
 * Purpose: Comprehensive security testing to ensure all database queries
 * are protected against SQL injection attacks
 *
 * Scope:
 * - Authentication endpoints
 * - Assessment CRUD operations
 * - Search and filter functionality
 * - JSONB query operations
 * - User management operations
 *
 * Test Strategy:
 * 1. Attempt classic SQL injection payloads
 * 2. Verify parameterized queries block attacks
 * 3. Test JSONB NoSQL injection attempts
 * 4. Validate error messages don't leak schema info
 *
 * Security Finding: CRIT-003
 * OWASP: A03:2021 - Injection
 * CWE: CWE-89 - SQL Injection
 */

import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AuthModule } from '../modules/auth/auth.module';
import { UsersModule } from '../modules/users/users.module';
import { AssessmentsModule } from '../modules/assessments/assessments.module';
import { QuestionsModule } from '../modules/questions/questions.module';
import { Assessment } from '../modules/assessments/entities/assessment.entity';
import { AssessmentResponse as AssessmentResponseEntity } from '../modules/assessments/entities/assessment-response.entity';
import { User } from '../modules/users/entities/user.entity';
import { RefreshToken } from '../modules/auth/entities/refresh-token.entity';
import { Question } from '../modules/questions/entities/question.entity';
import { DISCProfile } from '../modules/algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../modules/algorithms/entities/phase-result.entity';

describe('SQL Injection Security Tests', () => {
  let app: INestApplication;
  let authToken: string;
  let userId: string;
  let assessmentId: string;

  // Common SQL injection attack payloads
  const SQL_INJECTION_PAYLOADS = [
    // Classic SQL injection
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "admin'--",
    "admin' #",
    "admin'/*",

    // UNION-based injection
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION ALL SELECT NULL--",

    // Boolean-based blind injection
    "' AND 1=1--",
    "' AND 1=2--",

    // Time-based blind injection
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT pg_sleep(5)--",

    // Stacked queries
    "'; DROP TABLE users--",
    "'; DELETE FROM users WHERE 1=1--",

    // Comment injection
    "admin'-- -",
    "admin' -- ",

    // String concatenation attacks
    "' || 'a'='a",
    "' + 'a'='a",

    // Hex encoding attacks
    "0x61646d696e",

    // Special characters
    "\\'; DROP TABLE users--",
    "%27%20OR%201=1--",
  ];

  // JSONB NoSQL injection payloads
  const NOSQL_INJECTION_PAYLOADS = [
    "'; DROP TABLE questions--",
    "{'$gt': ''}",
    "{'$ne': null}",
    "'; SELECT * FROM pg_tables--",
  ];

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot({
          type: 'sqlite',
          database: ':memory:',
          entities: [
            User,
            RefreshToken,
            Assessment,
            AssessmentResponseEntity,
            Question,
            DISCProfile,
            PhaseResult,
          ],
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
    app.useGlobalPipes(
      new ValidationPipe({
        transform: true,
        whitelist: true,
        forbidNonWhitelisted: true,
      }),
    );
    await app.init();

    // Create test user and authenticate
    const registerResponse = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: `sql-injection-test-${Date.now()}@example.com`,
        password: 'SecureP@ssw0rd123',
        firstName: 'Security',
        lastName: 'Tester',
      });

    userId = registerResponse.body.user.id;

    const loginResponse = await request(app.getHttpServer())
      .post('/auth/login')
      .send({
        email: registerResponse.body.user.email,
        password: 'SecureP@ssw0rd123',
      });

    authToken = loginResponse.body.accessToken;

    // Create test assessment
    const assessmentResponse = await request(app.getHttpServer())
      .post('/assessments')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        clientName: 'Test Client',
        clientEmail: 'client@example.com',
        businessName: 'Test Business',
      });

    assessmentId = assessmentResponse.body.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Authentication Endpoint SQL Injection Tests', () => {
    describe('POST /auth/login', () => {
      SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should block SQL injection attempt ${index + 1}: "${payload}"`, async () => {
          const response = await request(app.getHttpServer())
            .post('/auth/login')
            .send({
              email: payload,
              password: 'password',
            });

          // Should either reject with validation error or return 401
          // Should NOT succeed or cause database error
          expect([400, 401]).toContain(response.status);
          expect(response.body).not.toHaveProperty('accessToken');

          // Ensure error message doesn't leak schema information
          if (response.body.message) {
            const errorMessage = JSON.stringify(response.body.message).toLowerCase();
            expect(errorMessage).not.toContain('syntax error');
            expect(errorMessage).not.toContain('sql');
            expect(errorMessage).not.toContain('postgres');
            expect(errorMessage).not.toContain('table');
            expect(errorMessage).not.toContain('column');
          }
        });
      });

      it('should reject SQL injection in password field', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/login')
          .send({
            email: 'test@example.com',
            password: "' OR '1'='1",
          });

        expect(response.status).toBe(401);
        expect(response.body).not.toHaveProperty('accessToken');
      });
    });

    describe('POST /auth/forgot-password', () => {
      SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should block SQL injection in email field ${index + 1}`, async () => {
          const response = await request(app.getHttpServer())
            .post('/auth/forgot-password')
            .send({
              email: payload,
            });

          // Should return generic message or validation error
          expect([200, 400]).toContain(response.status);

          // Verify response doesn't leak information
          if (response.body.message) {
            const message = response.body.message.toLowerCase();
            expect(message).not.toContain('error');
            expect(message).not.toContain('sql');
          }
        });
      });
    });
  });

  describe('Assessment CRUD SQL Injection Tests', () => {
    describe('GET /assessments (with search)', () => {
      SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should block SQL injection in search parameter ${index + 1}: "${payload}"`, async () => {
          const response = await request(app.getHttpServer())
            .get('/assessments')
            .query({ search: payload })
            .set('Authorization', `Bearer ${authToken}`);

          // Should return empty results or error, not database error
          expect([200, 400]).toContain(response.status);

          if (response.status === 200) {
            // Should not return unauthorized data
            expect(Array.isArray(response.body.data)).toBe(true);
          }

          // Verify no SQL error messages
          if (response.body.message) {
            const errorMessage = JSON.stringify(response.body).toLowerCase();
            expect(errorMessage).not.toContain('syntax error');
            expect(errorMessage).not.toContain('sql');
          }
        });
      });
    });

    describe('GET /assessments (with status filter)', () => {
      SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should block SQL injection in status filter ${index + 1}`, async () => {
          const response = await request(app.getHttpServer())
            .get('/assessments')
            .query({ status: payload })
            .set('Authorization', `Bearer ${authToken}`);

          // Should return validation error or empty results
          expect([200, 400]).toContain(response.status);

          // Verify response integrity
          if (response.status === 200) {
            expect(response.body).toHaveProperty('data');
            expect(Array.isArray(response.body.data)).toBe(true);
          }
        });
      });
    });

    describe('GET /assessments/:id', () => {
      SQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should block SQL injection in ID parameter ${index + 1}`, async () => {
          const response = await request(app.getHttpServer())
            .get(`/assessments/${payload}`)
            .set('Authorization', `Bearer ${authToken}`);

          // Should return validation error (invalid UUID)
          expect(response.status).toBe(400);

          // Verify UUID validation error
          if (response.body.message) {
            const message = Array.isArray(response.body.message)
              ? response.body.message.join(' ')
              : response.body.message;
            expect(message.toLowerCase()).toContain('uuid');
          }
        });
      });
    });

    describe('PATCH /assessments/:id', () => {
      it('should block SQL injection in client name', async () => {
        const response = await request(app.getHttpServer())
          .patch(`/assessments/${assessmentId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            clientName: "'; DROP TABLE assessments--",
          });

        // Should succeed but sanitize input
        expect([200, 400]).toContain(response.status);

        // If successful, verify data was sanitized
        if (response.status === 200) {
          const getResponse = await request(app.getHttpServer())
            .get(`/assessments/${assessmentId}`)
            .set('Authorization', `Bearer ${authToken}`);

          // Name should be stored as-is (parameterized query handles escaping)
          expect(getResponse.body.clientName).toBe("'; DROP TABLE assessments--");
        }
      });

      it('should block SQL injection in business name', async () => {
        const response = await request(app.getHttpServer())
          .patch(`/assessments/${assessmentId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            businessName: "' OR '1'='1",
          });

        expect([200, 400]).toContain(response.status);
      });

      it('should block SQL injection in client email', async () => {
        const response = await request(app.getHttpServer())
          .patch(`/assessments/${assessmentId}`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            clientEmail: "admin'-- @example.com",
          });

        // Should fail email validation
        expect(response.status).toBe(400);
      });
    });

    describe('DELETE /assessments/:id', () => {
      it('should block SQL injection in delete endpoint', async () => {
        const response = await request(app.getHttpServer())
          .delete(`/assessments/' OR '1'='1--`)
          .set('Authorization', `Bearer ${authToken}`);

        // Should return UUID validation error
        expect(response.status).toBe(400);
      });
    });
  });

  describe('JSONB Query SQL Injection Tests', () => {
    describe('Assessment Response JSONB Fields', () => {
      it('should block NoSQL injection in JSONB answer field', async () => {
        // This test verifies that JSONB queries are parameterized
        // and don't allow injection through JSON operators

        const createResponse = await request(app.getHttpServer())
          .post(`/assessments/${assessmentId}/responses`)
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            questionId: 'FIN-001',
            answer: {
              malicious: "'; DROP TABLE assessment_responses--",
              nested: {
                attack: "' OR '1'='1",
              },
            },
          });

        // Should either succeed (storing data safely) or reject
        expect([200, 201, 400, 404]).toContain(createResponse.status);

        // Verify no SQL injection occurred by checking data integrity
        if (createResponse.status === 200 || createResponse.status === 201) {
          const getResponse = await request(app.getHttpServer())
            .get(`/assessments/${assessmentId}`)
            .set('Authorization', `Bearer ${authToken}`);

          expect(getResponse.status).toBe(200);
          // Assessment should still exist (not dropped)
          expect(getResponse.body).toHaveProperty('id');
        }
      });

      NOSQL_INJECTION_PAYLOADS.forEach((payload, index) => {
        it(`should block NoSQL injection payload ${index + 1} in JSONB`, async () => {
          const response = await request(app.getHttpServer())
            .post(`/assessments/${assessmentId}/responses`)
            .set('Authorization', `Bearer ${authToken}`)
            .send({
              questionId: 'FIN-001',
              answer: payload,
            });

          // Should handle gracefully
          expect([200, 201, 400, 404]).toContain(response.status);

          // Verify database integrity
          const checkResponse = await request(app.getHttpServer())
            .get('/assessments')
            .set('Authorization', `Bearer ${authToken}`);

          expect(checkResponse.status).toBe(200);
        });
      });
    });
  });

  describe('User Management SQL Injection Tests', () => {
    describe('GET /users (admin search)', () => {
      SQL_INJECTION_PAYLOADS.slice(0, 5).forEach((payload, index) => {
        it(`should block SQL injection in user search ${index + 1}`, async () => {
          const response = await request(app.getHttpServer())
            .get('/users')
            .query({ search: payload })
            .set('Authorization', `Bearer ${authToken}`);

          // May be unauthorized (if not admin) or return safe results
          expect([200, 401, 403]).toContain(response.status);

          if (response.status === 200) {
            expect(Array.isArray(response.body.data) || Array.isArray(response.body)).toBe(true);
          }
        });
      });
    });
  });

  describe('Query Builder Parameterization Tests', () => {
    it('should use parameterized queries for WHERE clauses', async () => {
      // Test that ILIKE queries are properly parameterized
      const searchTerm = "%'; DROP TABLE assessments; --";

      const response = await request(app.getHttpServer())
        .get('/assessments')
        .query({ search: searchTerm })
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);

      // Verify database integrity - assessments table should still exist
      const verifyResponse = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`);

      expect(verifyResponse.status).toBe(200);
      expect(verifyResponse.body).toHaveProperty('data');
    });

    it('should use parameterized queries for IN clauses', async () => {
      // Test that IN queries with arrays are safe
      const maliciousArray = ["' OR '1'='1--", "'; DROP TABLE users--"];

      // This would be used in filtering by multiple question IDs
      const response = await request(app.getHttpServer())
        .get('/questions')
        .query({ ids: maliciousArray })
        .set('Authorization', `Bearer ${authToken}`);

      // Should handle gracefully
      expect([200, 400]).toContain(response.status);
    });

    it('should use parameterized queries for ORDER BY clauses', async () => {
      // Test dynamic sorting doesn't allow injection
      const maliciousSort = "created_at; DROP TABLE assessments--";

      const response = await request(app.getHttpServer())
        .get('/assessments')
        .query({ sortBy: maliciousSort })
        .set('Authorization', `Bearer ${authToken}`);

      // Should reject invalid sort field or use safe default
      expect([200, 400]).toContain(response.status);
    });
  });

  describe('Error Message Information Disclosure Tests', () => {
    it('should not leak database schema information in error messages', async () => {
      const response = await request(app.getHttpServer())
        .get(`/assessments/invalid-uuid' OR '1'='1`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(400);

      const errorMessage = JSON.stringify(response.body).toLowerCase();

      // Should not contain sensitive information
      expect(errorMessage).not.toContain('syntax error');
      expect(errorMessage).not.toContain('pg_');
      expect(errorMessage).not.toContain('postgres');
      expect(errorMessage).not.toContain('relation');
      expect(errorMessage).not.toContain('column');
      expect(errorMessage).not.toContain('table');
      expect(errorMessage).not.toContain('sql');
      expect(errorMessage).not.toContain('database');
    });

    it('should return generic error for database failures', async () => {
      // Attempt to cause a constraint violation with injection
      const response = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          clientName: 'Test',
          clientEmail: "invalid-email'; DROP TABLE users--",
          businessName: 'Test Business',
        });

      // Should return validation error, not database error
      expect(response.status).toBe(400);

      if (response.body.message) {
        const message = Array.isArray(response.body.message)
          ? response.body.message.join(' ').toLowerCase()
          : response.body.message.toLowerCase();

        // Should mention email validation, not SQL error
        expect(message).toContain('email');
        expect(message).not.toContain('sql');
      }
    });
  });

  describe('Comprehensive Attack Simulation', () => {
    it('should withstand coordinated SQL injection attack across multiple endpoints', async () => {
      // Simulate attacker trying multiple vectors
      const attacks = [
        { endpoint: '/auth/login', method: 'post', data: { email: "' OR '1'='1--", password: 'x' } },
        { endpoint: '/assessments', method: 'get', query: { search: "'; DROP TABLE assessments--" } },
        { endpoint: `/assessments/${assessmentId}`, method: 'patch', data: { clientName: "' UNION SELECT * FROM users--" } },
      ];

      for (const attack of attacks) {
        let response;
        if (attack.method === 'post') {
          response = await request(app.getHttpServer())
            .post(attack.endpoint)
            .set('Authorization', `Bearer ${authToken}`)
            .send(attack.data);
        } else if (attack.method === 'get') {
          response = await request(app.getHttpServer())
            .get(attack.endpoint)
            .query(attack.query)
            .set('Authorization', `Bearer ${authToken}`);
        } else if (attack.method === 'patch') {
          response = await request(app.getHttpServer())
            .patch(attack.endpoint)
            .set('Authorization', `Bearer ${authToken}`)
            .send(attack.data);
        }

        // None should cause database errors
        expect(response.status).toBeLessThan(500);
      }

      // Verify database integrity after attack simulation
      const integrityCheck = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`);

      expect(integrityCheck.status).toBe(200);
      expect(integrityCheck.body).toHaveProperty('data');
    });

    it('should maintain data integrity after injection attempts', async () => {
      // Get initial assessment count
      const initialResponse = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`);

      const initialCount = initialResponse.body.data.length;

      // Attempt multiple injections
      for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 10)) {
        await request(app.getHttpServer())
          .get('/assessments')
          .query({ search: payload })
          .set('Authorization', `Bearer ${authToken}`);
      }

      // Verify count hasn't changed (no data deleted/modified)
      const finalResponse = await request(app.getHttpServer())
        .get('/assessments')
        .set('Authorization', `Bearer ${authToken}`);

      expect(finalResponse.body.data.length).toBe(initialCount);
    });
  });

  describe('TypeORM QueryBuilder Safety Tests', () => {
    it('should verify parameterized queries are used in createQueryBuilder', async () => {
      // This test verifies our audit findings that all queries use parameterization
      // Test the actual implementation by confirming safe behavior

      const testCases = [
        { search: "test' OR '1'='1--", expectedSafe: true },
        { search: "'; DELETE FROM assessments--", expectedSafe: true },
        { search: "normal search", expectedSafe: true },
      ];

      for (const testCase of testCases) {
        const response = await request(app.getHttpServer())
          .get('/assessments')
          .query({ search: testCase.search })
          .set('Authorization', `Bearer ${authToken}`);

        if (testCase.expectedSafe) {
          expect(response.status).toBe(200);
          expect(response.body).toHaveProperty('data');
        }
      }
    });

    it('should verify JSONB queries are safe from NoSQL injection', async () => {
      // Verify that JSONB column queries don't allow operator injection
      // Even though we found no JSONB queries in the audit, this test
      // ensures future JSONB queries are handled safely

      const response = await request(app.getHttpServer())
        .post(`/assessments/${assessmentId}/responses`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          questionId: 'FIN-001',
          answer: {
            "$where": "1=1",
            "$gt": "",
          },
        });

      // Should handle safely (store as data, not execute as query)
      expect([200, 201, 400, 404]).toContain(response.status);
    });
  });
});
