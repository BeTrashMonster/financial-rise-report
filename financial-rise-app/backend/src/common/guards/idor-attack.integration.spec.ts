import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import * as request from 'supertest';
import { AppModule } from '../../app.module';
import { AssessmentsService } from '../../modules/assessments/assessments.service';
import { ReportGenerationService } from '../../reports/services/report-generation.service';
import { Assessment } from '../../modules/assessments/entities/assessment.entity';
import { Report } from '../../reports/entities/report.entity';
import { User, UserRole } from '../../modules/users/entities/user.entity';
import { JwtService } from '@nestjs/jwt';

/**
 * IDOR (Insecure Direct Object Reference) Attack Integration Tests
 *
 * These tests verify that the AssessmentOwnershipGuard and ReportOwnershipGuard
 * properly prevent unauthorized access to resources owned by other users.
 *
 * Security: OWASP A01:2021 - Broken Access Control
 * CVE: CWE-639 - Authorization Bypass Through User-Controlled Key
 *
 * Test scenarios:
 * 1. User A cannot access User B's assessments
 * 2. User A cannot modify User B's assessments
 * 3. User A cannot delete User B's assessments
 * 4. User A cannot access User B's reports
 * 5. Admin can access all resources (bypass ownership check)
 */
describe('IDOR Attack Prevention (Integration)', () => {
  let app: INestApplication;
  let jwtService: JwtService;
  let assessmentsService: AssessmentsService;
  let reportService: ReportGenerationService;

  // Test users
  let userA: User;
  let userB: User;
  let adminUser: User;
  let tokenA: string;
  let tokenB: string;
  let tokenAdmin: string;

  // Test data
  let assessmentA: Assessment;
  let assessmentB: Assessment;
  let reportA: Report;
  let reportB: Report;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    jwtService = moduleFixture.get<JwtService>(JwtService);
    assessmentsService = moduleFixture.get<AssessmentsService>(AssessmentsService);
    reportService = moduleFixture.get<ReportGenerationService>(ReportGenerationService);

    // Create test users
    userA = {
      id: 'user-a-id',
      email: 'usera@test.com',
      role: UserRole.CONSULTANT,
    } as User;

    userB = {
      id: 'user-b-id',
      email: 'userb@test.com',
      role: UserRole.CONSULTANT,
    } as User;

    adminUser = {
      id: 'admin-id',
      email: 'admin@test.com',
      role: UserRole.ADMIN,
    } as User;

    // Generate JWT tokens
    tokenA = jwtService.sign({ id: userA.id, email: userA.email, role: userA.role });
    tokenB = jwtService.sign({ id: userB.id, email: userB.email, role: userB.role });
    tokenAdmin = jwtService.sign({
      id: adminUser.id,
      email: adminUser.email,
      role: adminUser.role,
    });
  });

  beforeEach(async () => {
    // Create test assessments
    assessmentA = await assessmentsService.create(
      {
        clientName: 'Client A',
        businessName: 'Business A',
        clientEmail: 'clienta@test.com',
      },
      userA.id,
    );

    assessmentB = await assessmentsService.create(
      {
        clientName: 'Client B',
        businessName: 'Business B',
        clientEmail: 'clientb@test.com',
      },
      userB.id,
    );

    // Create test reports
    const mockDataA = {
      assessment: { id: assessmentA.id },
      client: { name: 'Client A', businessName: 'Business A', email: 'clienta@test.com' },
      discProfile: {
        primaryType: 'D' as const,
        scores: { D: 80, I: 60, S: 50, C: 40 },
        secondaryTraits: [],
        confidence: 'high',
      },
      phaseResults: {
        primaryPhase: 'organize' as any,
        scores: { stabilize: 70, organize: 80, build: 60, grow: 50, systemic: 55 } as any,
        secondaryPhases: [],
      },
      responses: [],
      consultantNotes: 'Test',
    };

    const mockDataB = {
      assessment: { id: assessmentB.id },
      client: { name: 'Client B', businessName: 'Business B', email: 'clientb@test.com' },
      discProfile: {
        primaryType: 'I' as const,
        scores: { D: 40, I: 90, S: 60, C: 30 },
        secondaryTraits: [],
        confidence: 'high',
      },
      phaseResults: {
        primaryPhase: 'build' as any,
        scores: { stabilize: 80, organize: 85, build: 75, grow: 60, systemic: 65 } as any,
        secondaryPhases: [],
      },
      responses: [],
      consultantNotes: 'Test',
    };

    reportA = await reportService.generateConsultantReport(mockDataA, userA.id);
    reportB = await reportService.generateConsultantReport(mockDataB, userB.id);
  });

  afterEach(async () => {
    // Cleanup
    if (assessmentA) await assessmentsService.remove(assessmentA.id, userA.id);
    if (assessmentB) await assessmentsService.remove(assessmentB.id, userB.id);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Assessment IDOR Attacks', () => {
    it('should prevent User A from accessing User B assessment (GET)', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404); // Returns 404 instead of 403 to prevent information disclosure

      // Should not reveal assessment exists
      expect(response.body.message).toContain('not found');
    });

    it('should prevent User A from updating User B assessment (PATCH)', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/api/v1/assessments/${assessmentB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .send({ notes: 'Malicious update attempt' })
        .expect(404);

      // Verify assessment was not modified
      const assessment = await assessmentsService.findOne(assessmentB.id, userB.id);
      expect(assessment.notes).not.toBe('Malicious update attempt');
    });

    it('should prevent User A from deleting User B assessment (DELETE)', async () => {
      const response = await request(app.getHttpServer())
        .delete(`/api/v1/assessments/${assessmentB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      // Verify assessment still exists
      const assessment = await assessmentsService.findOne(assessmentB.id, userB.id);
      expect(assessment).toBeDefined();
      expect(assessment.id).toBe(assessmentB.id);
    });

    it('should allow User A to access their own assessment', async () => {
      const response = await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentA.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(response.body.id).toBe(assessmentA.id);
      expect(response.body.consultant_id).toBe(userA.id);
    });

    it('should allow admin to access any assessment', async () => {
      // Admin can access User A's assessment
      const responseA = await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentA.id}`)
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .expect(200);
      expect(responseA.body.id).toBe(assessmentA.id);

      // Admin can access User B's assessment
      const responseB = await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentB.id}`)
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .expect(200);
      expect(responseB.body.id).toBe(assessmentB.id);
    });
  });

  describe('Report IDOR Attacks', () => {
    it('should prevent User A from accessing User B report status', async () => {
      const response = await request(app.getHttpServer())
        .get(`/reports/status/${reportB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(403);

      expect(response.body.message).toContain('permission');
    });

    it('should prevent User A from downloading User B report', async () => {
      const response = await request(app.getHttpServer())
        .get(`/reports/download/${reportB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(403);

      expect(response.body.message).toContain('permission');
    });

    it('should allow User A to access their own report', async () => {
      const response = await request(app.getHttpServer())
        .get(`/reports/status/${reportA.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(200);

      expect(response.body.reportId).toBe(reportA.id);
      expect(response.body.assessmentId).toBe(assessmentA.id);
    });

    it('should allow admin to access any report', async () => {
      // Admin can access User A's report
      const responseA = await request(app.getHttpServer())
        .get(`/reports/status/${reportA.id}`)
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .expect(200);
      expect(responseA.body.reportId).toBe(reportA.id);

      // Admin can access User B's report
      const responseB = await request(app.getHttpServer())
        .get(`/reports/status/${reportB.id}`)
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .expect(200);
      expect(responseB.body.reportId).toBe(reportB.id);
    });
  });

  describe('Attack Vector: ID Enumeration', () => {
    it('should not reveal assessment existence through error messages', async () => {
      const nonExistentId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

      const response = await request(app.getHttpServer())
        .get(`/api/v1/assessments/${nonExistentId}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      // Both cases should return same 404 error to prevent enumeration
      expect(response.body.message).toContain('not found');

      const responseOther = await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentB.id}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(404);

      expect(responseOther.body.message).toContain('not found');
    });

    it('should prevent sequential ID guessing attacks on assessments', async () => {
      // Attempt to access multiple IDs sequentially
      const attemptedIds = [assessmentB.id, 'random-uuid-1', 'random-uuid-2'];

      for (const id of attemptedIds) {
        await request(app.getHttpServer())
          .get(`/api/v1/assessments/${id}`)
          .set('Authorization', `Bearer ${tokenA}`)
          .expect(404);
      }

      // All should fail with same error - preventing enumeration
    });
  });

  describe('Attack Vector: Parameter Manipulation', () => {
    it('should reject malformed UUIDs gracefully', async () => {
      const malformedIds = ['123', 'not-a-uuid', '../../../etc/passwd', "'; DROP TABLE assessments;--"];

      for (const malformedId of malformedIds) {
        await request(app.getHttpServer())
          .get(`/api/v1/assessments/${malformedId}`)
          .set('Authorization', `Bearer ${tokenA}`)
          .expect(400); // ParseUUIDPipe should reject
      }
    });

    it('should prevent IDOR through SQL injection in ID parameter', async () => {
      const sqlInjection = "' OR '1'='1";

      await request(app.getHttpServer())
        .get(`/api/v1/assessments/${sqlInjection}`)
        .set('Authorization', `Bearer ${tokenA}`)
        .expect(400);
    });
  });

  describe('Attack Vector: Missing Authorization', () => {
    it('should reject requests without JWT token', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentA.id}`)
        .expect(401);
    });

    it('should reject requests with invalid JWT token', async () => {
      await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentA.id}`)
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);
    });

    it('should reject requests with expired JWT token', async () => {
      const expiredToken = jwtService.sign(
        { id: userA.id, email: userA.email, role: userA.role },
        { expiresIn: '-1h' },
      );

      await request(app.getHttpServer())
        .get(`/api/v1/assessments/${assessmentA.id}`)
        .set('Authorization', `Bearer ${expiredToken}`)
        .expect(401);
    });
  });

  describe('Defense in Depth Validation', () => {
    it('should have consistent ownership validation across all assessment endpoints', async () => {
      // Test all CRUD operations fail for User A accessing User B's assessment
      const endpoints = [
        { method: 'get', path: `/api/v1/assessments/${assessmentB.id}` },
        {
          method: 'patch',
          path: `/api/v1/assessments/${assessmentB.id}`,
          data: { notes: 'test' },
        },
        { method: 'delete', path: `/api/v1/assessments/${assessmentB.id}` },
      ];

      for (const endpoint of endpoints) {
        const req = request(app.getHttpServer())[endpoint.method](endpoint.path).set(
          'Authorization',
          `Bearer ${tokenA}`,
        );

        if (endpoint.data) {
          req.send(endpoint.data);
        }

        await req.expect((res) => {
          expect([403, 404]).toContain(res.status);
        });
      }
    });

    it('should have consistent ownership validation across all report endpoints', async () => {
      const endpoints = [
        { method: 'get', path: `/reports/status/${reportB.id}` },
        { method: 'get', path: `/reports/download/${reportB.id}` },
      ];

      for (const endpoint of endpoints) {
        await request(app.getHttpServer())
          [endpoint.method](endpoint.path)
          .set('Authorization', `Bearer ${tokenA}`)
          .expect(403);
      }
    });
  });
});
