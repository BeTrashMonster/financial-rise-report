import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AlgorithmsModule } from './algorithms.module';
import { AssessmentsModule } from '../assessments/assessments.module';
import { QuestionsModule } from '../questions/questions.module';
import { QuestionnaireModule } from '../questionnaire/questionnaire.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { Assessment } from '../assessments/entities/assessment.entity';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { Question, QuestionType } from '../questions/entities/question.entity';
import { User } from '../users/entities/user.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { DISCProfile } from './entities/disc-profile.entity';
import { PhaseResult } from './entities/phase-result.entity';
import { Repository } from 'typeorm';

describe('Algorithms E2E Tests', () => {
  let app: INestApplication;
  let authToken: string;
  let assessmentId: string;
  let questionRepo: Repository<Question>;
  const testEmail = `algorithms-${Date.now()}@example.com`;

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
            AssessmentResponse,
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
        QuestionnaireModule,
        AlgorithmsModule,
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    questionRepo = moduleFixture.get('QuestionRepository');

    // Seed DISC questions with scoring
    for (let i = 1; i <= 15; i++) {
      await questionRepo.save({
        question_key: `DISC-${i.toString().padStart(3, '0')}`,
        question_text: `DISC Question ${i}`,
        question_type: QuestionType.SINGLE_CHOICE,
        options: {
          options: [
            {
              value: 'option_d',
              text: 'D-oriented option',
              discScores: { D: 15, I: 0, S: 0, C: 5 },
              phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
            },
            {
              value: 'option_i',
              text: 'I-oriented option',
              discScores: { D: 0, I: 15, S: 5, C: 0 },
              phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
            },
            {
              value: 'option_s',
              text: 'S-oriented option',
              discScores: { D: 0, I: 5, S: 15, C: 0 },
              phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
            },
            {
              value: 'option_c',
              text: 'C-oriented option',
              discScores: { D: 5, I: 0, S: 0, C: 15 },
              phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
            },
          ],
        },
        required: true,
        display_order: i,
      });
    }

    // Seed Phase questions
    const phaseQuestions = [
      {
        key: 'PHASE-001',
        text: 'Do you have clean historical books?',
        scores: { stabilize: 20, organize: 5, build: 0, grow: 0, systemic: 0 },
      },
      {
        key: 'PHASE-002',
        text: 'Do you have a documented chart of accounts?',
        scores: { stabilize: 5, organize: 20, build: 5, grow: 0, systemic: 0 },
      },
      {
        key: 'PHASE-003',
        text: 'Do you have standardized financial workflows?',
        scores: { stabilize: 0, organize: 5, build: 20, grow: 5, systemic: 0 },
      },
      {
        key: 'PHASE-004',
        text: 'Do you have 12-month cash flow projections?',
        scores: { stabilize: 0, organize: 0, build: 5, grow: 20, systemic: 5 },
      },
      {
        key: 'PHASE-005',
        text: 'Can you interpret financial statements confidently?',
        scores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 20 },
      },
    ];

    for (const pq of phaseQuestions) {
      await questionRepo.save({
        question_key: pq.key,
        question_text: pq.text,
        question_type: QuestionType.SINGLE_CHOICE,
        options: {
          options: [
            {
              value: 'yes',
              text: 'Yes',
              discScores: { D: 0, I: 0, S: 0, C: 0 },
              phaseScores: pq.scores,
            },
            {
              value: 'no',
              text: 'No',
              discScores: { D: 0, I: 0, S: 0, C: 0 },
              phaseScores: { stabilize: 0, organize: 0, build: 0, grow: 0, systemic: 0 },
            },
          ],
        },
        required: true,
        display_order: 100 + phaseQuestions.indexOf(pq),
      });
    }

    // Register and login
    const registerResponse = await request(app.getHttpServer())
      .post('/auth/register')
      .send({
        email: testEmail,
        password: 'TestPass123!',
        first_name: 'Test',
        last_name: 'User',
      });

    authToken = registerResponse.body.tokens.accessToken;

    // Create assessment and answer questions
    const assessmentResponse = await request(app.getHttpServer())
      .post('/assessments')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        client_name: 'Algorithm Test',
        business_name: 'Algorithm Corp',
        client_email: 'algorithm@test.com',
      });

    assessmentId = assessmentResponse.body.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('POST /algorithms/disc-profile', () => {
    beforeAll(async () => {
      // Answer 15 DISC questions with high D scores
      for (let i = 1; i <= 15; i++) {
        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: assessmentId,
            questionId: `DISC-${i.toString().padStart(3, '0')}`,
            answer: { value: 'option_d' },
          });
      }
    });

    it('should calculate DISC profile successfully', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('assessmentId');
      expect(response.body.assessmentId).toBe(assessmentId);
      expect(response.body).toHaveProperty('d_score');
      expect(response.body).toHaveProperty('i_score');
      expect(response.body).toHaveProperty('s_score');
      expect(response.body).toHaveProperty('c_score');
      expect(response.body).toHaveProperty('primary_type');
      expect(response.body).toHaveProperty('confidence_level');
      expect(response.body).toHaveProperty('calculated_at');
    });

    it('should have high D score based on responses', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body.primary_type).toBe('D');
      expect(response.body.d_score).toBeGreaterThan(response.body.i_score);
      expect(response.body.d_score).toBeGreaterThan(response.body.s_score);
      expect(response.body.d_score).toBeGreaterThan(response.body.c_score);
    });

    it('should have scores between 0-100', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body.d_score).toBeGreaterThanOrEqual(0);
      expect(response.body.d_score).toBeLessThanOrEqual(100);
      expect(response.body.i_score).toBeGreaterThanOrEqual(0);
      expect(response.body.i_score).toBeLessThanOrEqual(100);
      expect(response.body.s_score).toBeGreaterThanOrEqual(0);
      expect(response.body.s_score).toBeLessThanOrEqual(100);
      expect(response.body.c_score).toBeGreaterThanOrEqual(0);
      expect(response.body.c_score).toBeLessThanOrEqual(100);
    });

    it('should have valid primary type', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(['D', 'I', 'S', 'C']).toContain(response.body.primary_type);
    });

    it('should have valid confidence level', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(['high', 'moderate', 'low']).toContain(response.body.confidence_level);
    });

    it('should reject calculation for non-existent assessment', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: fakeId,
        })
        .expect(404);
    });

    it('should handle insufficient data gracefully', async () => {
      // Create assessment with < 12 responses
      const newAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Insufficient Data',
          business_name: 'Test',
          client_email: 'insufficient@test.com',
        });

      // Answer only 8 questions
      for (let i = 1; i <= 8; i++) {
        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: newAssessment.body.id,
            questionId: `DISC-${i.toString().padStart(3, '0')}`,
            answer: { value: 'option_c' },
          });
      }

      const response = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: newAssessment.body.id,
        });

      // May return 400 or 200 with low confidence
      if (response.status === 200) {
        expect(response.body.confidence_level).toBe('low');
      }
    });
  });

  describe('POST /algorithms/phase-result', () => {
    beforeAll(async () => {
      // Answer phase questions indicating Stabilize phase
      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'PHASE-001',
          answer: { value: 'yes' },
        });

      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'PHASE-002',
          answer: { value: 'no' },
        });

      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'PHASE-003',
          answer: { value: 'no' },
        });

      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'PHASE-004',
          answer: { value: 'no' },
        });

      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'PHASE-005',
          answer: { value: 'no' },
        });
    });

    it('should calculate phase result successfully', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body).toHaveProperty('assessmentId');
      expect(response.body).toHaveProperty('stabilize_score');
      expect(response.body).toHaveProperty('organize_score');
      expect(response.body).toHaveProperty('build_score');
      expect(response.body).toHaveProperty('grow_score');
      expect(response.body).toHaveProperty('systemic_score');
      expect(response.body).toHaveProperty('primary_phase');
      expect(response.body).toHaveProperty('secondary_phases');
      expect(response.body).toHaveProperty('transition_state');
      expect(response.body).toHaveProperty('calculated_at');
    });

    it('should have valid primary phase', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(['stabilize', 'organize', 'build', 'grow', 'systemic']).toContain(
        response.body.primary_phase
      );
    });

    it('should have scores between 0-100', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(response.body.stabilize_score).toBeGreaterThanOrEqual(0);
      expect(response.body.stabilize_score).toBeLessThanOrEqual(100);
      expect(response.body.organize_score).toBeGreaterThanOrEqual(0);
      expect(response.body.organize_score).toBeLessThanOrEqual(100);
      expect(response.body.build_score).toBeGreaterThanOrEqual(0);
      expect(response.body.build_score).toBeLessThanOrEqual(100);
      expect(response.body.grow_score).toBeGreaterThanOrEqual(0);
      expect(response.body.grow_score).toBeLessThanOrEqual(100);
      expect(response.body.systemic_score).toBeGreaterThanOrEqual(0);
      expect(response.body.systemic_score).toBeLessThanOrEqual(100);
    });

    it('should have secondary_phases as array', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(Array.isArray(response.body.secondary_phases)).toBe(true);
    });

    it('should have transition_state as boolean', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      expect(typeof response.body.transition_state).toBe('boolean');
    });

    it('should detect critical stabilization needs', async () => {
      const response = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
        })
        .expect(200);

      // Based on our responses, should identify need for stabilization or organization
      expect(['stabilize', 'organize']).toContain(response.body.primary_phase);
    });
  });

  describe('GET /algorithms/disc-profile/:assessmentId', () => {
    it('should retrieve existing DISC profile', async () => {
      const response = await request(app.getHttpServer())
        .get(`/algorithms/disc-profile/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body.assessmentId).toBe(assessmentId);
    });

    it('should return 404 for non-existent profile', async () => {
      // Create assessment without calculating profile
      const newAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'No Profile',
          business_name: 'Test',
          client_email: 'noprofile@test.com',
        });

      await request(app.getHttpServer())
        .get(`/algorithms/disc-profile/${newAssessment.body.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('GET /algorithms/phase-result/:assessmentId', () => {
    it('should retrieve existing phase result', async () => {
      const response = await request(app.getHttpServer())
        .get(`/algorithms/phase-result/${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('id');
      expect(response.body.assessmentId).toBe(assessmentId);
    });

    it('should return 404 for non-existent result', async () => {
      const newAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'No Result',
          business_name: 'Test',
          client_email: 'noresult@test.com',
        });

      await request(app.getHttpServer())
        .get(`/algorithms/phase-result/${newAssessment.body.id}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(404);
    });
  });

  describe('Complete Algorithm Flow', () => {
    it('should calculate both DISC and Phase for completed assessment', async () => {
      // Create new assessment
      const newAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Complete Algorithm',
          business_name: 'Complete Corp',
          client_email: 'complete@algorithm.com',
        });

      const completeAssessmentId = newAssessment.body.id;

      // Answer all 20 questions (15 DISC + 5 Phase)
      for (let i = 1; i <= 15; i++) {
        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: completeAssessmentId,
            questionId: `DISC-${i.toString().padStart(3, '0')}`,
            answer: { value: 'option_c' },
          });
      }

      for (let i = 1; i <= 5; i++) {
        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: completeAssessmentId,
            questionId: `PHASE-00${i}`,
            answer: { value: 'yes' },
          });
      }

      // Calculate DISC
      const discResponse = await request(app.getHttpServer())
        .post('/algorithms/disc-profile')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: completeAssessmentId,
        })
        .expect(200);

      expect(discResponse.body.primary_type).toBe('C');

      // Calculate Phase
      const phaseResponse = await request(app.getHttpServer())
        .post('/algorithms/phase-result')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: completeAssessmentId,
        })
        .expect(200);

      expect(phaseResponse.body).toHaveProperty('primary_phase');

      // Verify both are retrievable
      await request(app.getHttpServer())
        .get(`/algorithms/disc-profile/${completeAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      await request(app.getHttpServer())
        .get(`/algorithms/phase-result/${completeAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);
    });
  });
});
