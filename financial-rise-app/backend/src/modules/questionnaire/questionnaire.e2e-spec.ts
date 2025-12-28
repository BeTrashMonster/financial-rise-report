import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import * as request from 'supertest';
import { TypeOrmModule } from '@nestjs/typeorm';
import { QuestionnaireModule } from './questionnaire.module';
import { QuestionsModule } from '../questions/questions.module';
import { AssessmentsModule } from '../assessments/assessments.module';
import { AuthModule } from '../auth/auth.module';
import { UsersModule } from '../users/users.module';
import { Assessment } from '../assessments/entities/assessment.entity';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { Question, QuestionType } from '../questions/entities/question.entity';
import { User } from '../users/entities/user.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { DISCProfile } from '../algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../algorithms/entities/phase-result.entity';
import { getRepository, Repository } from 'typeorm';

describe('Questionnaire E2E Tests', () => {
  let app: INestApplication;
  let authToken: string;
  let assessmentId: string;
  let questionRepo: Repository<Question>;
  let testQuestionId: string;
  const testEmail = `questionnaire-${Date.now()}@example.com`;

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
      ],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(new ValidationPipe({ transform: true, whitelist: true }));
    await app.init();

    // Get question repository to seed test data
    questionRepo = moduleFixture.get('QuestionRepository');

    // Seed test questions
    const question1 = questionRepo.create({
      question_key: 'FIN-001',
      question_text: 'How frequently do you review your financial statements?',
      question_type: QuestionType.SINGLE_CHOICE,
      options: {
        options: [
          { value: 'weekly', text: 'Weekly' },
          { value: 'monthly', text: 'Monthly' },
          { value: 'quarterly', text: 'Quarterly' },
          { value: 'annually', text: 'Annually or less' },
        ],
      },
      required: true,
      display_order: 1,
    });

    const question2 = questionRepo.create({
      question_key: 'FIN-002',
      question_text: 'Rate your financial system satisfaction (1-5)',
      question_type: QuestionType.RATING,
      options: {
        min: 1,
        max: 5,
        step: 1,
      },
      required: true,
      display_order: 2,
    });

    const question3 = questionRepo.create({
      question_key: 'FIN-003',
      question_text: 'Which accounting tools do you use?',
      question_type: QuestionType.MULTIPLE_CHOICE,
      options: {
        options: [
          { value: 'quickbooks', text: 'QuickBooks' },
          { value: 'xero', text: 'Xero' },
          { value: 'excel', text: 'Excel' },
          { value: 'other', text: 'Other' },
        ],
      },
      required: false,
      display_order: 3,
    });

    const question4 = questionRepo.create({
      question_key: 'FIN-004',
      question_text: 'Describe your current financial challenges',
      question_type: QuestionType.TEXT,
      options: null,
      required: false,
      display_order: 4,
    });

    await questionRepo.save([question1, question2, question3, question4]);
    testQuestionId = question1.question_key;

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

    // Create an assessment
    const assessmentResponse = await request(app.getHttpServer())
      .post('/assessments')
      .set('Authorization', `Bearer ${authToken}`)
      .send({
        client_name: 'Test Client',
        business_name: 'Test Business',
        client_email: 'client@test.com',
      });

    assessmentId = assessmentResponse.body.id;
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /questionnaire/questions', () => {
    it('should get all questions', async () => {
      const response = await request(app.getHttpServer())
        .get('/questionnaire/questions')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body).toHaveProperty('questions');
      expect(response.body).toHaveProperty('meta');
      expect(Array.isArray(response.body.questions)).toBe(true);
      expect(response.body.questions.length).toBe(4);
      expect(response.body.meta.totalQuestions).toBe(4);
      expect(response.body.meta.requiredQuestions).toBe(2);
      expect(response.body.meta.optionalQuestions).toBe(2);
    });

    it('should return questions in display order', async () => {
      const response = await request(app.getHttpServer())
        .get('/questionnaire/questions')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const orders = response.body.questions.map((q: any) => q.display_order);
      const sortedOrders = [...orders].sort((a, b) => a - b);
      expect(orders).toEqual(sortedOrders);
    });

    it('should include user responses when assessmentId provided', async () => {
      const response = await request(app.getHttpServer())
        .get(`/questionnaire/questions?assessmentId=${assessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(response.body.questions[0]).toHaveProperty('userResponse');
    });

    it('should reject unauthenticated requests', async () => {
      await request(app.getHttpServer())
        .get('/questionnaire/questions')
        .expect(401);
    });
  });

  describe('POST /questionnaire/responses', () => {
    it('should submit single choice response', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-001',
          answer: {
            value: 'monthly',
            text: 'Monthly',
          },
          notApplicable: false,
        })
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.assessmentId).toBe(assessmentId);
      expect(response.body.questionId).toBe('FIN-001');
      expect(response.body.answer.value).toBe('monthly');
      expect(response.body).toHaveProperty('answeredAt');
      expect(response.body).toHaveProperty('progress');
      expect(Number(response.body.progress)).toBeGreaterThan(0);
    });

    it('should submit rating response', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-002',
          answer: {
            value: 4,
          },
          notApplicable: false,
        })
        .expect(201);

      expect(response.body.answer.value).toBe(4);
      expect(response.body).toHaveProperty('progress');
    });

    it('should submit multiple choice response', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-003',
          answer: {
            values: ['quickbooks', 'excel'],
          },
          notApplicable: false,
        })
        .expect(201);

      expect(Array.isArray(response.body.answer.values)).toBe(true);
      expect(response.body.answer.values).toContain('quickbooks');
      expect(response.body.answer.values).toContain('excel');
    });

    it('should submit text response', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-004',
          answer: {
            text: 'We struggle with cash flow forecasting and need better reporting.',
          },
          notApplicable: false,
        })
        .expect(201);

      expect(response.body.answer.text).toBe(
        'We struggle with cash flow forecasting and need better reporting.'
      );
    });

    it('should submit response with consultant notes', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-001',
          answer: {
            value: 'weekly',
            text: 'Weekly',
          },
          consultantNotes: 'Client recently switched to weekly reviews',
          notApplicable: false,
        })
        .expect(201);

      expect(response.body.consultantNotes).toBe(
        'Client recently switched to weekly reviews'
      );
    });

    it('should submit response with not_applicable flag', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-003',
          answer: null,
          notApplicable: true,
          consultantNotes: 'Client does not use any accounting software yet',
        })
        .expect(201);

      expect(response.body.notApplicable).toBe(true);
      expect(response.body.answer).toBeNull();
    });

    it('should reject response without assessmentId', async () => {
      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          questionId: 'FIN-001',
          answer: {
            value: 'monthly',
          },
        })
        .expect(400);
    });

    it('should reject response without questionId', async () => {
      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          answer: {
            value: 'monthly',
          },
        })
        .expect(400);
    });

    it('should reject response without answer when notApplicable is false', async () => {
      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-001',
          notApplicable: false,
        })
        .expect(400);
    });

    it('should reject response for non-existent question', async () => {
      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'INVALID-001',
          answer: {
            value: 'test',
          },
        })
        .expect(404);
    });

    it('should reject response for non-existent assessment', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: fakeId,
          questionId: 'FIN-001',
          answer: {
            value: 'monthly',
          },
        })
        .expect(404);
    });

    it('should validate rating value within range', async () => {
      const response = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-002',
          answer: {
            value: 10, // Out of range (max is 5)
          },
        })
        .expect(400);

      expect(response.body.message).toContain('range');
    });

    it('should calculate progress after each response', async () => {
      // Create fresh assessment for progress test
      const newAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Progress Test',
          business_name: 'Progress Corp',
          client_email: 'progress@test.com',
        });

      const progressAssessmentId = newAssessment.body.id;

      // Submit first response (25% of 4 questions)
      const response1 = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: progressAssessmentId,
          questionId: 'FIN-001',
          answer: { value: 'monthly' },
        })
        .expect(201);

      expect(Number(response1.body.progress)).toBeCloseTo(25, 0);

      // Submit second response (50%)
      const response2 = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: progressAssessmentId,
          questionId: 'FIN-002',
          answer: { value: 3 },
        })
        .expect(201);

      expect(Number(response2.body.progress)).toBeCloseTo(50, 0);
    });
  });

  describe('PATCH /questionnaire/responses/:id', () => {
    let responseId: string;

    beforeAll(async () => {
      // Create a response to update
      const createResponse = await request(app.getHttpServer())
        .post('/questionnaire/responses')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          assessmentId: assessmentId,
          questionId: 'FIN-001',
          answer: { value: 'quarterly' },
        });

      responseId = createResponse.body.id;
    });

    it('should update existing response', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/questionnaire/responses/${responseId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          answer: { value: 'weekly', text: 'Weekly' },
          consultantNotes: 'Updated to weekly reviews',
        })
        .expect(200);

      expect(response.body.answer.value).toBe('weekly');
      expect(response.body.consultantNotes).toBe('Updated to weekly reviews');
    });

    it('should allow partial updates', async () => {
      const response = await request(app.getHttpServer())
        .patch(`/questionnaire/responses/${responseId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          consultantNotes: 'Only updating notes',
        })
        .expect(200);

      expect(response.body.consultantNotes).toBe('Only updating notes');
    });

    it('should reject update for non-existent response', async () => {
      const fakeId = '00000000-0000-0000-0000-000000000000';

      await request(app.getHttpServer())
        .patch(`/questionnaire/responses/${fakeId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          answer: { value: 'monthly' },
        })
        .expect(404);
    });
  });

  describe('Complete Questionnaire Flow', () => {
    it('should complete full questionnaire workflow', async () => {
      // Create new assessment
      const createAssessment = await request(app.getHttpServer())
        .post('/assessments')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          client_name: 'Complete Flow',
          business_name: 'Complete Corp',
          client_email: 'complete@test.com',
        });

      const flowAssessmentId = createAssessment.body.id;

      // 1. Get all questions
      const questionsResponse = await request(app.getHttpServer())
        .get('/questionnaire/questions')
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const questions = questionsResponse.body.questions;

      // 2. Answer all questions
      for (const question of questions) {
        let answer;

        switch (question.question_type) {
          case 'single_choice':
            answer = { value: question.options.options[0].value };
            break;
          case 'rating':
            answer = { value: 3 };
            break;
          case 'multiple_choice':
            answer = { values: [question.options.options[0].value] };
            break;
          case 'text':
            answer = { text: 'Sample text response' };
            break;
        }

        await request(app.getHttpServer())
          .post('/questionnaire/responses')
          .set('Authorization', `Bearer ${authToken}`)
          .send({
            assessmentId: flowAssessmentId,
            questionId: question.question_key,
            answer,
          })
          .expect(201);
      }

      // 3. Verify all questions answered
      const finalQuestionsResponse = await request(app.getHttpServer())
        .get(`/questionnaire/questions?assessmentId=${flowAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      const allAnswered = finalQuestionsResponse.body.questions.every(
        (q: any) => q.userResponse !== null
      );
      expect(allAnswered).toBe(true);

      // 4. Verify progress is 100%
      const assessmentCheck = await request(app.getHttpServer())
        .get(`/assessments/${flowAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .expect(200);

      expect(Number(assessmentCheck.body.progress)).toBe(100);

      // 5. Mark assessment as completed
      await request(app.getHttpServer())
        .patch(`/assessments/${flowAssessmentId}`)
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          status: 'completed',
        })
        .expect(200);
    });
  });
});
