import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DISCCalculatorService } from './disc-calculator.service';
import { DISCProfile } from '../entities/disc-profile.entity';
import { DISCQuestionResponse } from './disc.types';

/**
 * Unit tests for DISC Calculator Service
 *
 * Tests individual methods in isolation without database
 */
describe('DISCCalculatorService', () => {
  let service: DISCCalculatorService;
  let repository: Repository<DISCProfile>;

  // Mock repository
  const mockRepository = {
    create: jest.fn(),
    save: jest.fn(),
    findOne: jest.fn(),
    count: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DISCCalculatorService,
        {
          provide: getRepositoryToken(DISCProfile),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<DISCCalculatorService>(DISCCalculatorService);
    repository = module.get<Repository<DISCProfile>>(getRepositoryToken(DISCProfile));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('validateInputs', () => {
    it('should not throw error for sufficient responses (8+)', () => {
      const responses: DISCQuestionResponse[] = Array(8).fill({
        question_id: 'test',
        selected_value: 'test',
        weights: { disc_d_score: 5, disc_i_score: 5, disc_s_score: 0, disc_c_score: 0 },
      });

      expect(() => service.validateInputs(responses)).not.toThrow();
    });

    it('should log warning but not throw for insufficient responses (<8)', () => {
      const responses: DISCQuestionResponse[] = Array(4).fill({
        question_id: 'test',
        selected_value: 'test',
        weights: { disc_d_score: 5, disc_i_score: 5, disc_s_score: 0, disc_c_score: 0 },
      });

      // Should not throw, just log warning
      expect(() => service.validateInputs(responses)).not.toThrow();
    });

    it('should throw error for zero responses', () => {
      const responses: DISCQuestionResponse[] = [];

      expect(() => service.validateInputs(responses)).toThrow(
        'No DISC question responses provided',
      );
    });
  });

  describe('aggregateScores', () => {
    it('should correctly aggregate D scores', () => {
      const responses: DISCQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: { disc_d_score: 10, disc_i_score: 0, disc_s_score: 0, disc_c_score: 0 },
        },
        {
          question_id: 'q2',
          selected_value: 'opt2',
          weights: { disc_d_score: 8, disc_i_score: 2, disc_s_score: 0, disc_c_score: 0 },
        },
        {
          question_id: 'q3',
          selected_value: 'opt3',
          weights: { disc_d_score: 9, disc_i_score: 1, disc_s_score: 0, disc_c_score: 0 },
        },
      ];

      const scores = service.aggregateScores(responses);

      expect(scores.D).toBe(27); // 10 + 8 + 9
      expect(scores.I).toBe(3); // 0 + 2 + 1
      expect(scores.S).toBe(0);
      expect(scores.C).toBe(0);
    });

    it('should correctly aggregate all DISC scores', () => {
      const responses: DISCQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: { disc_d_score: 5, disc_i_score: 3, disc_s_score: 1, disc_c_score: 1 },
        },
        {
          question_id: 'q2',
          selected_value: 'opt2',
          weights: { disc_d_score: 4, disc_i_score: 4, disc_s_score: 1, disc_c_score: 1 },
        },
        {
          question_id: 'q3',
          selected_value: 'opt3',
          weights: { disc_d_score: 6, disc_i_score: 2, disc_s_score: 1, disc_c_score: 1 },
        },
      ];

      const scores = service.aggregateScores(responses);

      expect(scores.D).toBe(15); // 5 + 4 + 6
      expect(scores.I).toBe(9); // 3 + 4 + 2
      expect(scores.S).toBe(3); // 1 + 1 + 1
      expect(scores.C).toBe(3); // 1 + 1 + 1
    });

    it('should handle missing weights gracefully', () => {
      const responses: DISCQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: { disc_d_score: undefined as any, disc_i_score: 5, disc_s_score: 0, disc_c_score: 0 },
        },
      ];

      const scores = service.aggregateScores(responses);

      expect(scores.D).toBe(0);
      expect(scores.I).toBe(5);
    });
  });

  describe('normalizeScores', () => {
    it('should normalize scores to 0-100 scale', () => {
      const rawScores = { D: 30, I: 20, S: 10, C: 40 }; // Total: 100

      const normalized = service.normalizeScores(rawScores);

      expect(normalized.D).toBe(30);
      expect(normalized.I).toBe(20);
      expect(normalized.S).toBe(10);
      expect(normalized.C).toBe(40);
    });

    it('should normalize correctly when total is not 100', () => {
      const rawScores = { D: 10, I: 10, S: 10, C: 10 }; // Total: 40

      const normalized = service.normalizeScores(rawScores);

      expect(normalized.D).toBe(25);
      expect(normalized.I).toBe(25);
      expect(normalized.S).toBe(25);
      expect(normalized.C).toBe(25);
    });

    it('should handle zero total by returning even distribution', () => {
      const rawScores = { D: 0, I: 0, S: 0, C: 0 };

      const normalized = service.normalizeScores(rawScores);

      expect(normalized.D).toBe(25);
      expect(normalized.I).toBe(25);
      expect(normalized.S).toBe(25);
      expect(normalized.C).toBe(25);
    });

    it('should ensure scores sum to approximately 100', () => {
      const rawScores = { D: 15, I: 25, S: 35, C: 45 }; // Total: 120

      const normalized = service.normalizeScores(rawScores);

      const total = normalized.D + normalized.I + normalized.S + normalized.C;
      expect(total).toBeCloseTo(100, 1);
    });
  });

  describe('determinePrimaryType', () => {
    it('should identify D as primary when D score is highest', () => {
      const scores = { D: 50, I: 20, S: 15, C: 15 };

      const primaryType = service.determinePrimaryType(scores);

      expect(primaryType).toBe('D');
    });

    it('should identify I as primary when I score is highest', () => {
      const scores = { D: 20, I: 45, S: 20, C: 15 };

      const primaryType = service.determinePrimaryType(scores);

      expect(primaryType).toBe('I');
    });

    it('should identify S as primary when S score is highest', () => {
      const scores = { D: 15, I: 20, S: 50, C: 15 };

      const primaryType = service.determinePrimaryType(scores);

      expect(primaryType).toBe('S');
    });

    it('should identify C as primary when C score is highest', () => {
      const scores = { D: 15, I: 15, S: 20, C: 50 };

      const primaryType = service.determinePrimaryType(scores);

      expect(primaryType).toBe('C');
    });

    it('should default to C for perfectly even scores', () => {
      const scores = { D: 25, I: 25, S: 25, C: 25 };

      const primaryType = service.determinePrimaryType(scores);

      expect(primaryType).toBe('C');
    });

    it('should handle tie between two types by defaulting to C', () => {
      const scores = { D: 30, I: 30, S: 20, C: 20 };

      const primaryType = service.determinePrimaryType(scores);

      expect(primaryType).toBe('C');
    });
  });

  describe('identifySecondaryTraits', () => {
    it('should identify secondary trait when within 10-point threshold', () => {
      const scores = { D: 40, I: 35, S: 15, C: 10 };
      const primaryType = 'D';

      const secondaryType = service.identifySecondaryTraits(scores, primaryType);

      expect(secondaryType).toBe('I'); // I is 5 points away (within 10)
    });

    it('should not identify secondary trait when beyond threshold', () => {
      const scores = { D: 50, I: 30, S: 15, C: 5 };
      const primaryType = 'D';

      const secondaryType = service.identifySecondaryTraits(scores, primaryType);

      expect(secondaryType).toBeNull(); // I is 20 points away (beyond 10)
    });

    it('should identify the highest non-primary score as secondary', () => {
      const scores = { D: 45, I: 38, S: 12, C: 5 };
      const primaryType = 'D';

      const secondaryType = service.identifySecondaryTraits(scores, primaryType);

      expect(secondaryType).toBe('I'); // I is highest non-primary
    });

    it('should return null when all other scores are far below primary', () => {
      const scores = { D: 70, I: 10, S: 10, C: 10 };
      const primaryType = 'D';

      const secondaryType = service.identifySecondaryTraits(scores, primaryType);

      expect(secondaryType).toBeNull();
    });
  });

  describe('calculateConfidenceLevel', () => {
    it('should return high confidence for clear primary with >40% and >15 point difference', () => {
      const scores = { D: 50, I: 20, S: 20, C: 10 };

      const confidence = service.calculateConfidenceLevel(scores);

      expect(confidence).toBe('high');
    });

    it('should return moderate confidence for >30% primary with >10 point difference', () => {
      const scores = { D: 40, I: 25, S: 20, C: 15 };

      const confidence = service.calculateConfidenceLevel(scores);

      expect(confidence).toBe('moderate');
    });

    it('should return low confidence for close scores', () => {
      const scores = { D: 30, I: 28, S: 22, C: 20 };

      const confidence = service.calculateConfidenceLevel(scores);

      expect(confidence).toBe('low');
    });

    it('should return low confidence for even distribution', () => {
      const scores = { D: 25, I: 25, S: 25, C: 25 };

      const confidence = service.calculateConfidenceLevel(scores);

      expect(confidence).toBe('low');
    });

    it('should return high confidence for very dominant score', () => {
      const scores = { D: 70, I: 10, S: 10, C: 10 };

      const confidence = service.calculateConfidenceLevel(scores);

      expect(confidence).toBe('high');
    });
  });

  describe('calculate (integration)', () => {
    it('should create and save DISC profile', async () => {
      const assessmentId = 'test-assessment-123';
      const responses: DISCQuestionResponse[] = Array(15).fill({
        question_id: 'test',
        selected_value: 'test',
        weights: { disc_d_score: 8, disc_i_score: 1, disc_s_score: 0, disc_c_score: 1 },
      });

      const mockProfile = {
        id: 'profile-123',
        assessment_id: assessmentId,
        d_score: 80,
        i_score: 10,
        s_score: 0,
        c_score: 10,
        primary_type: 'D',
        secondary_type: null,
        confidence_level: 'high',
        calculated_at: new Date(),
      };

      mockRepository.create.mockReturnValue(mockProfile);
      mockRepository.save.mockResolvedValue(mockProfile);

      const result = await service.calculate(assessmentId, responses);

      expect(result).toBeDefined();
      expect(result.assessment_id).toBe(assessmentId);
      expect(result.primary_type).toBe('D');
      expect(mockRepository.create).toHaveBeenCalled();
      expect(mockRepository.save).toHaveBeenCalled();
    });
  });

  describe('getProfile', () => {
    it('should retrieve existing profile', async () => {
      const assessmentId = 'test-assessment-456';
      const mockProfile = {
        id: 'profile-456',
        assessment_id: assessmentId,
        d_score: 30,
        i_score: 40,
        s_score: 20,
        c_score: 10,
        primary_type: 'I',
        secondary_type: 'D',
        confidence_level: 'high',
        calculated_at: new Date(),
      };

      mockRepository.findOne.mockResolvedValue(mockProfile);

      const result = await service.getProfile(assessmentId);

      expect(result).toBe(mockProfile);
      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { assessment_id: assessmentId },
      });
    });

    it('should return null if profile does not exist', async () => {
      const assessmentId = 'non-existent';

      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.getProfile(assessmentId);

      expect(result).toBeNull();
    });
  });

  describe('profileExists', () => {
    it('should return true if profile exists', async () => {
      const assessmentId = 'existing-assessment';

      mockRepository.count.mockResolvedValue(1);

      const exists = await service.profileExists(assessmentId);

      expect(exists).toBe(true);
      expect(mockRepository.count).toHaveBeenCalledWith({
        where: { assessment_id: assessmentId },
      });
    });

    it('should return false if profile does not exist', async () => {
      const assessmentId = 'non-existent-assessment';

      mockRepository.count.mockResolvedValue(0);

      const exists = await service.profileExists(assessmentId);

      expect(exists).toBe(false);
    });
  });
});
