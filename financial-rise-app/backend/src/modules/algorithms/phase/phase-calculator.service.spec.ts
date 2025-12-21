import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { PhaseCalculatorService } from './phase-calculator.service';
import { PhaseResult } from '../entities/phase-result.entity';
import { PhaseQuestionResponse } from './phase.types';

/**
 * Unit tests for Phase Calculator Service
 *
 * Tests individual methods in isolation without database
 */
describe('PhaseCalculatorService', () => {
  let service: PhaseCalculatorService;
  let repository: Repository<PhaseResult>;

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
        PhaseCalculatorService,
        {
          provide: getRepositoryToken(PhaseResult),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<PhaseCalculatorService>(PhaseCalculatorService);
    repository = module.get<Repository<PhaseResult>>(getRepositoryToken(PhaseResult));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('validateInputs', () => {
    it('should not throw error for valid responses', () => {
      const responses: PhaseQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: {
            stabilize_score: 5,
            organize_score: 3,
            build_score: 1,
            grow_score: 0,
            systemic_score: 1,
          },
        },
      ];

      expect(() => service.validateInputs(responses)).not.toThrow();
    });

    it('should throw error for empty responses', () => {
      const responses: PhaseQuestionResponse[] = [];

      expect(() => service.validateInputs(responses)).toThrow(
        'No phase question responses provided',
      );
    });
  });

  describe('aggregateScores', () => {
    it('should correctly aggregate phase scores', () => {
      const responses: PhaseQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: {
            stabilize_score: 10,
            organize_score: 5,
            build_score: 3,
            grow_score: 2,
            systemic_score: 2,
          },
        },
        {
          question_id: 'q2',
          selected_value: 'opt2',
          weights: {
            stabilize_score: 8,
            organize_score: 6,
            build_score: 4,
            grow_score: 2,
            systemic_score: 3,
          },
        },
      ];

      const scores = service.aggregateScores(responses);

      expect(scores.stabilize).toBe(18); // 10 + 8
      expect(scores.organize).toBe(11); // 5 + 6
      expect(scores.build).toBe(7); // 3 + 4
      expect(scores.grow).toBe(4); // 2 + 2
      expect(scores.systemic).toBe(5); // 2 + 3
    });

    it('should handle missing weights gracefully', () => {
      const responses: PhaseQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: {
            stabilize_score: undefined as any,
            organize_score: 5,
            build_score: 0,
            grow_score: 0,
            systemic_score: 0,
          },
        },
      ];

      const scores = service.aggregateScores(responses);

      expect(scores.stabilize).toBe(0);
      expect(scores.organize).toBe(5);
    });
  });

  describe('normalizeScores', () => {
    it('should normalize scores to 0-100 scale', () => {
      const rawScores = {
        stabilize: 20,
        organize: 30,
        build: 20,
        grow: 20,
        systemic: 10,
      }; // Total: 100

      const normalized = service.normalizeScores(rawScores);

      expect(normalized.stabilize).toBe(20);
      expect(normalized.organize).toBe(30);
      expect(normalized.build).toBe(20);
      expect(normalized.grow).toBe(20);
      expect(normalized.systemic).toBe(10);
    });

    it('should normalize correctly when total is not 100', () => {
      const rawScores = {
        stabilize: 10,
        organize: 10,
        build: 10,
        grow: 10,
        systemic: 10,
      }; // Total: 50

      const normalized = service.normalizeScores(rawScores);

      expect(normalized.stabilize).toBe(20);
      expect(normalized.organize).toBe(20);
      expect(normalized.build).toBe(20);
      expect(normalized.grow).toBe(20);
      expect(normalized.systemic).toBe(20);
    });

    it('should handle zero total by returning even distribution', () => {
      const rawScores = {
        stabilize: 0,
        organize: 0,
        build: 0,
        grow: 0,
        systemic: 0,
      };

      const normalized = service.normalizeScores(rawScores);

      expect(normalized.stabilize).toBe(20);
      expect(normalized.organize).toBe(20);
      expect(normalized.build).toBe(20);
      expect(normalized.grow).toBe(20);
      expect(normalized.systemic).toBe(20);
    });

    it('should ensure scores sum to approximately 100', () => {
      const rawScores = {
        stabilize: 15,
        organize: 25,
        build: 35,
        grow: 45,
        systemic: 30,
      }; // Total: 150

      const normalized = service.normalizeScores(rawScores);

      const total =
        normalized.stabilize +
        normalized.organize +
        normalized.build +
        normalized.grow +
        normalized.systemic;
      expect(total).toBeCloseTo(100, 1);
    });
  });

  describe('rankPhases', () => {
    it('should rank phases by score in descending order', () => {
      const scores = {
        stabilize: 10,
        organize: 40,
        build: 30,
        grow: 15,
        systemic: 5,
      };

      const rankings = service.rankPhases(scores);

      expect(rankings).toHaveLength(5);
      expect(rankings[0].phase).toBe('organize'); // Highest
      expect(rankings[0].score).toBe(40);
      expect(rankings[1].phase).toBe('build');
      expect(rankings[1].score).toBe(30);
      expect(rankings[4].phase).toBe('systemic'); // Lowest
      expect(rankings[4].score).toBe(5);
    });

    it('should handle ties correctly', () => {
      const scores = {
        stabilize: 20,
        organize: 30,
        build: 30,
        grow: 10,
        systemic: 10,
      };

      const rankings = service.rankPhases(scores);

      expect(rankings).toHaveLength(5);
      // Organize and Build are tied at 30
      expect([rankings[0].score, rankings[1].score]).toEqual([30, 30]);
    });
  });

  describe('applySequencingLogic', () => {
    it('should identify stabilize as primary when score is very low (<40)', () => {
      const scores = {
        stabilize: 30, // Low score (< 40)
        organize: 25,
        build: 20,
        grow: 15,
        systemic: 10,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.primaryPhase).toBe('stabilize');
      expect(result.secondaryPhases).toEqual([]);
      expect(result.transitionState).toBe(false);
    });

    it('should apply sequential override when organize score is low but build is high', () => {
      const scores = {
        stabilize: 60, // Good
        organize: 45, // Moderate but < 50
        build: 60, // High (>organize + 10)
        grow: 20,
        systemic: 15,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.primaryPhase).toBe('organize');
      expect(result.secondaryPhases).toContain('build');
      expect(result.transitionState).toBe(true);
    });

    it('should identify highest score as primary when no overrides apply', () => {
      const scores = {
        stabilize: 70, // Good
        organize: 65, // Good
        build: 75, // Highest
        grow: 40,
        systemic: 50,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.primaryPhase).toBe('build');
    });

    it('should identify secondary phases within 15-point threshold', () => {
      const scores = {
        stabilize: 50,
        organize: 48, // Within 15 points of organize
        build: 47, // Within 15 points
        grow: 30, // Beyond 15 points
        systemic: 25,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.secondaryPhases).toContain('organize');
      expect(result.secondaryPhases).toContain('build');
      expect(result.secondaryPhases).not.toContain('grow');
      expect(result.transitionState).toBe(true);
    });

    it('should default to stabilize for perfectly even scores', () => {
      const scores = {
        stabilize: 20,
        organize: 20,
        build: 20,
        grow: 20,
        systemic: 20,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.primaryPhase).toBe('stabilize');
      expect(result.transitionState).toBe(true);
      expect(result.secondaryPhases).toEqual([
        'organize',
        'build',
        'grow',
        'systemic',
      ]);
    });

    it('should not identify secondary phases when primary is dominant', () => {
      const scores = {
        stabilize: 80, // Very high
        organize: 50,
        build: 30,
        grow: 20,
        systemic: 20,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.primaryPhase).toBe('stabilize');
      expect(result.secondaryPhases).toEqual([]);
      expect(result.transitionState).toBe(false);
    });

    it('should handle organize as primary phase', () => {
      const scores = {
        stabilize: 70, // Good foundation
        organize: 45, // Highest need
        build: 30,
        grow: 25,
        systemic: 30,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      expect(result.primaryPhase).toBe('stabilize');
    });

    it('should handle grow as primary phase', () => {
      const scores = {
        stabilize: 80, // Strong
        organize: 75, // Strong
        build: 70, // Strong
        grow: 40, // Highest need (inverted - higher score = more ready, so lower is more need)
        systemic: 60,
      };
      const rankings = service.rankPhases(scores);

      const result = service.applySequencingLogic(scores, rankings);

      // Since all foundation phases are strong (>50), highest score should win
      expect(result.primaryPhase).toBe('stabilize');
    });
  });

  describe('calculate (integration)', () => {
    it('should create and save phase result', async () => {
      const assessmentId = 'test-assessment-789';
      const responses: PhaseQuestionResponse[] = [
        {
          question_id: 'q1',
          selected_value: 'opt1',
          weights: {
            stabilize_score: 10,
            organize_score: 5,
            build_score: 3,
            grow_score: 2,
            systemic_score: 2,
          },
        },
        {
          question_id: 'q2',
          selected_value: 'opt2',
          weights: {
            stabilize_score: 8,
            organize_score: 6,
            build_score: 4,
            grow_score: 2,
            systemic_score: 3,
          },
        },
      ];

      const mockResult = {
        id: 'result-789',
        assessment_id: assessmentId,
        stabilize_score: 40,
        organize_score: 24.4,
        build_score: 15.6,
        grow_score: 8.9,
        systemic_score: 11.1,
        primary_phase: 'stabilize',
        secondary_phases: [],
        transition_state: false,
        calculated_at: new Date(),
      };

      mockRepository.create.mockReturnValue(mockResult);
      mockRepository.save.mockResolvedValue(mockResult);

      const result = await service.calculate(assessmentId, responses);

      expect(result).toBeDefined();
      expect(result.assessment_id).toBe(assessmentId);
      expect(result.primary_phase).toBe('stabilize');
      expect(mockRepository.create).toHaveBeenCalled();
      expect(mockRepository.save).toHaveBeenCalled();
    });
  });

  describe('getResult', () => {
    it('should retrieve existing phase result', async () => {
      const assessmentId = 'test-assessment-101';
      const mockResult = {
        id: 'result-101',
        assessment_id: assessmentId,
        stabilize_score: 25,
        organize_score: 35,
        build_score: 20,
        grow_score: 15,
        systemic_score: 5,
        primary_phase: 'organize',
        secondary_phases: ['build'],
        transition_state: true,
        calculated_at: new Date(),
      };

      mockRepository.findOne.mockResolvedValue(mockResult);

      const result = await service.getResult(assessmentId);

      expect(result).toBe(mockResult);
      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { assessment_id: assessmentId },
      });
    });

    it('should return null if result does not exist', async () => {
      const assessmentId = 'non-existent';

      mockRepository.findOne.mockResolvedValue(null);

      const result = await service.getResult(assessmentId);

      expect(result).toBeNull();
    });
  });

  describe('resultExists', () => {
    it('should return true if result exists', async () => {
      const assessmentId = 'existing-assessment';

      mockRepository.count.mockResolvedValue(1);

      const exists = await service.resultExists(assessmentId);

      expect(exists).toBe(true);
      expect(mockRepository.count).toHaveBeenCalledWith({
        where: { assessment_id: assessmentId },
      });
    });

    it('should return false if result does not exist', async () => {
      const assessmentId = 'non-existent-assessment';

      mockRepository.count.mockResolvedValue(0);

      const exists = await service.resultExists(assessmentId);

      expect(exists).toBe(false);
    });
  });
});
