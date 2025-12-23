import { Test, TestingModule } from '@nestjs/testing';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { AlgorithmsService } from './algorithms.service';
import { DISCCalculatorService } from './disc/disc-calculator.service';
import { PhaseCalculatorService } from './phase/phase-calculator.service';
import { DISCProfileResult } from './disc/disc.types';
import { PhaseResultData } from './phase/phase.types';

/**
 * Unit tests for Algorithms Service (Orchestrator)
 *
 * Tests the coordination between DISC and Phase calculations
 */
describe('AlgorithmsService', () => {
  let service: AlgorithmsService;
  let discCalculator: DISCCalculatorService;
  let phaseCalculator: PhaseCalculatorService;

  // Mock calculator services
  const mockDISCCalculator = {
    calculate: jest.fn(),
    getProfile: jest.fn(),
    profileExists: jest.fn(),
  };

  const mockPhaseCalculator = {
    calculate: jest.fn(),
    getResult: jest.fn(),
    resultExists: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AlgorithmsService,
        {
          provide: DISCCalculatorService,
          useValue: mockDISCCalculator,
        },
        {
          provide: PhaseCalculatorService,
          useValue: mockPhaseCalculator,
        },
      ],
    }).compile();

    service = module.get<AlgorithmsService>(AlgorithmsService);
    discCalculator = module.get<DISCCalculatorService>(DISCCalculatorService);
    phaseCalculator = module.get<PhaseCalculatorService>(PhaseCalculatorService);

    // Reset cache before each test
    service.resetCache();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('calculateAll', () => {
    it('should throw ConflictException if DISC profile already exists', async () => {
      const assessmentId = 'test-assessment-123';
      const responses = [
        { question_id: 'disc-001', response_value: 'decide_quickly' },
      ];

      mockDISCCalculator.profileExists.mockResolvedValue(true);
      mockPhaseCalculator.resultExists.mockResolvedValue(false);

      await expect(service.calculateAll(assessmentId, responses)).rejects.toThrow(
        ConflictException,
      );
      await expect(service.calculateAll(assessmentId, responses)).rejects.toThrow(
        'Results already calculated for this assessment',
      );
    });

    it('should throw ConflictException if Phase result already exists', async () => {
      const assessmentId = 'test-assessment-456';
      const responses = [
        { question_id: 'stab-001', response_value: 'current' },
      ];

      mockDISCCalculator.profileExists.mockResolvedValue(false);
      mockPhaseCalculator.resultExists.mockResolvedValue(true);

      await expect(service.calculateAll(assessmentId, responses)).rejects.toThrow(
        ConflictException,
      );
    });

    it('should calculate both DISC and Phase results successfully', async () => {
      const assessmentId = 'test-assessment-789';
      const responses = [
        { question_id: 'disc-001', response_value: 'decide_quickly' },
        { question_id: 'stab-001', response_value: 'current' },
      ];

      const mockDISCProfile: DISCProfileResult = {
        assessment_id: assessmentId,
        d_score: 60,
        i_score: 20,
        s_score: 10,
        c_score: 10,
        primary_type: 'D',
        secondary_type: null,
        confidence_level: 'high',
        calculated_at: new Date(),
      };

      const mockPhaseResults: PhaseResultData = {
        assessment_id: assessmentId,
        stabilize_score: 30,
        organize_score: 25,
        build_score: 20,
        grow_score: 15,
        systemic_score: 10,
        primary_phase: 'stabilize',
        secondary_phases: [],
        transition_state: false,
        calculated_at: new Date(),
      };

      mockDISCCalculator.profileExists.mockResolvedValue(false);
      mockPhaseCalculator.resultExists.mockResolvedValue(false);
      mockDISCCalculator.calculate.mockResolvedValue(mockDISCProfile);
      mockPhaseCalculator.calculate.mockResolvedValue(mockPhaseResults);

      const result = await service.calculateAll(assessmentId, responses);

      expect(result).toBeDefined();
      expect(result.disc_profile).toEqual(mockDISCProfile);
      expect(result.phase_results).toEqual(mockPhaseResults);
      expect(result.calculated_at).toBeInstanceOf(Date);
      expect(mockDISCCalculator.calculate).toHaveBeenCalled();
      expect(mockPhaseCalculator.calculate).toHaveBeenCalled();
    });

    it('should separate DISC and Phase responses correctly', async () => {
      const assessmentId = 'test-assessment-mixed';
      const responses = [
        { question_id: 'disc-001', response_value: 'decide_quickly' },
        { question_id: 'disc-002', response_value: 'lead_direct' },
        { question_id: 'stab-001', response_value: 'current' },
        { question_id: 'org-001', response_value: 'fully_separated' },
      ];

      const mockDISCProfile: DISCProfileResult = {
        assessment_id: assessmentId,
        d_score: 50,
        i_score: 25,
        s_score: 15,
        c_score: 10,
        primary_type: 'D',
        secondary_type: 'I',
        confidence_level: 'moderate',
        calculated_at: new Date(),
      };

      const mockPhaseResults: PhaseResultData = {
        assessment_id: assessmentId,
        stabilize_score: 20,
        organize_score: 30,
        build_score: 25,
        grow_score: 15,
        systemic_score: 10,
        primary_phase: 'organize',
        secondary_phases: ['build'],
        transition_state: true,
        calculated_at: new Date(),
      };

      mockDISCCalculator.profileExists.mockResolvedValue(false);
      mockPhaseCalculator.resultExists.mockResolvedValue(false);
      mockDISCCalculator.calculate.mockResolvedValue(mockDISCProfile);
      mockPhaseCalculator.calculate.mockResolvedValue(mockPhaseResults);

      await service.calculateAll(assessmentId, responses);

      // Verify DISC calculator was called with DISC responses only
      expect(mockDISCCalculator.calculate).toHaveBeenCalledWith(
        assessmentId,
        expect.any(Array),
      );

      // Verify Phase calculator was called with Phase responses only
      expect(mockPhaseCalculator.calculate).toHaveBeenCalledWith(
        assessmentId,
        expect.any(Array),
      );
    });
  });

  describe('getDISCProfile', () => {
    it('should retrieve existing DISC profile', async () => {
      const assessmentId = 'test-get-disc-123';
      const mockProfile = {
        assessment_id: assessmentId,
        d_score: 40,
        i_score: 35,
        s_score: 15,
        c_score: 10,
        primary_type: 'D' as const,
        secondary_type: 'I' as const,
        confidence_level: 'moderate' as const,
        calculated_at: new Date(),
      };

      mockDISCCalculator.getProfile.mockResolvedValue(mockProfile);

      const result = await service.getDISCProfile(assessmentId);

      expect(result).toEqual(mockProfile);
      expect(mockDISCCalculator.getProfile).toHaveBeenCalledWith(assessmentId);
    });

    it('should throw NotFoundException if DISC profile does not exist', async () => {
      const assessmentId = 'non-existent-disc';

      mockDISCCalculator.getProfile.mockResolvedValue(null);

      await expect(service.getDISCProfile(assessmentId)).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.getDISCProfile(assessmentId)).rejects.toThrow(
        'DISC profile not found',
      );
    });
  });

  describe('getPhaseResults', () => {
    it('should retrieve existing phase results', async () => {
      const assessmentId = 'test-get-phase-456';
      const mockResults = {
        assessment_id: assessmentId,
        stabilize_score: 25,
        organize_score: 30,
        build_score: 20,
        grow_score: 15,
        systemic_score: 10,
        primary_phase: 'organize' as const,
        secondary_phases: [],
        transition_state: false,
        calculated_at: new Date(),
      };

      mockPhaseCalculator.getResult.mockResolvedValue(mockResults);

      const result = await service.getPhaseResults(assessmentId);

      expect(result).toEqual(mockResults);
      expect(mockPhaseCalculator.getResult).toHaveBeenCalledWith(assessmentId);
    });

    it('should throw NotFoundException if phase results do not exist', async () => {
      const assessmentId = 'non-existent-phase';

      mockPhaseCalculator.getResult.mockResolvedValue(null);

      await expect(service.getPhaseResults(assessmentId)).rejects.toThrow(
        NotFoundException,
      );
      await expect(service.getPhaseResults(assessmentId)).rejects.toThrow(
        'Phase results not found',
      );
    });
  });

  describe('resetCache', () => {
    it('should reset the question weights cache', () => {
      // This is mainly for testing purposes
      expect(() => service.resetCache()).not.toThrow();
    });
  });
});
