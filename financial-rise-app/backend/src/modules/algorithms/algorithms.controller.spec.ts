import { Test, TestingModule } from '@nestjs/testing';
import { TypeOrmModule, getRepositoryToken } from '@nestjs/typeorm';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { AlgorithmsController } from './algorithms.controller';
import { AlgorithmsService } from './algorithms.service';
import { DISCCalculatorService } from './disc/disc-calculator.service';
import { PhaseCalculatorService } from './phase/phase-calculator.service';
import { DISCProfile } from './entities/disc-profile.entity';
import { PhaseResult } from './entities/phase-result.entity';
import { testDatabaseConfig } from '../../../test/test-db.config';
import {
  fullAssessmentResponses,
  highDominanceResponses,
  highInfluenceResponses,
  highSteadinessResponses,
  highComplianceResponses,
  stabilizePhaseResponses,
  organizePhaseResponses,
  buildPhaseResponses,
  growPhaseResponses,
  insufficientDISCResponses,
  mixedDISCResponses,
} from '../../../test/fixtures/test-data';

/**
 * Integration tests for Algorithms Controller
 *
 * These tests validate all three API endpoints with a real database:
 * - POST /api/v1/assessments/:id/calculate
 * - GET /api/v1/assessments/:id/disc-profile
 * - GET /api/v1/assessments/:id/phase-results
 *
 * Test Database: SQLite in-memory (auto-setup and teardown)
 */
describe('AlgorithmsController (Integration)', () => {
  let controller: AlgorithmsController;
  let service: AlgorithmsService;
  let module: TestingModule;

  // Setup before all tests
  beforeAll(async () => {
    module = await Test.createTestingModule({
      imports: [
        TypeOrmModule.forRoot(testDatabaseConfig),
        TypeOrmModule.forFeature([DISCProfile, PhaseResult]),
      ],
      controllers: [AlgorithmsController],
      providers: [AlgorithmsService, DISCCalculatorService, PhaseCalculatorService],
    }).compile();

    controller = module.get<AlgorithmsController>(AlgorithmsController);
    service = module.get<AlgorithmsService>(AlgorithmsService);
  });

  // Clean database before each test
  beforeEach(async () => {
    const discRepository = module.get(getRepositoryToken(DISCProfile));
    const phaseRepository = module.get(getRepositoryToken(PhaseResult));
    await discRepository.clear();
    await phaseRepository.clear();

    // Reset question cache to pick up updated question weights
    service.resetCache();
  });

  // Cleanup after all tests
  afterAll(async () => {
    await module.close();
  });

  describe('Health Check', () => {
    it('should be defined', () => {
      expect(controller).toBeDefined();
      expect(service).toBeDefined();
    });
  });

  describe('POST /api/v1/assessments/:id/calculate', () => {
    const assessmentId = 'test-assessment-001';

    beforeEach(async () => {
      // Mock the getMockResponses method to return test data
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue(fullAssessmentResponses.highDStabilize);
    });

    it('should calculate DISC profile and phase results successfully', async () => {
      const result = await controller.calculate(assessmentId);

      expect(result).toBeDefined();
      expect(result.assessment_id).toBe(assessmentId);
      expect(result.disc_profile).toBeDefined();
      expect(result.phase_results).toBeDefined();
      expect(result.calculated_at).toBeInstanceOf(Date);
    });

    it('should return valid DISC profile data', async () => {
      const result = await controller.calculate('test-assessment-disc-001');

      const { disc_profile } = result;

      // Check required fields
      expect(disc_profile.assessment_id).toBe('test-assessment-disc-001');
      expect(disc_profile.d_score).toBeGreaterThanOrEqual(0);
      expect(disc_profile.d_score).toBeLessThanOrEqual(100);
      expect(disc_profile.i_score).toBeGreaterThanOrEqual(0);
      expect(disc_profile.i_score).toBeLessThanOrEqual(100);
      expect(disc_profile.s_score).toBeGreaterThanOrEqual(0);
      expect(disc_profile.s_score).toBeLessThanOrEqual(100);
      expect(disc_profile.c_score).toBeGreaterThanOrEqual(0);
      expect(disc_profile.c_score).toBeLessThanOrEqual(100);

      // Check primary type is valid
      expect(['D', 'I', 'S', 'C']).toContain(disc_profile.primary_type);

      // Check confidence level is valid
      expect(['high', 'moderate', 'low']).toContain(disc_profile.confidence_level);

      // Check scores sum to approximately 100 (allowing for rounding)
      const total =
        disc_profile.d_score +
        disc_profile.i_score +
        disc_profile.s_score +
        disc_profile.c_score;
      expect(total).toBeGreaterThan(99);
      expect(total).toBeLessThan(101);
    });

    it('should return valid phase results data', async () => {
      const result = await controller.calculate('test-assessment-phase-001');

      const { phase_results } = result;

      // Check required fields
      expect(phase_results.assessment_id).toBe('test-assessment-phase-001');
      expect(phase_results.stabilize_score).toBeGreaterThanOrEqual(0);
      expect(phase_results.stabilize_score).toBeLessThanOrEqual(100);
      expect(phase_results.organize_score).toBeGreaterThanOrEqual(0);
      expect(phase_results.organize_score).toBeLessThanOrEqual(100);
      expect(phase_results.build_score).toBeGreaterThanOrEqual(0);
      expect(phase_results.build_score).toBeLessThanOrEqual(100);
      expect(phase_results.grow_score).toBeGreaterThanOrEqual(0);
      expect(phase_results.grow_score).toBeLessThanOrEqual(100);
      expect(phase_results.systemic_score).toBeGreaterThanOrEqual(0);
      expect(phase_results.systemic_score).toBeLessThanOrEqual(100);

      // Check primary phase is valid
      expect(['stabilize', 'organize', 'build', 'grow', 'systemic']).toContain(
        phase_results.primary_phase,
      );

      // Check secondary phases is an array
      expect(Array.isArray(phase_results.secondary_phases)).toBe(true);

      // Check transition state is boolean
      expect(typeof phase_results.transition_state).toBe('boolean');

      // Check scores sum to approximately 100
      const total =
        phase_results.stabilize_score +
        phase_results.organize_score +
        phase_results.build_score +
        phase_results.grow_score +
        phase_results.systemic_score;
      expect(total).toBeGreaterThan(99);
      expect(total).toBeLessThan(101);
    });

    it('should throw ConflictException if calculation already exists', async () => {
      const duplicateId = 'test-assessment-duplicate';

      // First calculation should succeed
      await controller.calculate(duplicateId);

      // Second calculation should throw conflict
      await expect(controller.calculate(duplicateId)).rejects.toThrow(ConflictException);
    });

    it('should calculate high D (Dominance) type correctly', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...stabilizePhaseResponses]);

      const result = await controller.calculate('test-high-d');
      const { disc_profile } = result;

      expect(disc_profile.primary_type).toBe('D');
      expect(disc_profile.d_score).toBeGreaterThan(disc_profile.i_score);
      expect(disc_profile.d_score).toBeGreaterThan(disc_profile.s_score);
      expect(disc_profile.d_score).toBeGreaterThan(disc_profile.c_score);
    });

    it('should calculate high I (Influence) type correctly', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highInfluenceResponses, ...organizePhaseResponses]);

      const result = await controller.calculate('test-high-i');
      const { disc_profile } = result;

      expect(disc_profile.primary_type).toBe('I');
      expect(disc_profile.i_score).toBeGreaterThan(disc_profile.d_score);
      expect(disc_profile.i_score).toBeGreaterThan(disc_profile.s_score);
      expect(disc_profile.i_score).toBeGreaterThan(disc_profile.c_score);
    });

    it('should calculate high S (Steadiness) type correctly', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highSteadinessResponses, ...buildPhaseResponses]);

      const result = await controller.calculate('test-high-s');
      const { disc_profile } = result;

      expect(disc_profile.primary_type).toBe('S');
      expect(disc_profile.s_score).toBeGreaterThan(disc_profile.d_score);
      expect(disc_profile.s_score).toBeGreaterThan(disc_profile.i_score);
      expect(disc_profile.s_score).toBeGreaterThan(disc_profile.c_score);
    });

    it('should calculate high C (Compliance) type correctly', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highComplianceResponses, ...growPhaseResponses]);

      const result = await controller.calculate('test-high-c');
      const { disc_profile } = result;

      expect(disc_profile.primary_type).toBe('C');
      expect(disc_profile.c_score).toBeGreaterThan(disc_profile.d_score);
      expect(disc_profile.c_score).toBeGreaterThan(disc_profile.i_score);
      expect(disc_profile.c_score).toBeGreaterThan(disc_profile.s_score);
    });

    it('should identify Stabilize as primary phase for poor financial organization', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...stabilizePhaseResponses]);

      const result = await controller.calculate('test-stabilize-phase');
      const { phase_results } = result;

      expect(phase_results.primary_phase).toBe('stabilize');
    });

    it('should identify Organize as primary phase for good stabilization', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...organizePhaseResponses]);

      const result = await controller.calculate('test-organize-phase');
      const { phase_results } = result;

      expect(phase_results.primary_phase).toBe('organize');
    });

    it('should identify Build as primary phase for good foundation', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...buildPhaseResponses]);

      const result = await controller.calculate('test-build-phase');
      const { phase_results } = result;

      expect(phase_results.primary_phase).toBe('build');
    });

    it('should identify Grow as primary phase for strong systems', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...growPhaseResponses]);

      const result = await controller.calculate('test-grow-phase');
      const { phase_results } = result;

      expect(phase_results.primary_phase).toBe('grow');
    });

    it('should identify secondary traits when DISC scores are close', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...mixedDISCResponses, ...stabilizePhaseResponses]);

      const result = await controller.calculate('test-mixed-disc');
      const { disc_profile } = result;

      // Mixed responses should potentially have a secondary type
      // (depends on exact score distribution)
      if (disc_profile.secondary_type) {
        expect(['D', 'I', 'S', 'C']).toContain(disc_profile.secondary_type);
        expect(disc_profile.secondary_type).not.toBe(disc_profile.primary_type);
      }
    });

    it('should handle insufficient DISC data gracefully', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...insufficientDISCResponses, ...stabilizePhaseResponses]);

      const result = await controller.calculate('test-insufficient-disc');
      const { disc_profile } = result;

      // Should still calculate but with low confidence
      expect(disc_profile).toBeDefined();
      expect(disc_profile.confidence_level).toBe('low');
    });
  });

  describe('GET /api/v1/assessments/:id/disc-profile', () => {
    const assessmentId = 'test-get-disc-profile';

    beforeEach(async () => {
      // Create a calculation first
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue(fullAssessmentResponses.highDStabilize);

      await controller.calculate(assessmentId);
    });

    it('should retrieve DISC profile with personality summary', async () => {
      const result = await controller.getDISCProfile(assessmentId);

      expect(result).toBeDefined();
      expect(result.assessment_id).toBe(assessmentId);
      expect(result.primary_type).toBeDefined();
      expect(result.personality_summary).toBeDefined();
    });

    it('should include personality summary with correct fields', async () => {
      const result = await controller.getDISCProfile(assessmentId);

      const { personality_summary } = result;

      expect(personality_summary.primary_traits).toBeDefined();
      expect(Array.isArray(personality_summary.primary_traits)).toBe(true);
      expect(personality_summary.primary_traits.length).toBeGreaterThan(0);

      expect(personality_summary.communication_style).toBeDefined();
      expect(typeof personality_summary.communication_style).toBe('string');

      expect(personality_summary.report_preferences).toBeDefined();
      expect(personality_summary.report_preferences.focus).toBeDefined();
      expect(personality_summary.report_preferences.visual_style).toBeDefined();
    });

    it('should provide D-type personality summary for Dominance', async () => {
      const dTypeId = 'test-d-type-summary';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...stabilizePhaseResponses]);

      await controller.calculate(dTypeId);
      const result = await controller.getDISCProfile(dTypeId);

      expect(result.primary_type).toBe('D');
      expect(result.personality_summary.primary_traits).toContain('Direct');
      expect(result.personality_summary.primary_traits).toContain('Results-oriented');
    });

    it('should provide I-type personality summary for Influence', async () => {
      const iTypeId = 'test-i-type-summary';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highInfluenceResponses, ...organizePhaseResponses]);

      await controller.calculate(iTypeId);
      const result = await controller.getDISCProfile(iTypeId);

      expect(result.primary_type).toBe('I');
      expect(result.personality_summary.primary_traits).toContain('Outgoing');
      expect(result.personality_summary.primary_traits).toContain('Enthusiastic');
    });

    it('should provide S-type personality summary for Steadiness', async () => {
      const sTypeId = 'test-s-type-summary';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highSteadinessResponses, ...buildPhaseResponses]);

      await controller.calculate(sTypeId);
      const result = await controller.getDISCProfile(sTypeId);

      expect(result.primary_type).toBe('S');
      expect(result.personality_summary.primary_traits).toContain('Patient');
      expect(result.personality_summary.primary_traits).toContain('Reliable');
    });

    it('should provide C-type personality summary for Compliance', async () => {
      const cTypeId = 'test-c-type-summary';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highComplianceResponses, ...growPhaseResponses]);

      await controller.calculate(cTypeId);
      const result = await controller.getDISCProfile(cTypeId);

      expect(result.primary_type).toBe('C');
      expect(result.personality_summary.primary_traits).toContain('Analytical');
      expect(result.personality_summary.primary_traits).toContain('Detail-oriented');
    });

    it('should throw NotFoundException if profile does not exist', async () => {
      const nonExistentId = 'non-existent-assessment';

      await expect(controller.getDISCProfile(nonExistentId)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('GET /api/v1/assessments/:id/phase-results', () => {
    const assessmentId = 'test-get-phase-results';

    beforeEach(async () => {
      // Create a calculation first
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue(fullAssessmentResponses.highDStabilize);

      await controller.calculate(assessmentId);
    });

    it('should retrieve phase results with phase details', async () => {
      const result = await controller.getPhaseResults(assessmentId);

      expect(result).toBeDefined();
      expect(result.assessment_id).toBe(assessmentId);
      expect(result.primary_phase).toBeDefined();
      expect(result.phase_details).toBeDefined();
    });

    it('should include phase details for primary phase', async () => {
      const result = await controller.getPhaseResults(assessmentId);

      const primaryPhaseDetails = result.phase_details[result.primary_phase];

      expect(primaryPhaseDetails).toBeDefined();
      expect(primaryPhaseDetails.name).toBeDefined();
      expect(primaryPhaseDetails.objective).toBeDefined();
      expect(primaryPhaseDetails.key_focus_areas).toBeDefined();
      expect(Array.isArray(primaryPhaseDetails.key_focus_areas)).toBe(true);
      expect(primaryPhaseDetails.key_focus_areas.length).toBeGreaterThan(0);
    });

    it('should include phase details for secondary phases', async () => {
      const result = await controller.getPhaseResults(assessmentId);

      if (result.secondary_phases.length > 0) {
        const secondaryPhase = result.secondary_phases[0];
        const secondaryPhaseDetails = result.phase_details[secondaryPhase];

        expect(secondaryPhaseDetails).toBeDefined();
        expect(secondaryPhaseDetails.name).toBeDefined();
        expect(secondaryPhaseDetails.objective).toBeDefined();
        expect(secondaryPhaseDetails.key_focus_areas).toBeDefined();
      }
    });

    it('should provide Stabilize phase details correctly', async () => {
      const stabilizeId = 'test-stabilize-details';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...stabilizePhaseResponses]);

      await controller.calculate(stabilizeId);
      const result = await controller.getPhaseResults(stabilizeId);

      expect(result.primary_phase).toBe('stabilize');

      const stabilizeDetails = result.phase_details.stabilize;
      expect(stabilizeDetails.name).toBe('Stabilize');
      expect(stabilizeDetails.objective).toContain('basic financial order');
      expect(stabilizeDetails.key_focus_areas).toContain(
        'Chart of Accounts review and cleanup',
      );
    });

    it('should provide Organize phase details correctly', async () => {
      const organizeId = 'test-organize-details';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...organizePhaseResponses]);

      await controller.calculate(organizeId);
      const result = await controller.getPhaseResults(organizeId);

      expect(result.primary_phase).toBe('organize');

      const organizeDetails = result.phase_details.organize;
      expect(organizeDetails.name).toBe('Organize');
      expect(organizeDetails.objective).toContain('foundational financial systems');
      expect(organizeDetails.key_focus_areas).toContain('Chart of Accounts proper setup');
    });

    it('should provide Build phase details correctly', async () => {
      const buildId = 'test-build-details';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...buildPhaseResponses]);

      await controller.calculate(buildId);
      const result = await controller.getPhaseResults(buildId);

      expect(result.primary_phase).toBe('build');

      const buildDetails = result.phase_details.build;
      expect(buildDetails.name).toBe('Build');
      expect(buildDetails.objective).toContain('robust operational systems');
      expect(buildDetails.key_focus_areas).toContain('Financial SOPs development');
    });

    it('should provide Grow phase details correctly', async () => {
      const growId = 'test-grow-details';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue([...highDominanceResponses, ...growPhaseResponses]);

      await controller.calculate(growId);
      const result = await controller.getPhaseResults(growId);

      expect(result.primary_phase).toBe('grow');

      const growDetails = result.phase_details.grow;
      expect(growDetails.name).toBe('Grow');
      expect(growDetails.objective).toContain('strategic financial planning');
      expect(growDetails.key_focus_areas).toContain('Revenue forecasting');
    });

    it('should throw NotFoundException if phase result does not exist', async () => {
      const nonExistentId = 'non-existent-phase-assessment';

      await expect(controller.getPhaseResults(nonExistentId)).rejects.toThrow(
        NotFoundException,
      );
    });

    it('should include transition state when multiple phases are needed', async () => {
      const result = await controller.getPhaseResults(assessmentId);

      expect(typeof result.transition_state).toBe('boolean');

      if (result.secondary_phases.length > 0) {
        expect(result.transition_state).toBe(true);
      }
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle assessment with no responses gracefully', async () => {
      jest.spyOn(controller as any, 'getMockResponses').mockResolvedValue([]);

      await expect(controller.calculate('test-no-responses')).rejects.toThrow();
    });

    it('should persist results to database correctly', async () => {
      const persistId = 'test-persistence';

      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue(fullAssessmentResponses.highDStabilize);

      // Calculate
      await controller.calculate(persistId);

      // Verify DISC profile persisted
      const discProfile = await controller.getDISCProfile(persistId);
      expect(discProfile.assessment_id).toBe(persistId);

      // Verify phase results persisted
      const phaseResults = await controller.getPhaseResults(persistId);
      expect(phaseResults.assessment_id).toBe(persistId);
    });

    it('should handle concurrent requests for different assessments', async () => {
      jest
        .spyOn(controller as any, 'getMockResponses')
        .mockResolvedValue(fullAssessmentResponses.highDStabilize);

      const promises = [
        controller.calculate('concurrent-1'),
        controller.calculate('concurrent-2'),
        controller.calculate('concurrent-3'),
      ];

      const results = await Promise.all(promises);

      expect(results).toHaveLength(3);
      expect(results[0].assessment_id).toBe('concurrent-1');
      expect(results[1].assessment_id).toBe('concurrent-2');
      expect(results[2].assessment_id).toBe('concurrent-3');
    });
  });
});
