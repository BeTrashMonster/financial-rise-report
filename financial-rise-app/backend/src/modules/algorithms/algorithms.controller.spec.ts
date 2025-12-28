import { Test, TestingModule } from '@nestjs/testing';
import { AlgorithmsController } from './algorithms.controller';
import { AlgorithmsService } from './algorithms.service';

describe('AlgorithmsController (Unit)', () => {
  let controller: AlgorithmsController;
  let service: AlgorithmsService;

  const mockDISCProfile = {
    id: 'disc-123',
    assessment_id: 'test-assessment-001',
    d_score: 75.5,
    i_score: 60.0,
    s_score: 45.5,
    c_score: 50.0,
    primary_type: 'D',
    secondary_type: 'I',
    confidence_level: 'high',
    calculated_at: new Date(),
  };

  const mockPhaseResults = {
    id: 'phase-123',
    assessment_id: 'test-assessment-001',
    stabilize_score: 80.0,
    organize_score: 60.0,
    build_score: 40.0,
    grow_score: 20.0,
    systemic_score: 50.0,
    primary_phase: 'stabilize',
    secondary_phases: ['organize'],
    transition_state: false,
    calculated_at: new Date(),
  };

  const mockCalculationResult = {
    disc_profile: mockDISCProfile,
    phase_results: mockPhaseResults,
    calculated_at: new Date(),
  };

  const mockAlgorithmsService = {
    calculateAll: jest.fn(),
    getDISCProfile: jest.fn(),
    getPhaseResults: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AlgorithmsController],
      providers: [
        {
          provide: AlgorithmsService,
          useValue: mockAlgorithmsService,
        },
      ],
    }).compile();

    controller = module.get<AlgorithmsController>(AlgorithmsController);
    service = module.get<AlgorithmsService>(AlgorithmsService);

    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
    expect(service).toBeDefined();
  });

  describe('POST /:id/calculate', () => {
    it('should calculate DISC profile and phase results', async () => {
      mockAlgorithmsService.calculateAll.mockResolvedValue(mockCalculationResult);

      const result = await controller.calculate('test-assessment-001');

      expect(result).toBeDefined();
      expect(result.assessment_id).toBe('test-assessment-001');
      expect(result.disc_profile).toBeDefined();
      expect(result.disc_profile.primary_type).toBe('D');
      expect(result.phase_results).toBeDefined();
      expect(result.phase_results.primary_phase).toBe('stabilize');
      expect(result.calculated_at).toBeInstanceOf(Date);
    });

    it('should return correct DISC scores', async () => {
      mockAlgorithmsService.calculateAll.mockResolvedValue(mockCalculationResult);

      const result = await controller.calculate('test-assessment-001');

      expect(result.disc_profile.d_score).toBe(75.5);
      expect(result.disc_profile.i_score).toBe(60.0);
      expect(result.disc_profile.s_score).toBe(45.5);
      expect(result.disc_profile.c_score).toBe(50.0);
    });

    it('should return correct phase scores', async () => {
      mockAlgorithmsService.calculateAll.mockResolvedValue(mockCalculationResult);

      const result = await controller.calculate('test-assessment-001');

      expect(result.phase_results.stabilize_score).toBe(80.0);
      expect(result.phase_results.organize_score).toBe(60.0);
      expect(result.phase_results.build_score).toBe(40.0);
      expect(result.phase_results.grow_score).toBe(20.0);
      expect(result.phase_results.systemic_score).toBe(50.0);
    });
  });

  describe('GET /:id/disc-profile', () => {
    it('should return DISC profile with personality summary', async () => {
      mockAlgorithmsService.getDISCProfile.mockResolvedValue(mockDISCProfile);

      const result = await controller.getDISCProfile('test-assessment-001');

      expect(result).toBeDefined();
      expect(result.primary_type).toBe('D');
      expect(result.secondary_type).toBe('I');
      expect(result.personality_summary).toBeDefined();
      expect(result.personality_summary.primary_traits).toContain('Direct');
    });

    it('should include appropriate communication style for D type', async () => {
      mockAlgorithmsService.getDISCProfile.mockResolvedValue(mockDISCProfile);

      const result = await controller.getDISCProfile('test-assessment-001');

      expect(result.personality_summary.communication_style).toContain('brief');
      expect(result.personality_summary.report_preferences.focus).toContain('ROI');
    });

    it('should handle I type personality', async () => {
      const iTypeProfile = { ...mockDISCProfile, primary_type: 'I', secondary_type: 'D' };
      mockAlgorithmsService.getDISCProfile.mockResolvedValue(iTypeProfile);

      const result = await controller.getDISCProfile('test-assessment-002');

      expect(result.personality_summary.primary_traits).toContain('Enthusiastic');
      expect(result.personality_summary.communication_style).toContain('collaborative');
    });
  });

  describe('GET /:id/phase-results', () => {
    it('should return phase results with phase details', async () => {
      mockAlgorithmsService.getPhaseResults.mockResolvedValue(mockPhaseResults);

      const result = await controller.getPhaseResults('test-assessment-001');

      expect(result).toBeDefined();
      expect(result.primary_phase).toBe('stabilize');
      expect(result.phase_details).toBeDefined();
      expect(result.phase_details['stabilize']).toBeDefined();
      expect(result.phase_details['stabilize'].name).toBe('Stabilize');
    });

    it('should include secondary phase details', async () => {
      mockAlgorithmsService.getPhaseResults.mockResolvedValue(mockPhaseResults);

      const result = await controller.getPhaseResults('test-assessment-001');

      expect(result.secondary_phases).toContain('organize');
      expect(result.phase_details['organize']).toBeDefined();
      expect(result.phase_details['organize'].name).toBe('Organize');
    });

    it('should include key focus areas for phases', async () => {
      mockAlgorithmsService.getPhaseResults.mockResolvedValue(mockPhaseResults);

      const result = await controller.getPhaseResults('test-assessment-001');

      expect(result.phase_details['stabilize'].key_focus_areas).toContain(
        'Chart of Accounts review and cleanup',
      );
      expect(result.phase_details['organize'].key_focus_areas).toContain(
        'Chart of Accounts proper setup',
      );
    });
  });
});
