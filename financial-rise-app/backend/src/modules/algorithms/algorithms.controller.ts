import {
  Controller,
  Get,
  Post,
  Param,
  UseGuards,
  HttpCode,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { AlgorithmsService } from './algorithms.service';
import {
  CalculationResultDto,
  DISCProfileDto,
  DISCProfileWithSummaryDto,
  PhaseResultsDto,
  PhaseResultsWithDetailsDto,
} from './dto';

// TODO: Import JwtAuthGuard when auth module is integrated
// import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

/**
 * Controller for DISC & Phase algorithm endpoints
 *
 * Implements API endpoints as specified in:
 * plans/work-stream-7-implementation-spec.md Section 4
 */
@Controller('api/v1/assessments')
// @UseGuards(JwtAuthGuard) // TODO: Enable when auth is integrated
export class AlgorithmsController {
  private readonly logger = new Logger(AlgorithmsController.name);

  constructor(private readonly algorithmsService: AlgorithmsService) {}

  /**
   * Calculate DISC profile and phase results for an assessment
   *
   * POST /api/v1/assessments/:id/calculate
   *
   * @param id - Assessment UUID
   * @returns Combined DISC and phase calculation results
   */
  @Post(':id/calculate')
  @HttpCode(HttpStatus.CREATED)
  async calculate(@Param('id') id: string): Promise<CalculationResultDto> {
    this.logger.log(`POST /api/v1/assessments/${id}/calculate`);

    // TODO: Validate that user owns this assessment (authorization)
    // TODO: Fetch assessment responses from database
    // For now, using mock responses - will integrate with Assessment API later

    const mockResponses = await this.getMockResponses(id);

    const result = await this.algorithmsService.calculateAll(id, mockResponses);

    return {
      assessment_id: id,
      disc_profile: {
        assessment_id: result.disc_profile.assessment_id,
        d_score: result.disc_profile.d_score,
        i_score: result.disc_profile.i_score,
        s_score: result.disc_profile.s_score,
        c_score: result.disc_profile.c_score,
        primary_type: result.disc_profile.primary_type,
        secondary_type: result.disc_profile.secondary_type,
        confidence_level: result.disc_profile.confidence_level,
        calculated_at: result.disc_profile.calculated_at,
      },
      phase_results: {
        assessment_id: result.phase_results.assessment_id,
        stabilize_score: result.phase_results.stabilize_score,
        organize_score: result.phase_results.organize_score,
        build_score: result.phase_results.build_score,
        grow_score: result.phase_results.grow_score,
        systemic_score: result.phase_results.systemic_score,
        primary_phase: result.phase_results.primary_phase,
        secondary_phases: result.phase_results.secondary_phases,
        transition_state: result.phase_results.transition_state,
        calculated_at: result.phase_results.calculated_at,
      },
      calculated_at: result.calculated_at,
    };
  }

  /**
   * Get DISC personality profile for an assessment
   *
   * GET /api/v1/assessments/:id/disc-profile
   *
   * @param id - Assessment UUID
   * @returns DISC profile with personality summary
   */
  @Get(':id/disc-profile')
  async getDISCProfile(@Param('id') id: string): Promise<DISCProfileWithSummaryDto> {
    this.logger.log(`GET /api/v1/assessments/${id}/disc-profile`);

    // TODO: Validate that user owns this assessment (authorization)

    const profile = await this.algorithmsService.getDISCProfile(id);

    // Enrich with personality summary
    const summary = this.getPersonalitySummary(profile.primary_type);

    return {
      ...profile,
      personality_summary: summary,
    };
  }

  /**
   * Get financial readiness phase results for an assessment
   *
   * GET /api/v1/assessments/:id/phase-results
   *
   * @param id - Assessment UUID
   * @returns Phase results with phase details
   */
  @Get(':id/phase-results')
  async getPhaseResults(@Param('id') id: string): Promise<PhaseResultsWithDetailsDto> {
    this.logger.log(`GET /api/v1/assessments/${id}/phase-results`);

    // TODO: Validate that user owns this assessment (authorization)

    const results = await this.algorithmsService.getPhaseResults(id);

    // Enrich with phase details
    const phaseDetails = this.getPhaseDetails(
      results.primary_phase,
      results.secondary_phases,
    );

    return {
      ...results,
      phase_details: phaseDetails,
    };
  }

  /**
   * Get personality summary based on DISC type
   *
   * TODO: Move to a dedicated mapper service
   */
  private getPersonalitySummary(type: string): {
    primary_traits: string[];
    communication_style: string;
    report_preferences: {
      focus: string;
      visual_style: string;
    };
  } {
    const summaries = {
      D: {
        primary_traits: ['Direct', 'Results-oriented', 'Decisive', 'Competitive'],
        communication_style: 'Prefers brief, bottom-line communication',
        report_preferences: {
          focus: 'ROI, quick wins, action steps',
          visual_style: 'Charts, graphs, bullet points',
        },
      },
      I: {
        primary_traits: ['Outgoing', 'Enthusiastic', 'Optimistic', 'Relationship-focused'],
        communication_style: 'Prefers collaborative, positive interaction',
        report_preferences: {
          focus: 'Emphasize opportunities, people impact, big picture',
          visual_style: 'Colorful visuals, stories, testimonials',
        },
      },
      S: {
        primary_traits: ['Patient', 'Reliable', 'Supportive', 'Team-oriented'],
        communication_style: 'Prefers calm, step-by-step approach',
        report_preferences: {
          focus: 'Emphasize stability, support available, gentle pace',
          visual_style: 'Clear timelines, process diagrams, reassuring language',
        },
      },
      C: {
        primary_traits: ['Analytical', 'Detail-oriented', 'Systematic', 'Quality-focused'],
        communication_style: 'Prefers data, logic, thorough explanations',
        report_preferences: {
          focus: 'Provide detailed analysis, data support, systematic approach',
          visual_style: 'Detailed tables, comprehensive analysis, thorough documentation',
        },
      },
    };

    return summaries[type as keyof typeof summaries] || summaries['C'];
  }

  /**
   * Get phase details for enrichment
   *
   * TODO: Move to a dedicated mapper service or load from JSON
   */
  private getPhaseDetails(
    primaryPhase: string,
    secondaryPhases: string[],
  ): Record<string, any> {
    const allPhaseDetails = {
      stabilize: {
        name: 'Stabilize',
        objective: 'Establish basic financial order and compliance',
        key_focus_areas: [
          'Chart of Accounts review and cleanup',
          'Bank reconciliation',
          'Tax preparation readiness',
          'Debt management',
        ],
      },
      organize: {
        name: 'Organize',
        objective: 'Build foundational financial systems and processes',
        key_focus_areas: [
          'Chart of Accounts proper setup',
          'Accounting system integration',
          'Payroll system configuration',
          'Vendor and customer setup',
        ],
      },
      build: {
        name: 'Build',
        objective: 'Create robust operational systems and workflows',
        key_focus_areas: [
          'Financial SOPs development',
          'Team workflow documentation',
          'Custom spreadsheet or tool creation',
        ],
      },
      grow: {
        name: 'Grow',
        objective: 'Enable strategic financial planning and forecasting',
        key_focus_areas: [
          'Revenue forecasting',
          'Expense planning',
          'Cash flow pattern analysis',
          'Scenario planning',
        ],
      },
      systemic: {
        name: 'Systemic (Financial Literacy)',
        objective: 'Develop capability to read, interpret, and act on financial reports',
        key_focus_areas: [
          'Profit & Loss statement understanding',
          'Balance sheet understanding',
          'Cash flow statement understanding',
          'Key metric identification',
        ],
      },
    };

    const details: Record<string, any> = {};

    // Include primary phase details
    if (allPhaseDetails[primaryPhase as keyof typeof allPhaseDetails]) {
      details[primaryPhase] = allPhaseDetails[primaryPhase as keyof typeof allPhaseDetails];
    }

    // Include secondary phase details
    for (const phase of secondaryPhases) {
      if (allPhaseDetails[phase as keyof typeof allPhaseDetails]) {
        details[phase] = allPhaseDetails[phase as keyof typeof allPhaseDetails];
      }
    }

    return details;
  }

  /**
   * Mock assessment responses for testing
   *
   * TODO: Replace with actual database fetch when Assessment API is integrated
   */
  private async getMockResponses(assessmentId: string): Promise<any[]> {
    // Mock responses for demonstration
    // In production, this will fetch from the assessments.responses table
    return [
      { question_id: 'disc-001', response_value: 'decide_quickly' },
      { question_id: 'disc-002', response_value: 'lead_direct' },
      { question_id: 'stab-001', response_value: 'current' },
      { question_id: 'stab-002', response_value: 'fully_separated' },
    ];
  }
}
