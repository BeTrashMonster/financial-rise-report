import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  UseGuards,
  NotFoundException,
  BadRequestException,
  Logger,
  Res,
  StreamableFile,
} from '@nestjs/common';
import { Response } from 'express';
import * as fs from 'fs/promises';
import * as path from 'path';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../modules/auth/guards/jwt-auth.guard';
import { ReportOwnershipGuard } from '../common/guards/report-ownership.guard';
import { GetUser } from '../modules/auth/decorators/get-user.decorator';
import { ReportGenerationService } from './services/report-generation.service';
import { GenerateReportDto } from './dto/generate-report.dto';
import { ReportResponseDto, ReportAcceptedDto } from './dto/report-response.dto';
import { AssessmentsService } from '../modules/assessments/assessments.service';
import { AlgorithmsService } from '../modules/algorithms/algorithms.service';
import { AssessmentStatus } from '../modules/assessments/entities/assessment.entity';
import { FinancialPhase } from '../modules/algorithms/entities/phase-result.entity';

/**
 * Controller for report generation and retrieval endpoints
 * Implements API contract from API-CONTRACT.md Section 5
 */
@ApiTags('Reports')
@Controller('reports')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class ReportsController {
  private readonly logger = new Logger(ReportsController.name);

  constructor(
    private readonly reportGenerationService: ReportGenerationService,
    private readonly assessmentsService: AssessmentsService,
    private readonly algorithmsService: AlgorithmsService,
  ) {}

  /**
   * POST /reports/generate/consultant
   * Generates a consultant report PDF asynchronously
   */
  @Post('generate/consultant')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Generate consultant report' })
  @ApiResponse({
    status: 202,
    description: 'Report generation started',
    type: ReportAcceptedDto,
  })
  async generateConsultantReport(@Body() dto: GenerateReportDto, @GetUser() user: any): Promise<ReportAcceptedDto> {
    this.logger.log(`Generating consultant report for assessment ${dto.assessmentId}`);

    // Fetch assessment with all relationships
    const assessment = await this.assessmentsService.findOne(dto.assessmentId, user.id);

    // Verify assessment is completed
    if (assessment.status !== AssessmentStatus.COMPLETED) {
      throw new BadRequestException('Assessment must be completed before generating reports');
    }

    // Fetch DISC profile and phase results
    const discProfile = await this.algorithmsService.getDISCProfile(dto.assessmentId);
    const phaseResults = await this.algorithmsService.getPhaseResults(dto.assessmentId);

    if (!discProfile || !phaseResults) {
      throw new BadRequestException('Assessment results not found. Please ensure the assessment was submitted successfully.');
    }

    // Transform data for report template
    const consultantData = {
      client: {
        name: assessment.client_name,
        businessName: assessment.business_name,
        email: assessment.client_email,
      },
      assessment: {
        id: assessment.id,
        completedAt: assessment.completed_at || new Date(),
      },
      discProfile: {
        primaryType: discProfile.primary_type as any,
        scores: {
          D: discProfile.d_score,
          I: discProfile.i_score,
          S: discProfile.s_score,
          C: discProfile.c_score,
        },
        secondaryTraits: discProfile.secondary_type ? [discProfile.secondary_type] : [],
        confidence: 'high',
      },
      phaseResults: {
        primaryPhase: phaseResults.primary_phase as any,
        scores: {
          stabilize: phaseResults.stabilize_score,
          organize: phaseResults.organize_score,
          build: phaseResults.build_score,
          grow: phaseResults.grow_score,
          systemic: phaseResults.systemic_score,
        } as any,
        secondaryPhases: (phaseResults.secondary_phases || []) as FinancialPhase[],
      },
      responses: [], // Empty for now - response transformation not needed for PDF template
      consultantNotes: assessment.notes || '',
    };

    const report = await this.reportGenerationService.generateConsultantReport(consultantData, user.id);

    return {
      reportId: report.id,
      status: 'generating',
      message: 'Report generation started. Poll /reports/status/{reportId} for updates.',
      estimatedCompletionTime: 5,
    };
  }

  /**
   * POST /reports/generate/client
   * Generates a client report PDF asynchronously
   */
  @Post('generate/client')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({ summary: 'Generate client report' })
  @ApiResponse({
    status: 202,
    description: 'Report generation started',
    type: ReportAcceptedDto,
  })
  async generateClientReport(@Body() dto: GenerateReportDto, @GetUser() user: any): Promise<ReportAcceptedDto> {
    this.logger.log(`Generating client report for assessment ${dto.assessmentId}`);

    // Fetch assessment with all relationships
    const assessment = await this.assessmentsService.findOne(dto.assessmentId, user.id);

    // Verify assessment is completed
    if (assessment.status !== AssessmentStatus.COMPLETED) {
      throw new BadRequestException('Assessment must be completed before generating reports');
    }

    // Fetch DISC profile and phase results
    const discProfile = await this.algorithmsService.getDISCProfile(dto.assessmentId);
    const phaseResults = await this.algorithmsService.getPhaseResults(dto.assessmentId);

    if (!discProfile || !phaseResults) {
      throw new BadRequestException('Assessment results not found. Please ensure the assessment was submitted successfully.');
    }

    // Generate quick wins based on phase scores (top 3 improvement areas)
    const quickWins = this.generateQuickWins(phaseResults);

    // Generate roadmap based on primary and secondary phases
    const roadmap = this.generateRoadmap(phaseResults);

    // Transform data for report template
    const clientData = {
      client: {
        name: assessment.client_name,
        businessName: assessment.business_name,
        email: assessment.client_email,
      },
      discProfile: {
        primaryType: discProfile.primary_type as any,
        scores: {
          D: discProfile.d_score,
          I: discProfile.i_score,
          S: discProfile.s_score,
          C: discProfile.c_score,
        },
        secondaryTraits: discProfile.secondary_type ? [discProfile.secondary_type] : [],
        confidence: 'high',
      },
      phaseResults: {
        primaryPhase: phaseResults.primary_phase as any,
        scores: {
          stabilize: phaseResults.stabilize_score,
          organize: phaseResults.organize_score,
          build: phaseResults.build_score,
          grow: phaseResults.grow_score,
          systemic: phaseResults.systemic_score,
        } as any,
        secondaryPhases: (phaseResults.secondary_phases || []) as FinancialPhase[],
      },
      quickWins,
      roadmap,
      branding: {
        consultantName: user.name || 'Your Financial Consultant',
        logo: null,
        brandColor: '#4B006E',
      },
    };

    const report = await this.reportGenerationService.generateClientReport(clientData, user.id, dto.assessmentId);

    return {
      reportId: report.id,
      status: 'generating',
      message: 'Report generation started. Poll /reports/status/{reportId} for updates.',
      estimatedCompletionTime: 5,
    };
  }

  /**
   * GET /reports/status/:id
   * Gets the status of a report generation request
   */
  @Get('status/:id')
  @UseGuards(ReportOwnershipGuard)
  @ApiOperation({ summary: 'Get report generation status - IDOR protected' })
  @ApiResponse({ status: 200, description: 'Report status', type: ReportResponseDto })
  @ApiResponse({ status: 404, description: 'Report not found' })
  @ApiResponse({ status: 403, description: 'Forbidden - report belongs to another user' })
  async getReportStatus(@Param('id') reportId: string): Promise<ReportResponseDto> {
    this.logger.log(`Fetching status for report ${reportId}`);

    const report = await this.reportGenerationService.getReportStatus(reportId);

    if (!report) {
      throw new NotFoundException(`Report ${reportId} not found`);
    }

    return {
      reportId: report.id,
      assessmentId: report.assessmentId,
      reportType: report.reportType,
      status: report.status,
      fileUrl: report.fileUrl,
      fileSizeBytes: report.fileSizeBytes,
      generatedAt: report.generatedAt?.toISOString() || null,
      expiresAt: report.expiresAt?.toISOString() || null,
      error: report.error,
    };
  }

  /**
   * GET /reports/download/:id
   * Downloads a generated report (redirects to signed URL)
   */
  @Get('download/:id')
  @UseGuards(ReportOwnershipGuard)
  @ApiOperation({ summary: 'Download generated report - IDOR protected' })
  @ApiResponse({ status: 200, description: 'Redirects to report PDF' })
  @ApiResponse({ status: 404, description: 'Report not found or not ready' })
  @ApiResponse({ status: 403, description: 'Forbidden - report belongs to another user' })
  async downloadReport(@Param('id') reportId: string): Promise<{ url: string }> {
    this.logger.log(`Downloading report ${reportId}`);

    const report = await this.reportGenerationService.getReportStatus(reportId);

    if (!report) {
      throw new NotFoundException(`Report ${reportId} not found`);
    }

    if (report.status !== 'completed' || !report.fileUrl) {
      throw new NotFoundException(`Report ${reportId} is not ready for download`);
    }

    // Check if URL has expired
    if (report.expiresAt && new Date() > report.expiresAt) {
      throw new NotFoundException(`Report ${reportId} has expired`);
    }

    // Return the signed URL for download
    return { url: report.fileUrl };
  }

  /**
   * GET /reports/files/:filename
   * Serves local PDF files (when GCS is not configured)
   */
  @Get('files/:filename')
  @ApiOperation({ summary: 'Download local PDF file' })
  @ApiResponse({ status: 200, description: 'PDF file' })
  @ApiResponse({ status: 404, description: 'File not found' })
  async downloadLocalFile(
    @Param('filename') filename: string,
    @Res({ passthrough: true }) res: Response,
  ): Promise<StreamableFile> {
    try {
      // Convert double dashes back to slashes
      const actualFilename = filename.replace(/--/g, '/');

      // Build file path
      const filePath = path.join(process.cwd(), 'reports', actualFilename);

      // Check if file exists
      try {
        await fs.access(filePath);
      } catch {
        throw new NotFoundException('PDF file not found');
      }

      // Read file
      const fileBuffer = await fs.readFile(filePath);

      // Set response headers
      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="${path.basename(actualFilename)}"`,
      });

      return new StreamableFile(fileBuffer);
    } catch (error) {
      this.logger.error(`Error serving local PDF ${filename}:`, error);
      if (error instanceof NotFoundException) {
        throw error;
      }
      throw new NotFoundException('Failed to retrieve PDF file');
    }
  }

  /**
   * POST /reports/disc-profile
   * Calculate and save DISC profile for an assessment
   * Note: This is handled by AlgorithmsController, kept here for API contract completeness
   */
  @Post('disc-profile')
  @ApiOperation({
    summary: 'Calculate DISC profile',
    description: 'Redirects to /algorithms/disc - kept for API contract compatibility',
  })
  @ApiResponse({ status: 307, description: 'Temporary redirect to /algorithms/disc' })
  calculateDISCProfile(@Body() dto: GenerateReportDto) {
    // This endpoint is actually handled by AlgorithmsController
    // Keeping this for API contract documentation
    return {
      message: 'Use POST /algorithms/disc endpoint instead',
      redirectTo: '/api/v1/algorithms/disc',
    };
  }

  /**
   * POST /reports/phase-result
   * Calculate and save phase results for an assessment
   * Note: This is handled by AlgorithmsController, kept here for API contract completeness
   */
  @Post('phase-result')
  @ApiOperation({
    summary: 'Calculate phase result',
    description: 'Redirects to /algorithms/phase - kept for API contract compatibility',
  })
  @ApiResponse({ status: 307, description: 'Temporary redirect to /algorithms/phase' })
  calculatePhaseResult(@Body() dto: GenerateReportDto) {
    // This endpoint is actually handled by AlgorithmsController
    // Keeping this for API contract documentation
    return {
      message: 'Use POST /algorithms/phase endpoint instead',
      redirectTo: '/api/v1/algorithms/phase',
    };
  }

  /**
   * Generate quick wins based on phase scores
   * Identifies top 3 areas for improvement with lowest scores
   */
  private generateQuickWins(phaseResults: any): Array<{ action: string; why: string; benefit: string }> {
    const phaseQuickWins: Record<string, { action: string; why: string; benefit: string }> = {
      stabilize: {
        action: 'Set up automated bank reconciliation',
        why: 'Reduces manual errors and ensures accurate financial records',
        benefit: 'Save 2-3 hours per week and catch discrepancies early',
      },
      organize: {
        action: 'Implement a standardized chart of accounts',
        why: 'Creates consistency in financial reporting',
        benefit: 'Easier to track expenses and generate meaningful reports',
      },
      build: {
        action: 'Document your month-end close process',
        why: 'Ensures consistency and reduces time to close books',
        benefit: 'Close books 50% faster with fewer errors',
      },
      grow: {
        action: 'Create a 13-week cash flow forecast',
        why: 'Provides early warning of cash shortfalls',
        benefit: 'Make informed decisions about hiring and investments',
      },
      systemic: {
        action: 'Schedule monthly financial review meetings',
        why: 'Keeps financial health top of mind',
        benefit: 'Catch trends early and make data-driven decisions',
      },
    };

    // Find bottom 3 phases by score
    const phases = [
      { phase: 'stabilize', score: phaseResults.stabilize_score },
      { phase: 'organize', score: phaseResults.organize_score },
      { phase: 'build', score: phaseResults.build_score },
      { phase: 'grow', score: phaseResults.grow_score },
      { phase: 'systemic', score: phaseResults.systemic_score },
    ];

    return phases
      .sort((a, b) => a.score - b.score)
      .slice(0, 3)
      .map((p) => phaseQuickWins[p.phase]);
  }

  /**
   * Generate roadmap based on phase results
   * Creates prioritized list of phases and milestones
   */
  private generateRoadmap(phaseResults: any): { phases: FinancialPhase[]; milestones: string[] } {
    const phaseMilestones: Record<string, string[]> = {
      stabilize: [
        'Clean up historical accounting records',
        'Establish regular bookkeeping schedule',
        'Reconcile all bank and credit card accounts',
      ],
      organize: [
        'Set up proper chart of accounts',
        'Integrate accounting software with bank feeds',
        'Implement approval workflows for expenses',
      ],
      build: [
        'Document month-end close procedures',
        'Create financial reporting templates',
        'Set up budget vs actual tracking',
      ],
      grow: [
        'Develop 12-month revenue forecast',
        'Create scenario planning models',
        'Implement KPI dashboard',
      ],
      systemic: [
        'Establish monthly financial review cadence',
        'Train team on reading financial statements',
        'Develop data-driven decision framework',
      ],
    };

    // Determine phase sequence based on scores
    const phaseOrder: FinancialPhase[] = ['stabilize', 'organize', 'build', 'grow', 'systemic'];
    const currentPhaseIndex = phaseOrder.indexOf(phaseResults.primary_phase.toLowerCase() as FinancialPhase);

    // Roadmap includes current phase and next 2 phases
    const roadmapPhases = phaseOrder.slice(currentPhaseIndex, currentPhaseIndex + 3);

    // Get milestones for roadmap phases
    const milestones = roadmapPhases.flatMap((phase) => phaseMilestones[phase] || []);

    return {
      phases: roadmapPhases,
      milestones: milestones.slice(0, 6), // Top 6 milestones
    };
  }
}
