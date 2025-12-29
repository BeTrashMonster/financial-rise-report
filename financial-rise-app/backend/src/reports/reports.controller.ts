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
  Logger,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../modules/auth/guards/jwt-auth.guard';
import { ReportOwnershipGuard } from '../common/guards/report-ownership.guard';
import { GetUser } from '../modules/auth/decorators/get-user.decorator';
import { ReportGenerationService } from './services/report-generation.service';
import { GenerateReportDto } from './dto/generate-report.dto';
import { ReportResponseDto, ReportAcceptedDto } from './dto/report-response.dto';

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

  constructor(private readonly reportGenerationService: ReportGenerationService) {}

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

    // TODO: Fetch assessment data from database
    // For now, this is a placeholder structure
    const consultantData = {
      client: {
        name: 'Client Name',
        businessName: 'Business Name',
        email: 'client@example.com',
      },
      assessment: {
        id: dto.assessmentId,
        completedAt: new Date(),
      },
      discProfile: {
        primaryType: 'C' as const,
        scores: { D: 65, I: 70, S: 55, C: 85 },
        secondaryTraits: ['D'],
        confidence: 'high',
      },
      phaseResults: {
        primaryPhase: 'organize' as any,
        scores: {
          stabilize: 65,
          organize: 75,
          build: 45,
          grow: 30,
          systemic: 50,
        } as any,
        secondaryPhases: ['stabilize' as any],
      },
      responses: [],
      consultantNotes: 'Initial assessment complete',
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

    // TODO: Fetch assessment data and generate quick wins/roadmap
    const clientData = {
      client: {
        name: 'Client Name',
        businessName: 'Business Name',
        email: 'client@example.com',
      },
      discProfile: {
        primaryType: 'C' as const,
        scores: { D: 65, I: 70, S: 55, C: 85 },
        secondaryTraits: ['D'],
        confidence: 'high',
      },
      phaseResults: {
        primaryPhase: 'organize' as any,
        scores: {
          stabilize: 65,
          organize: 75,
          build: 45,
          grow: 30,
          systemic: 50,
        } as any,
        secondaryPhases: ['stabilize' as any],
      },
      quickWins: [
        {
          action: 'Set up automated bank reconciliation',
          why: 'Reduces manual errors and saves time',
          benefit: 'Save 2-3 hours per week',
        },
      ],
      roadmap: {
        phases: ['organize' as any, 'build' as any],
        milestones: ['Complete chart of accounts setup', 'Integrate accounting software'],
      },
      branding: {
        consultantName: 'Your Financial Consultant',
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
}
