import { Response } from 'express';
import { AuthenticatedRequest, FinancialPhase } from '../types';
import { ReportGenerationService } from '../services/ReportGenerationService';
import Assessment from '../models/Assessment';
import AssessmentResponse from '../models/AssessmentResponse';

export class ReportController {
  private reportService: ReportGenerationService;

  constructor() {
    this.reportService = new ReportGenerationService();
  }

  /**
   * POST /api/v1/assessments/:id/reports/consultant
   * Generate consultant report for an assessment
   */
  public generateConsultantReport = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id: assessmentId } = req.params;
      const consultantId = req.consultantId;

      // Find assessment
      const assessment = await Assessment.findOne({
        where: { id: assessmentId, consultantId },
      });

      if (!assessment) {
        res.status(404).json({
          error: {
            code: 'ASSESSMENT_NOT_FOUND',
            message: 'Assessment not found or you do not have access to it',
          },
        });
        return;
      }

      if (assessment.status !== 'completed') {
        res.status(400).json({
          error: {
            code: 'ASSESSMENT_NOT_COMPLETED',
            message: 'Assessment must be completed before generating reports',
          },
        });
        return;
      }

      // Fetch assessment responses
      const responses = await AssessmentResponse.findAll({
        where: { assessmentId },
      });

      // TODO: Fetch DISC profile from DISC calculation service
      // For now, using mock data - this will be replaced with actual service call
      const discProfile = {
        primaryType: 'D' as const,
        scores: { D: 85, I: 45, S: 30, C: 55 },
        secondaryTraits: ['C'],
        confidence: 'high',
      };

      // TODO: Fetch phase results from phase calculation service
      // For now, using mock data - this will be replaced with actual service call
      const phaseResults = {
        primaryPhase: FinancialPhase.ORGANIZE,
        scores: {
          [FinancialPhase.STABILIZE]: 75,
          [FinancialPhase.ORGANIZE]: 45,
          [FinancialPhase.BUILD]: 30,
          [FinancialPhase.GROW]: 20,
          [FinancialPhase.SYSTEMIC]: 40,
        },
        secondaryPhases: [FinancialPhase.STABILIZE],
      };

      // Generate report
      const result = await this.reportService.generateConsultantReport({
        assessment: {
          id: assessment.id,
          consultantId: assessment.consultantId,
          clientName: assessment.clientName,
          businessName: assessment.businessName,
          clientEmail: assessment.clientEmail,
          completedAt: assessment.completedAt!,
        },
        discProfile,
        phaseResults,
        responses: responses.map((r: any) => ({
          questionId: r.questionId,
          questionText: r.questionText || '',
          answer: r.answer,
          phase: r.phase || FinancialPhase.STABILIZE,
          notes: r.consultantNotes,
        })),
        consultantNotes: assessment.notes || '',
      });

      res.status(201).json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      console.error('Error generating consultant report:', error);
      res.status(500).json({
        error: {
          code: 'REPORT_GENERATION_FAILED',
          message: error.message || 'Failed to generate consultant report',
        },
      });
    }
  };

  /**
   * POST /api/v1/assessments/:id/reports/client
   * Generate client report for an assessment
   */
  public generateClientReport = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id: assessmentId } = req.params;
      const consultantId = req.consultantId;

      // Find assessment
      const assessment = await Assessment.findOne({
        where: { id: assessmentId, consultantId },
      });

      if (!assessment) {
        res.status(404).json({
          error: {
            code: 'ASSESSMENT_NOT_FOUND',
            message: 'Assessment not found or you do not have access to it',
          },
        });
        return;
      }

      if (assessment.status !== 'completed') {
        res.status(400).json({
          error: {
            code: 'ASSESSMENT_NOT_COMPLETED',
            message: 'Assessment must be completed before generating reports',
          },
        });
        return;
      }

      // TODO: Fetch DISC profile from DISC calculation service
      const discProfile = {
        primaryType: 'D' as const,
        scores: { D: 85, I: 45, S: 30, C: 55 },
        secondaryTraits: ['C'],
        confidence: 'high',
      };

      // TODO: Fetch phase results from phase calculation service
      const phaseResults = {
        primaryPhase: FinancialPhase.ORGANIZE,
        scores: {
          [FinancialPhase.STABILIZE]: 75,
          [FinancialPhase.ORGANIZE]: 45,
          [FinancialPhase.BUILD]: 30,
          [FinancialPhase.GROW]: 20,
          [FinancialPhase.SYSTEMIC]: 40,
        },
        secondaryPhases: [FinancialPhase.STABILIZE],
      };

      // TODO: Generate quick wins based on phase results and DISC profile
      const quickWins = [
        {
          action: 'Set up monthly financial review meetings',
          why: 'Regular reviews improve financial awareness',
          benefit: 'Better decision-making and early problem detection',
        },
        {
          action: 'Implement expense categorization system',
          why: 'Proper categorization enables accurate reporting',
          benefit: 'Clear visibility into spending patterns',
        },
        {
          action: 'Create cash flow projection template',
          why: 'Forecasting prevents cash shortages',
          benefit: 'Proactive financial management',
        },
      ];

      // TODO: Generate roadmap based on phase results
      const roadmap = {
        phases: [FinancialPhase.ORGANIZE, FinancialPhase.BUILD, FinancialPhase.GROW],
        milestones: [
          'Complete Chart of Accounts restructuring',
          'Implement monthly financial close process',
          'Establish KPI tracking dashboard',
        ],
      };

      // TODO: Fetch consultant branding settings
      const branding = {
        consultantName: 'Financial Experts Inc.',
        logo: null,
        brandColor: '#4B006E',
      };

      // Generate report
      const result = await this.reportService.generateClientReport({
        assessment: {
          id: assessment.id,
          consultantId: assessment.consultantId,
          clientName: assessment.clientName,
          businessName: assessment.businessName,
          clientEmail: assessment.clientEmail,
          completedAt: assessment.completedAt!,
        },
        discProfile,
        phaseResults,
        quickWins,
        roadmap,
        branding,
      });

      res.status(201).json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      console.error('Error generating client report:', error);
      res.status(500).json({
        error: {
          code: 'REPORT_GENERATION_FAILED',
          message: error.message || 'Failed to generate client report',
        },
      });
    }
  };

  /**
   * POST /api/v1/assessments/:id/reports
   * Generate both consultant and client reports
   */
  public generateBothReports = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { id: assessmentId } = req.params;
      const consultantId = req.consultantId;

      // Find assessment
      const assessment = await Assessment.findOne({
        where: { id: assessmentId, consultantId },
      });

      if (!assessment) {
        res.status(404).json({
          error: {
            code: 'ASSESSMENT_NOT_FOUND',
            message: 'Assessment not found or you do not have access to it',
          },
        });
        return;
      }

      if (assessment.status !== 'completed') {
        res.status(400).json({
          error: {
            code: 'ASSESSMENT_NOT_COMPLETED',
            message: 'Assessment must be completed before generating reports',
          },
        });
        return;
      }

      // Fetch assessment responses
      const responses = await AssessmentResponse.findAll({
        where: { assessmentId },
      });

      // TODO: Fetch DISC profile from DISC calculation service
      const discProfile = {
        primaryType: 'D' as const,
        scores: { D: 85, I: 45, S: 30, C: 55 },
        secondaryTraits: ['C'],
        confidence: 'high',
      };

      // TODO: Fetch phase results from phase calculation service
      const phaseResults = {
        primaryPhase: FinancialPhase.ORGANIZE,
        scores: {
          [FinancialPhase.STABILIZE]: 75,
          [FinancialPhase.ORGANIZE]: 45,
          [FinancialPhase.BUILD]: 30,
          [FinancialPhase.GROW]: 20,
          [FinancialPhase.SYSTEMIC]: 40,
        },
        secondaryPhases: [FinancialPhase.STABILIZE],
      };

      // TODO: Generate quick wins and roadmap
      const quickWins = [
        {
          action: 'Set up monthly financial review meetings',
          why: 'Regular reviews improve financial awareness',
          benefit: 'Better decision-making and early problem detection',
        },
        {
          action: 'Implement expense categorization system',
          why: 'Proper categorization enables accurate reporting',
          benefit: 'Clear visibility into spending patterns',
        },
        {
          action: 'Create cash flow projection template',
          why: 'Forecasting prevents cash shortages',
          benefit: 'Proactive financial management',
        },
      ];

      const roadmap = {
        phases: [FinancialPhase.ORGANIZE, FinancialPhase.BUILD, FinancialPhase.GROW],
        milestones: [
          'Complete Chart of Accounts restructuring',
          'Implement monthly financial close process',
          'Establish KPI tracking dashboard',
        ],
      };

      // TODO: Fetch consultant branding settings
      const branding = {
        consultantName: 'Financial Experts Inc.',
        logo: null,
        brandColor: '#4B006E',
      };

      // Generate both reports
      const result = await this.reportService.generateBothReports({
        assessment: {
          id: assessment.id,
          consultantId: assessment.consultantId,
          clientName: assessment.clientName,
          businessName: assessment.businessName,
          clientEmail: assessment.clientEmail,
          completedAt: assessment.completedAt!,
        },
        discProfile,
        phaseResults,
        responses: responses.map((r: any) => ({
          questionId: r.questionId,
          questionText: r.questionText || '',
          answer: r.answer,
          phase: r.phase || FinancialPhase.STABILIZE,
          notes: r.consultantNotes,
        })),
        consultantNotes: assessment.notes || '',
        quickWins,
        roadmap,
        branding,
      });

      res.status(201).json({
        success: true,
        data: result,
      });
    } catch (error: any) {
      console.error('Error generating reports:', error);
      res.status(500).json({
        error: {
          code: 'REPORT_GENERATION_FAILED',
          message: error.message || 'Failed to generate reports',
        },
      });
    }
  };

  /**
   * GET /api/v1/reports/:reportId/download
   * Download a generated report
   */
  public downloadReport = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const { reportId: _reportId } = req.params;

      // TODO: Implement report metadata storage to track generated reports
      // For now, returning a simple message
      res.status(501).json({
        error: {
          code: 'NOT_IMPLEMENTED',
          message: 'Report download functionality will be implemented in a future update',
        },
      });
    } catch (error: any) {
      console.error('Error downloading report:', error);
      res.status(500).json({
        error: {
          code: 'DOWNLOAD_FAILED',
          message: error.message || 'Failed to download report',
        },
      });
    }
  };
}

export default new ReportController();
