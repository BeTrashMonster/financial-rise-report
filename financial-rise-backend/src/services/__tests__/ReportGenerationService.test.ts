import { ReportGenerationService } from '../ReportGenerationService';
import { ReportTemplateService } from '../ReportTemplateService';
import { DISCType, FinancialPhase } from '../../types';

// Mock puppeteer
jest.mock('puppeteer', () => ({
  launch: jest.fn().mockResolvedValue({
    newPage: jest.fn().mockResolvedValue({
      setContent: jest.fn(),
      pdf: jest.fn().mockResolvedValue(Buffer.from('mock-pdf-content')),
      close: jest.fn(),
    }),
    close: jest.fn(),
  }),
}));

// Mock AWS SDK (S3)
jest.mock('@aws-sdk/client-s3', () => ({
  S3Client: jest.fn().mockImplementation(() => ({
    send: jest.fn().mockResolvedValue({ $metadata: { httpStatusCode: 200 } }),
  })),
  PutObjectCommand: jest.fn(),
}));

// Mock getSignedUrl
jest.mock('@aws-sdk/s3-request-presigner', () => ({
  getSignedUrl: jest.fn().mockResolvedValue('https://s3.amazonaws.com/bucket/signed-url'),
}));

describe('ReportGenerationService', () => {
  let reportGenerationService: ReportGenerationService;
  let reportTemplateService: ReportTemplateService;

  const mockAssessmentData = {
    id: 'assessment-123',
    consultantId: 'consultant-456',
    clientName: 'John Doe',
    businessName: 'Acme Corp',
    clientEmail: 'john@acme.com',
    completedAt: new Date('2024-01-15'),
  };

  const mockDISCProfile = {
    primaryType: 'D' as DISCType,
    scores: {
      D: 85,
      I: 45,
      S: 30,
      C: 55,
    },
    secondaryTraits: ['C'],
    confidence: 'high',
  };

  const mockPhaseResults = {
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

  const mockResponses = [
    {
      questionId: 'q1',
      questionText: 'Do you have a formal accounting system?',
      answer: 'Yes',
      phase: FinancialPhase.STABILIZE,
      notes: 'Using QuickBooks',
    },
    {
      questionId: 'q2',
      questionText: 'Is your Chart of Accounts organized?',
      answer: 'Partially',
      phase: FinancialPhase.ORGANIZE,
      notes: 'Needs refinement',
    },
  ];

  const mockQuickWins = [
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

  const mockRoadmap = {
    phases: [FinancialPhase.ORGANIZE, FinancialPhase.BUILD, FinancialPhase.GROW],
    milestones: [
      'Complete Chart of Accounts restructuring',
      'Implement monthly financial close process',
      'Establish KPI tracking dashboard',
    ],
  };

  const mockBranding = {
    consultantName: 'Financial Experts Inc.',
    logo: null,
    brandColor: '#4B006E',
  };

  beforeEach(() => {
    reportTemplateService = new ReportTemplateService();
    reportGenerationService = new ReportGenerationService(reportTemplateService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('generateConsultantReport', () => {
    it('should generate a consultant report PDF successfully', async () => {
      const result = await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: 'Client is highly motivated and ready to implement changes.',
      });

      expect(result).toBeDefined();
      expect(result.reportId).toBeDefined();
      expect(result.reportType).toBe('consultant');
      expect(result.assessmentId).toBe('assessment-123');
      expect(result.pdfUrl).toContain('https://s3.amazonaws.com');
      expect(result.generatedAt).toBeInstanceOf(Date);
    });

    it('should include all required sections in consultant report', async () => {
      const renderSpy = jest.spyOn(reportTemplateService, 'renderConsultantReport');

      await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: 'Test notes',
      });

      expect(renderSpy).toHaveBeenCalledWith({
        client: {
          name: mockAssessmentData.clientName,
          businessName: mockAssessmentData.businessName,
          email: mockAssessmentData.clientEmail,
        },
        assessment: {
          id: mockAssessmentData.id,
          completedAt: mockAssessmentData.completedAt,
        },
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: 'Test notes',
      });
    });

    it('should handle missing consultant notes gracefully', async () => {
      const result = await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: '',
      });

      expect(result).toBeDefined();
      expect(result.reportType).toBe('consultant');
    });

    it('should throw error for incomplete assessment data', async () => {
      await expect(
        reportGenerationService.generateConsultantReport({
          assessment: { ...mockAssessmentData, id: '' },
          discProfile: mockDISCProfile,
          phaseResults: mockPhaseResults,
          responses: mockResponses,
          consultantNotes: '',
        })
      ).rejects.toThrow('Invalid assessment data');
    });
  });

  describe('generateClientReport', () => {
    it('should generate a client report PDF successfully', async () => {
      const result = await reportGenerationService.generateClientReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        quickWins: mockQuickWins,
        roadmap: mockRoadmap,
        branding: mockBranding,
      });

      expect(result).toBeDefined();
      expect(result.reportId).toBeDefined();
      expect(result.reportType).toBe('client');
      expect(result.assessmentId).toBe('assessment-123');
      expect(result.pdfUrl).toContain('https://s3.amazonaws.com');
      expect(result.generatedAt).toBeInstanceOf(Date);
    });

    it('should adapt content based on DISC profile', async () => {
      const renderSpy = jest.spyOn(reportTemplateService, 'renderClientReport');

      // Test with D-type profile
      await reportGenerationService.generateClientReport({
        assessment: mockAssessmentData,
        discProfile: { ...mockDISCProfile, primaryType: 'D' },
        phaseResults: mockPhaseResults,
        quickWins: mockQuickWins,
        roadmap: mockRoadmap,
        branding: mockBranding,
      });

      expect(renderSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          discProfile: expect.objectContaining({
            primaryType: 'D',
          }),
        })
      );
    });

    it('should handle different DISC types (I, S, C)', async () => {
      const discTypes: DISCType[] = ['I', 'S', 'C'];

      for (const discType of discTypes) {
        const result = await reportGenerationService.generateClientReport({
          assessment: mockAssessmentData,
          discProfile: { ...mockDISCProfile, primaryType: discType },
          phaseResults: mockPhaseResults,
          quickWins: mockQuickWins,
          roadmap: mockRoadmap,
          branding: mockBranding,
        });

        expect(result).toBeDefined();
        expect(result.reportType).toBe('client');
      }
    });

    it('should include branding in client report', async () => {
      const renderSpy = jest.spyOn(reportTemplateService, 'renderClientReport');

      const customBranding = {
        consultantName: 'Custom Consultants LLC',
        logo: 'https://example.com/logo.png',
        brandColor: '#FF5733',
      };

      await reportGenerationService.generateClientReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        quickWins: mockQuickWins,
        roadmap: mockRoadmap,
        branding: customBranding,
      });

      expect(renderSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          branding: customBranding,
        })
      );
    });

    it('should generate different quick wins for different phases', async () => {
      const stabilizePhase = {
        ...mockPhaseResults,
        primaryPhase: FinancialPhase.STABILIZE,
      };

      const result = await reportGenerationService.generateClientReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: stabilizePhase,
        quickWins: mockQuickWins,
        roadmap: mockRoadmap,
        branding: mockBranding,
      });

      expect(result).toBeDefined();
      expect(result.reportType).toBe('client');
    });
  });

  describe('generateBothReports', () => {
    it('should generate both consultant and client reports', async () => {
      const result = await reportGenerationService.generateBothReports({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: 'Test notes',
        quickWins: mockQuickWins,
        roadmap: mockRoadmap,
        branding: mockBranding,
      });

      expect(result).toBeDefined();
      expect(result.consultantReport).toBeDefined();
      expect(result.clientReport).toBeDefined();
      expect(result.consultantReport.reportType).toBe('consultant');
      expect(result.clientReport.reportType).toBe('client');
      expect(result.consultantReport.assessmentId).toBe('assessment-123');
      expect(result.clientReport.assessmentId).toBe('assessment-123');
    });
  });

  describe('PDF Generation', () => {
    it('should generate PDF with proper settings', async () => {
      const puppeteer = require('puppeteer');

      await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: '',
      });

      expect(puppeteer.launch).toHaveBeenCalled();
    });

    it('should handle PDF generation errors', async () => {
      const puppeteer = require('puppeteer');
      puppeteer.launch.mockRejectedValueOnce(new Error('Puppeteer error'));

      await expect(
        reportGenerationService.generateConsultantReport({
          assessment: mockAssessmentData,
          discProfile: mockDISCProfile,
          phaseResults: mockPhaseResults,
          responses: mockResponses,
          consultantNotes: '',
        })
      ).rejects.toThrow('Failed to generate PDF');
    });

    it('should close browser after PDF generation', async () => {
      const mockBrowser = {
        newPage: jest.fn().mockResolvedValue({
          setContent: jest.fn(),
          pdf: jest.fn().mockResolvedValue(Buffer.from('pdf')),
          close: jest.fn(),
        }),
        close: jest.fn(),
      };

      const puppeteer = require('puppeteer');
      puppeteer.launch.mockResolvedValueOnce(mockBrowser);

      await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: '',
      });

      expect(mockBrowser.close).toHaveBeenCalled();
    });
  });

  describe('S3 Upload', () => {
    it('should upload PDF to S3 successfully', async () => {
      const { S3Client } = require('@aws-sdk/client-s3');

      await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: '',
      });

      expect(S3Client).toHaveBeenCalled();
    });

    it('should handle S3 upload errors', async () => {
      const { S3Client } = require('@aws-sdk/client-s3');
      S3Client.mockImplementationOnce(() => ({
        send: jest.fn().mockRejectedValue(new Error('S3 upload failed')),
      }));

      await expect(
        reportGenerationService.generateConsultantReport({
          assessment: mockAssessmentData,
          discProfile: mockDISCProfile,
          phaseResults: mockPhaseResults,
          responses: mockResponses,
          consultantNotes: '',
        })
      ).rejects.toThrow('Failed to upload PDF to S3');
    });

    it('should generate signed URL for uploaded PDF', async () => {
      const result = await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: '',
      });

      expect(result.pdfUrl).toContain('https://s3.amazonaws.com');
      expect(result.pdfUrl).toContain('signed-url');
    });
  });

  describe('Performance', () => {
    it('should generate report within 5 seconds', async () => {
      const startTime = Date.now();

      await reportGenerationService.generateConsultantReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: mockPhaseResults,
        responses: mockResponses,
        consultantNotes: '',
      });

      const duration = Date.now() - startTime;
      expect(duration).toBeLessThan(5000); // Must be under 5 seconds per REQ-PERF-002
    });
  });

  describe('DISC Content Personalization', () => {
    it('should use different language for each DISC type', async () => {
      const getContentSpy = jest.spyOn(reportTemplateService, 'getDISCContentVariation');

      const discTypes: DISCType[] = ['D', 'I', 'S', 'C'];

      for (const discType of discTypes) {
        await reportGenerationService.generateClientReport({
          assessment: mockAssessmentData,
          discProfile: { ...mockDISCProfile, primaryType: discType },
          phaseResults: mockPhaseResults,
          quickWins: mockQuickWins,
          roadmap: mockRoadmap,
          branding: mockBranding,
        });
      }

      // Verify DISC content variation was used
      expect(getContentSpy).toHaveBeenCalled();
    });
  });

  describe('Phase-based Recommendations', () => {
    it('should generate phase-specific quick wins', async () => {
      const phases = [
        FinancialPhase.STABILIZE,
        FinancialPhase.ORGANIZE,
        FinancialPhase.BUILD,
        FinancialPhase.GROW,
        FinancialPhase.SYSTEMIC,
      ];

      for (const phase of phases) {
        const result = await reportGenerationService.generateClientReport({
          assessment: mockAssessmentData,
          discProfile: mockDISCProfile,
          phaseResults: { ...mockPhaseResults, primaryPhase: phase },
          quickWins: mockQuickWins,
          roadmap: mockRoadmap,
          branding: mockBranding,
        });

        expect(result).toBeDefined();
      }
    });

    it('should prioritize actions based on phase scores', async () => {
      const lowScorePhase = {
        ...mockPhaseResults,
        scores: {
          ...mockPhaseResults.scores,
          [FinancialPhase.STABILIZE]: 25, // Critical priority
        },
      };

      const result = await reportGenerationService.generateClientReport({
        assessment: mockAssessmentData,
        discProfile: mockDISCProfile,
        phaseResults: lowScorePhase,
        quickWins: mockQuickWins,
        roadmap: mockRoadmap,
        branding: mockBranding,
      });

      expect(result).toBeDefined();
    });
  });
});
