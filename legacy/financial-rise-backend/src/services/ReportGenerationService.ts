import puppeteer, { Browser, Page, PDFOptions } from 'puppeteer';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuidv4 } from 'uuid';
import { ReportTemplateService } from './ReportTemplateService';
import { DISCType, FinancialPhase } from '../types';

export interface AssessmentData {
  id: string;
  consultantId: string;
  clientName: string;
  businessName: string;
  clientEmail: string;
  completedAt: Date;
}

export interface DISCProfile {
  primaryType: DISCType;
  scores: {
    D: number;
    I: number;
    S: number;
    C: number;
  };
  secondaryTraits: string[];
  confidence: string;
}

export interface PhaseResults {
  primaryPhase: FinancialPhase;
  scores: {
    [key in FinancialPhase]: number;
  };
  secondaryPhases: FinancialPhase[];
}

export interface AssessmentResponse {
  questionId: string;
  questionText: string;
  answer: string;
  phase: FinancialPhase;
  notes?: string;
}

export interface QuickWin {
  action: string;
  why: string;
  benefit: string;
}

export interface Roadmap {
  phases: FinancialPhase[];
  milestones: string[];
}

export interface Branding {
  consultantName: string;
  logo: string | null;
  brandColor: string;
}

export interface ReportResult {
  reportId: string;
  reportType: 'consultant' | 'client';
  assessmentId: string;
  pdfUrl: string;
  generatedAt: Date;
}

export interface ConsultantReportData {
  assessment: AssessmentData;
  discProfile: DISCProfile;
  phaseResults: PhaseResults;
  responses: AssessmentResponse[];
  consultantNotes: string;
}

export interface ClientReportData {
  assessment: AssessmentData;
  discProfile: DISCProfile;
  phaseResults: PhaseResults;
  quickWins: QuickWin[];
  roadmap: Roadmap;
  branding: Branding;
}

export interface BothReportsData extends ConsultantReportData, ClientReportData {}

export interface BothReportsResult {
  consultantReport: ReportResult;
  clientReport: ReportResult;
}

export class ReportGenerationService {
  private templateService: ReportTemplateService;
  private s3Client: S3Client;
  private bucketName: string;

  constructor(templateService?: ReportTemplateService) {
    this.templateService = templateService || new ReportTemplateService();
    this.s3Client = new S3Client({
      region: process.env.AWS_REGION || 'us-east-1',
      credentials: process.env.AWS_ACCESS_KEY_ID
        ? {
            accessKeyId: process.env.AWS_ACCESS_KEY_ID,
            secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY || '',
          }
        : undefined,
    });
    this.bucketName = process.env.S3_BUCKET_NAME || 'financial-rise-reports';
  }

  /**
   * Generates consultant report PDF
   */
  public async generateConsultantReport(data: ConsultantReportData): Promise<ReportResult> {
    this.validateAssessmentData(data.assessment);

    const reportId = uuidv4();

    try {
      // Render HTML template
      const html = this.templateService.renderConsultantReport({
        client: {
          name: data.assessment.clientName,
          businessName: data.assessment.businessName,
          email: data.assessment.clientEmail,
        },
        assessment: {
          id: data.assessment.id,
          completedAt: data.assessment.completedAt,
        },
        discProfile: data.discProfile,
        phaseResults: data.phaseResults,
        responses: data.responses,
        consultantNotes: data.consultantNotes,
      });

      // Generate PDF
      const pdfBuffer = await this.generatePDF(html);

      // Upload to S3
      const pdfUrl = await this.uploadToS3(
        pdfBuffer,
        `consultant-reports/${data.assessment.id}/${reportId}.pdf`
      );

      return {
        reportId,
        reportType: 'consultant',
        assessmentId: data.assessment.id,
        pdfUrl,
        generatedAt: new Date(),
      };
    } catch (error: any) {
      if (error.message?.includes('Puppeteer')) {
        throw new Error('Failed to generate PDF: ' + error.message);
      }
      if (error.message?.includes('S3')) {
        throw new Error('Failed to upload PDF to S3: ' + error.message);
      }
      throw error;
    }
  }

  /**
   * Generates client report PDF
   */
  public async generateClientReport(data: ClientReportData): Promise<ReportResult> {
    this.validateAssessmentData(data.assessment);

    const reportId = uuidv4();

    try {
      // Render HTML template
      const html = this.templateService.renderClientReport({
        client: {
          name: data.assessment.clientName,
          businessName: data.assessment.businessName,
          email: data.assessment.clientEmail,
        },
        discProfile: data.discProfile,
        phaseResults: data.phaseResults,
        quickWins: data.quickWins,
        roadmap: data.roadmap,
        branding: data.branding,
      });

      // Generate PDF
      const pdfBuffer = await this.generatePDF(html);

      // Upload to S3
      const pdfUrl = await this.uploadToS3(
        pdfBuffer,
        `client-reports/${data.assessment.id}/${reportId}.pdf`
      );

      return {
        reportId,
        reportType: 'client',
        assessmentId: data.assessment.id,
        pdfUrl,
        generatedAt: new Date(),
      };
    } catch (error: any) {
      if (error.message?.includes('Puppeteer')) {
        throw new Error('Failed to generate PDF: ' + error.message);
      }
      if (error.message?.includes('S3')) {
        throw new Error('Failed to upload PDF to S3: ' + error.message);
      }
      throw error;
    }
  }

  /**
   * Generates both consultant and client reports
   */
  public async generateBothReports(data: BothReportsData): Promise<BothReportsResult> {
    const [consultantReport, clientReport] = await Promise.all([
      this.generateConsultantReport({
        assessment: data.assessment,
        discProfile: data.discProfile,
        phaseResults: data.phaseResults,
        responses: data.responses,
        consultantNotes: data.consultantNotes,
      }),
      this.generateClientReport({
        assessment: data.assessment,
        discProfile: data.discProfile,
        phaseResults: data.phaseResults,
        quickWins: data.quickWins,
        roadmap: data.roadmap,
        branding: data.branding,
      }),
    ]);

    return {
      consultantReport,
      clientReport,
    };
  }

  /**
   * Generates PDF from HTML using Puppeteer
   */
  private async generatePDF(html: string): Promise<Buffer> {
    let browser: Browser | null = null;
    let page: Page | null = null;

    try {
      // Launch headless browser
      browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-accelerated-2d-canvas',
          '--no-first-run',
          '--no-zygote',
          '--disable-gpu',
        ],
      });

      page = await browser.newPage();

      // Set content with proper encoding
      await page.setContent(html, {
        waitUntil: 'networkidle0',
      });

      // PDF generation options
      const pdfOptions: PDFOptions = {
        format: 'letter',
        printBackground: true,
        margin: {
          top: '0.5in',
          right: '0.5in',
          bottom: '0.5in',
          left: '0.5in',
        },
        preferCSSPageSize: true,
      };

      // Generate PDF
      const pdfBuffer = await page.pdf(pdfOptions);

      return Buffer.from(pdfBuffer);
    } catch (error: any) {
      throw new Error('Puppeteer error: ' + error.message);
    } finally {
      // Clean up resources
      if (page) {
        await page.close().catch(() => {});
      }
      if (browser) {
        await browser.close().catch(() => {});
      }
    }
  }

  /**
   * Uploads PDF to S3 and returns signed URL
   */
  private async uploadToS3(pdfBuffer: Buffer, key: string): Promise<string> {
    try {
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: key,
        Body: pdfBuffer,
        ContentType: 'application/pdf',
        ServerSideEncryption: 'AES256',
      });

      await this.s3Client.send(command);

      // Generate signed URL (valid for 7 days)
      const signedUrl = await getSignedUrl(
        this.s3Client,
        new PutObjectCommand({
          Bucket: this.bucketName,
          Key: key,
        }),
        { expiresIn: 604800 } // 7 days
      );

      return signedUrl;
    } catch (error: any) {
      throw new Error('S3 error: ' + error.message);
    }
  }

  /**
   * Validates assessment data
   */
  private validateAssessmentData(assessment: AssessmentData): void {
    if (!assessment.id || assessment.id.trim() === '') {
      throw new Error('Invalid assessment data: missing assessment ID');
    }
    if (!assessment.clientName || assessment.clientName.trim() === '') {
      throw new Error('Invalid assessment data: missing client name');
    }
    if (!assessment.businessName || assessment.businessName.trim() === '') {
      throw new Error('Invalid assessment data: missing business name');
    }
    if (!assessment.clientEmail || assessment.clientEmail.trim() === '') {
      throw new Error('Invalid assessment data: missing client email');
    }
    if (!assessment.completedAt) {
      throw new Error('Invalid assessment data: missing completion date');
    }
  }
}
