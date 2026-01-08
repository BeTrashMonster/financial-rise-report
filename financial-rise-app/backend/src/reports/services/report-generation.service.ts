import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Storage } from '@google-cloud/storage';
import * as puppeteer from 'puppeteer';
import { Browser, Page, PDFOptions } from 'puppeteer';
import * as fs from 'fs/promises';
import * as path from 'path';
import { Report } from '../entities/report.entity';
import {
  ReportTemplateService,
  ConsultantReportData,
  ClientReportData,
} from './report-template.service';

/**
 * Service for generating PDF reports using Puppeteer and uploading to Google Cloud Storage
 * Ported from Express backend with S3 replaced by GCS
 */
@Injectable()
export class ReportGenerationService {
  private readonly logger = new Logger(ReportGenerationService.name);
  private storage: Storage | null;
  private bucketName: string;

  constructor(
    @InjectRepository(Report)
    private reportRepository: Repository<Report>,
    private reportTemplateService: ReportTemplateService,
    private configService: ConfigService,
  ) {
    // Initialize Google Cloud Storage (optional - falls back to local storage)
    try {
      const keyFilename = this.configService.get<string>('GOOGLE_APPLICATION_CREDENTIALS');
      this.storage = new Storage(keyFilename ? { keyFilename } : undefined);
      this.bucketName = this.configService.get<string>('GCS_BUCKET_NAME') || 'financial-rise-reports';
      this.logger.log(`Initialized GCS with bucket: ${this.bucketName}`);
    } catch (error) {
      this.logger.warn('GCS not configured, using local file storage for PDFs');
      this.storage = null;
      this.bucketName = '';
    }
  }

  /**
   * Generates consultant report PDF asynchronously
   */
  async generateConsultantReport(data: ConsultantReportData, consultantId: string): Promise<Report> {
    this.logger.log(`Generating consultant report for assessment ${data.assessment.id}`);

    // Create report record with generating status
    const report = this.reportRepository.create({
      assessmentId: data.assessment.id,
      consultantId: consultantId,
      reportType: 'consultant',
      status: 'generating',
    });

    const savedReport = await this.reportRepository.save(report);

    // Generate PDF in background (don't await)
    this.generateAndUploadPDF(
      savedReport.id,
      data,
      'consultant',
      this.reportTemplateService.renderConsultantReport(data),
    ).catch((error) => {
      this.logger.error(`Failed to generate consultant report ${savedReport.id}:`, error);
      // Update report with error status
      this.reportRepository.update(savedReport.id, {
        status: 'failed',
        error: error.message,
      });
    });

    return savedReport;
  }

  /**
   * Generates client report PDF asynchronously
   */
  async generateClientReport(data: ClientReportData, consultantId: string, assessmentId: string): Promise<Report> {
    this.logger.log(`Generating client report for ${data.client.name}`);

    // Create report record with generating status
    const report = this.reportRepository.create({
      assessmentId: assessmentId,
      consultantId: consultantId,
      reportType: 'client',
      status: 'generating',
    });

    const savedReport = await this.reportRepository.save(report);

    // Generate PDF in background (don't await)
    this.generateAndUploadPDF(
      savedReport.id,
      data,
      'client',
      this.reportTemplateService.renderClientReport(data),
    ).catch((error) => {
      this.logger.error(`Failed to generate client report ${savedReport.id}:`, error);
      // Update report with error status
      this.reportRepository.update(savedReport.id, {
        status: 'failed',
        error: error.message,
      });
    });

    return savedReport;
  }

  /**
   * Gets report status by ID
   */
  async getReportStatus(reportId: string): Promise<Report | null> {
    return this.reportRepository.findOne({ where: { id: reportId } });
  }

  /**
   * Generates PDF from HTML and uploads to GCS
   * @private
   */
  private async generateAndUploadPDF(
    reportId: string,
    data: ConsultantReportData | ClientReportData,
    reportType: 'consultant' | 'client',
    html: string,
  ): Promise<void> {
    try {
      // Generate PDF
      const pdfBuffer = await this.generatePDF(html);
      this.logger.log(`PDF generated for report ${reportId}, size: ${pdfBuffer.length} bytes`);

      // Upload to GCS
      const assessmentId =
        'assessment' in data ? data.assessment.id : (data as any).assessmentId || 'unknown';
      const fileName = `${reportType}-reports/${assessmentId}/${reportId}.pdf`;
      const fileUrl = await this.uploadToGCS(pdfBuffer, fileName);

      // Update report with success status
      await this.reportRepository.update(reportId, {
        status: 'completed',
        fileUrl,
        fileSizeBytes: pdfBuffer.length,
        generatedAt: new Date(),
        expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours from now
      });

      this.logger.log(`Report ${reportId} completed successfully: ${fileUrl}`);
    } catch (error) {
      this.logger.error(`Error generating/uploading report ${reportId}:`, error);
      throw error;
    }
  }

  /**
   * Generates PDF from HTML using Puppeteer
   * @private
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
      this.logger.error('Puppeteer error:', error);
      throw new Error('Failed to generate PDF: ' + error.message);
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
   * Uploads PDF to Google Cloud Storage and returns signed URL
   * @private
   */
  private async uploadToGCS(pdfBuffer: Buffer, fileName: string): Promise<string> {
    // If GCS is not configured, use local file storage
    if (!this.storage) {
      return this.saveToLocal(pdfBuffer, fileName);
    }

    try {
      const file = this.storage.bucket(this.bucketName).file(fileName);

      // Upload file
      await file.save(pdfBuffer, {
        metadata: {
          contentType: 'application/pdf',
        },
      });

      this.logger.log(`File uploaded to GCS: ${fileName}`);

      // Generate signed URL (valid for 8 hours)
      const [url] = await file.getSignedUrl({
        action: 'read',
        expires: Date.now() + 8 * 60 * 60 * 1000, // 8 hours
      });

      return url;
    } catch (error: any) {
      this.logger.error('GCS upload error:', error);
      throw new Error('Failed to upload PDF to Google Cloud Storage: ' + error.message);
    }
  }

  /**
   * Save PDF to local file system (fallback when GCS not configured)
   * @private
   */
  private async saveToLocal(pdfBuffer: Buffer, fileName: string): Promise<string> {
    try {
      // Create reports directory if it doesn't exist
      const reportsDir = path.join(process.cwd(), 'reports');
      await fs.mkdir(reportsDir, { recursive: true });

      // Create subdirectory for file
      const fileDir = path.join(reportsDir, path.dirname(fileName));
      await fs.mkdir(fileDir, { recursive: true });

      // Save file
      const filePath = path.join(reportsDir, fileName);
      await fs.writeFile(filePath, pdfBuffer);

      this.logger.log(`PDF saved locally: ${filePath}`);

      // Return URL path for serving the file
      const fileUrl = `/api/v1/reports/files/${fileName.replace(/\//g, '--')}`;
      return fileUrl;
    } catch (error: any) {
      this.logger.error('Local file save error:', error);
      throw new Error('Failed to save PDF locally: ' + error.message);
    }
  }

  /**
   * Validates that required assessment data is present
   * @private
   */
  private validateAssessmentData(assessment: any): void {
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
