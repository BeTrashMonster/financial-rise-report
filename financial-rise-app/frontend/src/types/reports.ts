/**
 * Report Type Definitions
 * Matches backend API response structures for report generation
 */

export type ReportType = 'consultant' | 'client';
export type ReportStatus = 'generating' | 'completed' | 'failed';

export interface GenerateReportRequest {
  assessmentId: string;
}

export interface ReportAccepted {
  reportId: string;
  status: string;
  message: string;
  estimatedCompletionTime: number;
}

export interface ReportStatusResponse {
  reportId: string;
  assessmentId: string;
  reportType: ReportType;
  status: ReportStatus;
  fileUrl: string | null;
  fileSizeBytes: number | null;
  generatedAt: string | null;
  expiresAt: string | null;
  error: string | null;
}

export interface ReportDownloadResponse {
  url: string;
}
