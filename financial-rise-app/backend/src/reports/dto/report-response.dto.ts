import { ApiProperty } from '@nestjs/swagger';

export class ReportResponseDto {
  @ApiProperty({ example: 'rep1rep2-rep3-rep4-rep5-rep6rep7rep8' })
  reportId: string;

  @ApiProperty({ example: 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d' })
  assessmentId: string;

  @ApiProperty({ example: 'consultant', enum: ['consultant', 'client'] })
  reportType: string;

  @ApiProperty({ example: 'generating', enum: ['generating', 'completed', 'failed'] })
  status: string;

  @ApiProperty({ example: 'https://storage.googleapis.com/...', nullable: true })
  fileUrl: string | null;

  @ApiProperty({ example: 245678, nullable: true })
  fileSizeBytes: number | null;

  @ApiProperty({ example: '2025-12-27T10:52:00Z', nullable: true })
  generatedAt: string | null;

  @ApiProperty({ example: '2025-12-27T18:52:00Z', nullable: true })
  expiresAt: string | null;

  @ApiProperty({ example: null, nullable: true })
  error: string | null;
}

export class ReportAcceptedDto {
  @ApiProperty({ example: 'rep1rep2-rep3-rep4-rep5-rep6rep7rep8' })
  reportId: string;

  @ApiProperty({ example: 'generating' })
  status: string;

  @ApiProperty({ example: 'Report generation started. Poll /reports/status/{reportId} for updates.' })
  message: string;

  @ApiProperty({ example: 5 })
  estimatedCompletionTime: number;
}
