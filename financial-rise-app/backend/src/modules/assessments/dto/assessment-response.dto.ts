import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Expose, Type } from 'class-transformer';
import { AssessmentStatus } from '../entities/assessment.entity';

export class AssessmentMetaDto {
  @ApiProperty({ example: 1 })
  page: number;

  @ApiProperty({ example: 20 })
  limit: number;

  @ApiProperty({ example: 45 })
  total: number;

  @ApiProperty({ example: 3 })
  totalPages: number;
}

export class AssessmentResponseDto {
  @ApiProperty({
    description: 'Assessment ID',
    example: 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
  })
  @Expose()
  id: string;

  @ApiProperty({
    description: 'Consultant ID',
    example: '550e8400-e29b-41d4-a716-446655440000',
  })
  @Expose()
  consultantId: string;

  @ApiProperty({
    description: 'Client full name',
    example: 'John Smith',
  })
  @Expose()
  clientName: string;

  @ApiProperty({
    description: 'Business name',
    example: 'Acme Corp',
  })
  @Expose()
  businessName: string;

  @ApiProperty({
    description: 'Client email address',
    example: 'john@acmecorp.com',
  })
  @Expose()
  clientEmail: string;

  @ApiProperty({
    description: 'Assessment status',
    enum: AssessmentStatus,
    example: AssessmentStatus.IN_PROGRESS,
  })
  @Expose()
  status: AssessmentStatus;

  @ApiProperty({
    description: 'Progress percentage (0-100)',
    example: 45.5,
  })
  @Expose()
  progress: number;

  @ApiProperty({
    description: 'When assessment was created',
    example: '2025-12-20T08:00:00Z',
  })
  @Expose()
  createdAt: Date;

  @ApiProperty({
    description: 'When assessment was last updated',
    example: '2025-12-26T14:30:00Z',
  })
  @Expose()
  updatedAt: Date;

  @ApiPropertyOptional({
    description: 'When assessment was started',
    example: '2025-12-20T09:15:00Z',
  })
  @Expose()
  startedAt: Date | null;

  @ApiPropertyOptional({
    description: 'When assessment was completed',
    example: null,
  })
  @Expose()
  completedAt: Date | null;

  @ApiPropertyOptional({
    description: 'Optional notes about the assessment',
    example: 'Follow up on payroll questions',
  })
  @Expose()
  notes: string | null;
}

export class PaginatedAssessmentsResponseDto {
  @ApiProperty({
    description: 'Array of assessments',
    type: [AssessmentResponseDto],
  })
  data: AssessmentResponseDto[];

  @ApiProperty({
    description: 'Pagination metadata',
    type: AssessmentMetaDto,
  })
  meta: AssessmentMetaDto;
}
