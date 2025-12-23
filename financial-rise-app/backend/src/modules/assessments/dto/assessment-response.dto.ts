import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Expose, Type } from 'class-transformer';
import { AssessmentStatus } from '../../../../../../database/entities/Assessment';

export class ResponseItemDto {
  @ApiProperty()
  @Expose()
  id: string;

  @ApiProperty()
  @Expose()
  questionId: string;

  @ApiPropertyOptional()
  @Expose()
  answerValue: string | null;

  @ApiPropertyOptional()
  @Expose()
  answerNumeric: number | null;

  @ApiProperty()
  @Expose()
  isNotApplicable: boolean;

  @ApiPropertyOptional()
  @Expose()
  consultantNotes: string | null;

  @ApiProperty()
  @Expose()
  createdAt: Date;

  @ApiProperty()
  @Expose()
  updatedAt: Date;
}

export class AssessmentResponseDto {
  @ApiProperty({
    description: 'Assessment ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Expose()
  id: string;

  @ApiProperty({
    description: 'Consultant ID',
    example: '123e4567-e89b-12d3-a456-426614174001',
  })
  @Expose()
  consultantId: string;

  @ApiProperty({
    description: 'Client name',
    example: 'John Smith',
  })
  @Expose()
  clientName: string;

  @ApiProperty({
    description: 'Client business name',
    example: 'Smith Consulting LLC',
  })
  @Expose()
  clientBusinessName: string;

  @ApiProperty({
    description: 'Client email',
    example: 'john.smith@example.com',
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

  @ApiPropertyOptional({
    description: 'Entity type',
    example: 'S-Corp',
  })
  @Expose()
  entityType: string | null;

  @ApiPropertyOptional({
    description: 'Is S-Corp on payroll',
    example: true,
  })
  @Expose()
  isSCorpOnPayroll: boolean | null;

  @ApiPropertyOptional({
    description: 'Confidence before assessment (1-10)',
    example: 5,
  })
  @Expose()
  confidenceBefore: number | null;

  @ApiPropertyOptional({
    description: 'Confidence after assessment (1-10)',
    example: 8,
  })
  @Expose()
  confidenceAfter: number | null;

  @ApiProperty({
    description: 'Progress percentage (0-100)',
    example: 45.5,
  })
  @Expose()
  progressPercentage: number;

  @ApiPropertyOptional({
    description: 'When assessment was started',
  })
  @Expose()
  startedAt: Date | null;

  @ApiPropertyOptional({
    description: 'When assessment was completed',
  })
  @Expose()
  completedAt: Date | null;

  @ApiProperty({
    description: 'When assessment was created',
  })
  @Expose()
  createdAt: Date;

  @ApiProperty({
    description: 'When assessment was last updated',
  })
  @Expose()
  updatedAt: Date;

  @ApiPropertyOptional({
    description: 'When assessment was archived',
  })
  @Expose()
  archivedAt: Date | null;

  @ApiPropertyOptional({
    description: 'Assessment responses',
    type: [ResponseItemDto],
  })
  @Expose()
  @Type(() => ResponseItemDto)
  responses?: ResponseItemDto[];
}

export class AssessmentListResponseDto {
  @ApiProperty({
    description: 'List of assessments',
    type: [AssessmentResponseDto],
  })
  assessments: AssessmentResponseDto[];

  @ApiProperty({
    description: 'Total count',
    example: 42,
  })
  total: number;
}
