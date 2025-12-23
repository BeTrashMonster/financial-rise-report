import {
  IsString,
  IsEmail,
  IsOptional,
  IsEnum,
  IsInt,
  IsBoolean,
  Min,
  Max,
  Length,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { AssessmentStatus } from '../../../../../../database/entities/Assessment';

export class UpdateAssessmentDto {
  @ApiPropertyOptional({
    description: 'Client full name',
    example: 'John Smith',
    minLength: 2,
    maxLength: 100,
  })
  @IsString()
  @IsOptional()
  @Length(2, 100)
  clientName?: string;

  @ApiPropertyOptional({
    description: 'Client business name',
    example: 'Smith Consulting LLC',
    minLength: 2,
    maxLength: 200,
  })
  @IsString()
  @IsOptional()
  @Length(2, 200)
  clientBusinessName?: string;

  @ApiPropertyOptional({
    description: 'Client email address',
    example: 'john.smith@example.com',
  })
  @IsEmail()
  @IsOptional()
  clientEmail?: string;

  @ApiPropertyOptional({
    description: 'Assessment status',
    enum: AssessmentStatus,
    example: AssessmentStatus.IN_PROGRESS,
  })
  @IsEnum(AssessmentStatus)
  @IsOptional()
  status?: AssessmentStatus;

  @ApiPropertyOptional({
    description: 'Entity type (LLC, S-Corp, C-Corp, Sole Proprietor, Partnership)',
    example: 'S-Corp',
    maxLength: 100,
  })
  @IsString()
  @IsOptional()
  @Length(0, 100)
  entityType?: string;

  @ApiPropertyOptional({
    description: 'Whether S-Corp is on payroll (conditional question)',
    example: true,
  })
  @IsBoolean()
  @IsOptional()
  isSCorpOnPayroll?: boolean;

  @ApiPropertyOptional({
    description: 'Confidence level before assessment (1-10)',
    minimum: 1,
    maximum: 10,
    example: 5,
  })
  @IsInt()
  @Min(1)
  @Max(10)
  @IsOptional()
  confidenceBefore?: number;

  @ApiPropertyOptional({
    description: 'Confidence level after assessment (1-10)',
    minimum: 1,
    maximum: 10,
    example: 8,
  })
  @IsInt()
  @Min(1)
  @Max(10)
  @IsOptional()
  confidenceAfter?: number;
}
