import {
  IsString,
  IsEmail,
  IsOptional,
  IsEnum,
  MaxLength,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';
import { AssessmentStatus } from '../entities/assessment.entity';

export class UpdateAssessmentDto {
  @ApiPropertyOptional({
    description: 'Client full name',
    example: 'John Smith',
    maxLength: 100,
  })
  @IsString()
  @IsOptional()
  @MaxLength(100)
  clientName?: string;

  @ApiPropertyOptional({
    description: 'Business name',
    example: 'Acme Corp',
    maxLength: 100,
  })
  @IsString()
  @IsOptional()
  @MaxLength(100)
  businessName?: string;

  @ApiPropertyOptional({
    description: 'Client email address',
    example: 'john.smith@example.com',
    maxLength: 255,
  })
  @IsEmail()
  @IsOptional()
  @MaxLength(255)
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
    description: 'Optional notes about the assessment',
    example: 'Updated notes after consultation',
    maxLength: 5000,
  })
  @IsString()
  @IsOptional()
  @MaxLength(5000)
  notes?: string;
}
