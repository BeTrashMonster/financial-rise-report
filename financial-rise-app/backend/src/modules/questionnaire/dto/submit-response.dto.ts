import { IsString, IsUUID, IsNotEmpty, IsOptional, IsBoolean, MaxLength } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SubmitResponseDto {
  @ApiProperty({
    description: 'Assessment ID',
    example: 'a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
  })
  @IsUUID()
  @IsNotEmpty()
  assessmentId: string;

  @ApiProperty({
    description: 'Question ID (question_key)',
    example: 'FIN-001',
  })
  @IsString()
  @IsNotEmpty()
  questionId: string;

  @ApiProperty({
    description: 'Answer value (structure depends on question type)',
    example: { value: 'monthly', text: 'Monthly' },
  })
  @IsNotEmpty()
  answer: Record<string, any>;

  @ApiPropertyOptional({
    description: 'Mark question as not applicable',
    example: false,
  })
  @IsOptional()
  @IsBoolean()
  notApplicable?: boolean;

  @ApiPropertyOptional({
    description: 'Consultant notes',
    example: 'Client uses QuickBooks Online',
    maxLength: 2000,
  })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  consultantNotes?: string;
}
