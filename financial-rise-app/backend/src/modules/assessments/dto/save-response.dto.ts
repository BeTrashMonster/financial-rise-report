import { IsString, IsNotEmpty, IsOptional, IsInt, IsBoolean, IsUUID } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class SaveResponseDto {
  @ApiProperty({
    description: 'Question ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @IsUUID()
  @IsNotEmpty()
  questionId: string;

  @ApiPropertyOptional({
    description: 'Answer value (text)',
    example: 'Yes',
  })
  @IsString()
  @IsOptional()
  answerValue?: string;

  @ApiPropertyOptional({
    description: 'Answer numeric value (for ratings)',
    example: 8,
  })
  @IsInt()
  @IsOptional()
  answerNumeric?: number;

  @ApiPropertyOptional({
    description: 'Whether the question is not applicable',
    example: false,
  })
  @IsBoolean()
  @IsOptional()
  isNotApplicable?: boolean;

  @ApiPropertyOptional({
    description: 'Consultant private notes for this response',
    example: 'Client seems uncertain about cash flow processes',
  })
  @IsString()
  @IsOptional()
  consultantNotes?: string;
}

export class BulkSaveResponsesDto {
  @ApiProperty({
    description: 'Array of responses to save',
    type: [SaveResponseDto],
  })
  responses: SaveResponseDto[];
}
