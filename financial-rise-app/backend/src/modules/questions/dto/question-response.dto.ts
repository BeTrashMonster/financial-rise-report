import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { Expose } from 'class-transformer';
import { QuestionType, QuestionSection } from '../entities/question.entity';

export class AnswerOptionDto {
  @ApiProperty({ description: 'Option value' })
  @Expose()
  value: string;

  @ApiProperty({ description: 'Option label' })
  @Expose()
  label: string;
}

export class QuestionResponseDto {
  @ApiProperty({
    description: 'Question ID',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Expose()
  id: string;

  @ApiProperty({
    description: 'Question text',
    example: 'Do you have a bookkeeping system in place?',
  })
  @Expose()
  questionText: string;

  @ApiProperty({
    description: 'Question type',
    enum: QuestionType,
    example: QuestionType.SINGLE_CHOICE,
  })
  @Expose()
  questionType: QuestionType;

  @ApiProperty({
    description: 'Question section/phase',
    enum: QuestionSection,
    example: QuestionSection.STABILIZE,
  })
  @Expose()
  section: QuestionSection;

  @ApiProperty({
    description: 'Order in questionnaire',
    example: 1,
  })
  @Expose()
  orderIndex: number;

  @ApiProperty({
    description: 'Whether question is required',
    example: true,
  })
  @Expose()
  isRequired: boolean;

  @ApiProperty({
    description: 'Whether question is conditional (hidden by default)',
    example: false,
  })
  @Expose()
  isConditional: boolean;

  @ApiPropertyOptional({
    description: 'Parent question ID if conditional',
    example: '123e4567-e89b-12d3-a456-426614174001',
  })
  @Expose()
  conditionalParentId: string | null;

  @ApiPropertyOptional({
    description: 'Trigger value from parent to show this question',
    example: 'S-Corp',
  })
  @Expose()
  conditionalTriggerValue: string | null;

  @ApiPropertyOptional({
    description: 'Answer options for choice questions',
    type: [AnswerOptionDto],
  })
  @Expose()
  answerOptions: AnswerOptionDto[] | null;

  @ApiPropertyOptional({
    description: 'Help text for the question',
    example: 'This helps us understand your current financial management setup',
  })
  @Expose()
  helpText: string | null;

  @ApiProperty({
    description: 'When question was created',
  })
  @Expose()
  createdAt: Date;

  @ApiProperty({
    description: 'When question was last updated',
  })
  @Expose()
  updatedAt: Date;
}

export class QuestionnaireResponseDto {
  @ApiProperty({
    description: 'List of all questions in order',
    type: [QuestionResponseDto],
  })
  questions: QuestionResponseDto[];

  @ApiProperty({
    description: 'Total number of questions',
    example: 50,
  })
  total: number;
}
