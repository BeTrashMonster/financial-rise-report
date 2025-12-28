import { IsString, IsEmail, IsNotEmpty, MaxLength, IsOptional } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateAssessmentDto {
  @ApiProperty({
    description: 'Client full name',
    example: 'John Smith',
    maxLength: 100,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  clientName: string;

  @ApiProperty({
    description: 'Business name',
    example: 'Acme Corp',
    maxLength: 100,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  businessName: string;

  @ApiProperty({
    description: 'Client email address',
    example: 'john.smith@example.com',
    maxLength: 255,
  })
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  clientEmail: string;

  @ApiPropertyOptional({
    description: 'Optional notes about the assessment',
    example: 'Initial consultation scheduled for next week',
    maxLength: 5000,
  })
  @IsString()
  @IsOptional()
  @MaxLength(5000)
  notes?: string;
}
