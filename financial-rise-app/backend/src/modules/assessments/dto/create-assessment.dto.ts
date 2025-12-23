import { IsString, IsEmail, IsNotEmpty, Length, IsOptional } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateAssessmentDto {
  @ApiProperty({
    description: 'Client full name',
    example: 'John Smith',
    minLength: 2,
    maxLength: 100,
  })
  @IsString()
  @IsNotEmpty()
  @Length(2, 100)
  clientName: string;

  @ApiProperty({
    description: 'Client business name',
    example: 'Smith Consulting LLC',
    minLength: 2,
    maxLength: 200,
  })
  @IsString()
  @IsNotEmpty()
  @Length(2, 200)
  clientBusinessName: string;

  @ApiProperty({
    description: 'Client email address',
    example: 'john.smith@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  clientEmail: string;

  @ApiPropertyOptional({
    description: 'Entity type (LLC, S-Corp, C-Corp, Sole Proprietor, Partnership)',
    example: 'S-Corp',
    maxLength: 100,
  })
  @IsString()
  @IsOptional()
  @Length(0, 100)
  entityType?: string;
}
