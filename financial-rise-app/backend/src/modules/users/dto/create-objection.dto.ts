import { IsEnum, IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ObjectionType } from '../entities/user-objection.entity';

export class CreateObjectionDto {
  @IsEnum(ObjectionType, {
    message: 'objection_type must be one of: marketing, analytics, profiling',
  })
  @IsNotEmpty({ message: 'objection_type is required' })
  objection_type: ObjectionType;

  @IsString({ message: 'reason must be a string' })
  @IsNotEmpty({ message: 'reason is required' })
  @MinLength(10, { message: 'reason must be at least 10 characters long' })
  reason: string;
}
