import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AssessmentsController } from './assessments.controller';
import { AssessmentsService } from './assessments.service';
import { Assessment } from '../../../../../database/entities/Assessment'
import { Response } from '../../../../../database/entities/Response'
import { Question } from '../../../../../database/entities/Question'

@Module({
  imports: [TypeOrmModule.forFeature([Assessment, Response, Question])],
  controllers: [AssessmentsController],
  providers: [AssessmentsService],
  exports: [AssessmentsService],
})
export class AssessmentsModule {}
