import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AssessmentsController } from './assessments.controller';
import { AssessmentsService } from './assessments.service';
import { Assessment } from './entities/assessment.entity';
import { AssessmentResponse } from './entities/assessment-response.entity';
import { Question } from '../questions/entities/question.entity';
import { ProgressService } from './services/progress.service';
import { ValidationService } from './services/validation.service';
import { AlgorithmsModule } from '../algorithms/algorithms.module';

/**
 * Assessments Module - Core assessment management
 *
 * Phase 2.2 Enhancements:
 * - Added ProgressService for accurate progress calculation
 * - Added ValidationService for response validation
 * - Exports all services for use by other modules (especially Questionnaire)
 *
 * Phase 2.3 Enhancements:
 * - Integrated AlgorithmsModule for DISC and phase calculations on submission
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([Assessment, AssessmentResponse, Question]),
    AlgorithmsModule,
  ],
  controllers: [AssessmentsController],
  providers: [AssessmentsService, ProgressService, ValidationService],
  exports: [AssessmentsService, ProgressService, ValidationService],
})
export class AssessmentsModule {}
