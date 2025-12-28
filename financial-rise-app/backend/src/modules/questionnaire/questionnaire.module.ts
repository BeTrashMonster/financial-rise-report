import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { QuestionnaireController } from './questionnaire.controller';
import { QuestionnaireService } from './questionnaire.service';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { Question } from '../questions/entities/question.entity';
import { AssessmentsModule } from '../assessments/assessments.module';

/**
 * Questionnaire Module - Enhanced with Phase 2.2 services
 *
 * This module handles questionnaire responses with full validation
 * and progress tracking via AssessmentsModule services.
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([AssessmentResponse, Assessment, Question]),
    AssessmentsModule, // Provides ValidationService, ProgressService, AssessmentsService
  ],
  controllers: [QuestionnaireController],
  providers: [QuestionnaireService],
  exports: [QuestionnaireService],
})
export class QuestionnaireModule {}
