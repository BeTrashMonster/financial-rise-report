import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { QuestionnaireController } from './questionnaire.controller';
import { QuestionnaireService } from './questionnaire.service';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { Question } from '../questions/entities/question.entity';
import { AssessmentsModule } from '../assessments/assessments.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([AssessmentResponse, Assessment, Question]),
    AssessmentsModule,
  ],
  controllers: [QuestionnaireController],
  providers: [QuestionnaireService],
  exports: [QuestionnaireService],
})
export class QuestionnaireModule {}
