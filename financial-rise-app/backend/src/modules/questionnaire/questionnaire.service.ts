import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { Question } from '../questions/entities/question.entity';
import { SubmitResponseDto } from './dto/submit-response.dto';
import { AssessmentsService } from '../assessments/assessments.service';
import { ValidationService } from '../assessments/services/validation.service';
import { ProgressService } from '../assessments/services/progress.service';

/**
 * Questionnaire Service - Enhanced with validation and progress tracking
 *
 * Phase 2.2 Enhancements:
 * - Integrated ValidationService for response validation
 * - Integrated ProgressService for accurate progress calculation
 * - Added proper error handling for invalid responses
 */
@Injectable()
export class QuestionnaireService {
  constructor(
    @InjectRepository(AssessmentResponse)
    private responseRepository: Repository<AssessmentResponse>,
    @InjectRepository(Assessment)
    private assessmentRepository: Repository<Assessment>,
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
    private assessmentsService: AssessmentsService,
    private validationService: ValidationService,
    private progressService: ProgressService,
  ) {}

  /**
   * Submit or update a response to a question
   * ENHANCED: Now validates response before saving
   */
  async submitResponse(dto: SubmitResponseDto, consultantId: string) {
    // Verify assessment exists and belongs to consultant
    const assessment = await this.assessmentsService.findOne(dto.assessmentId, consultantId);

    // Verify question exists
    const question = await this.questionRepository.findOne({
      where: { question_key: dto.questionId },
    });

    if (!question) {
      throw new NotFoundException(`Question with ID ${dto.questionId} not found`);
    }

    // PHASE 2.2: Validate response before saving
    await this.validationService.validateResponseOrThrow(
      dto.questionId,
      dto.answer,
      dto.notApplicable || false,
    );

    // Check if response already exists
    // NOTE: question_id in DB is UUID, but frontend sends question_key
    let response = await this.responseRepository.findOne({
      where: {
        assessment_id: dto.assessmentId,
        question_id: question.id, // Use UUID from fetched question
      },
    });

    if (response) {
      // Update existing response
      response.answer = dto.answer;
      response.not_applicable = dto.notApplicable || false;
      response.consultant_notes = dto.consultantNotes || null;
      response.answered_at = new Date();
    } else {
      // Create new response
      response = this.responseRepository.create({
        assessment_id: dto.assessmentId,
        question_id: question.id, // Use UUID from fetched question
        answer: dto.answer,
        not_applicable: dto.notApplicable || false,
        consultant_notes: dto.consultantNotes || null,
      });
    }

    const savedResponse = await this.responseRepository.save(response);

    // PHASE 2.2: Use ProgressService for accurate progress calculation
    const progressResult = await this.progressService.calculateProgress(dto.assessmentId);

    // Update assessment progress in database
    await this.assessmentRepository.update(dto.assessmentId, {
      progress: progressResult.progress,
    });

    return {
      ...savedResponse,
      progress: progressResult.progress,
      totalQuestions: progressResult.totalQuestions,
      answeredQuestions: progressResult.answeredQuestions,
    };
  }

  /**
   * Update an existing response
   */
  async updateResponse(id: string, dto: Partial<SubmitResponseDto>, consultantId: string) {
    const response = await this.responseRepository.findOne({
      where: { id },
      relations: ['assessment'],
    });

    if (!response) {
      throw new NotFoundException(`Response with ID ${id} not found`);
    }

    // Verify assessment belongs to consultant
    await this.assessmentsService.findOne(response.assessment_id, consultantId);

    // Update fields
    if (dto.answer !== undefined) response.answer = dto.answer;
    if (dto.consultantNotes !== undefined) response.consultant_notes = dto.consultantNotes;
    if (dto.notApplicable !== undefined) response.not_applicable = dto.notApplicable;
    response.answered_at = new Date();

    return this.responseRepository.save(response);
  }
}
