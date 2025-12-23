import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Assessment, AssessmentStatus } from '../../../../../database/entities/Assessment'
import { Response } from '../../../../../database/entities/Response'
import { Question } from '../../../../../database/entities/Question'
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { SaveResponseDto } from './dto/save-response.dto';

@Injectable()
export class AssessmentsService {
  constructor(
    @InjectRepository(Assessment)
    private assessmentRepository: Repository<Assessment>,
    @InjectRepository(Response)
    private responseRepository: Repository<Response>,
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
  ) {}

  /**
   * Create a new assessment
   */
  async create(createDto: CreateAssessmentDto, consultantId: string): Promise<Assessment> {
    const assessment = this.assessmentRepository.create({
      ...createDto,
      consultantId,
      status: AssessmentStatus.DRAFT,
      progressPercentage: 0,
    });

    return this.assessmentRepository.save(assessment);
  }

  /**
   * Find all assessments for a consultant
   * @param consultantId - The consultant's user ID
   * @param includeArchived - Whether to include archived assessments (false = exclude, true = only archived)
   */
  async findAll(consultantId: string, includeArchived: boolean = false): Promise<Assessment[]> {
    const queryBuilder = this.assessmentRepository
      .createQueryBuilder('assessment')
      .where('assessment.consultantId = :consultantId', { consultantId })
      .andWhere('assessment.deletedAt IS NULL');

    if (includeArchived) {
      queryBuilder.andWhere('assessment.archivedAt IS NOT NULL');
    } else {
      queryBuilder.andWhere('assessment.archivedAt IS NULL');
    }

    return queryBuilder.orderBy('assessment.updatedAt', 'DESC').getMany();
  }

  /**
   * Find one assessment by ID
   * Only returns assessment if it belongs to the consultant
   */
  async findOne(id: string, consultantId: string): Promise<Assessment> {
    const assessment = await this.assessmentRepository.findOne({
      where: { id, consultantId },
      relations: ['responses'],
    });

    if (!assessment) {
      throw new NotFoundException(`Assessment with ID ${id} not found`);
    }

    return assessment;
  }

  /**
   * Update an assessment
   */
  async update(
    id: string,
    updateDto: UpdateAssessmentDto,
    consultantId: string,
  ): Promise<Assessment> {
    const assessment = await this.findOne(id, consultantId);

    // Track status changes
    const oldStatus = assessment.status;
    const newStatus = updateDto.status;

    // Set startedAt when moving to IN_PROGRESS
    if (
      newStatus === AssessmentStatus.IN_PROGRESS &&
      oldStatus === AssessmentStatus.DRAFT &&
      !assessment.startedAt
    ) {
      assessment.startedAt = new Date();
    }

    // Set completedAt when moving to COMPLETED
    if (newStatus === AssessmentStatus.COMPLETED && !assessment.completedAt) {
      assessment.completedAt = new Date();
    }

    // Update fields
    Object.assign(assessment, updateDto);

    return this.assessmentRepository.save(assessment);
  }

  /**
   * Soft delete an assessment (only DRAFT assessments can be deleted)
   */
  async remove(id: string, consultantId: string): Promise<void> {
    const assessment = await this.findOne(id, consultantId);

    // Only allow deletion of DRAFT assessments
    if (assessment.status !== AssessmentStatus.DRAFT) {
      throw new BadRequestException(
        'Only draft assessments can be deleted. Completed assessments should be archived instead.',
      );
    }

    await this.assessmentRepository.softDelete(id);
  }

  /**
   * Archive an assessment
   */
  async archive(id: string, consultantId: string): Promise<Assessment> {
    const assessment = await this.findOne(id, consultantId);

    assessment.archivedAt = new Date();
    return this.assessmentRepository.save(assessment);
  }

  /**
   * Restore an archived assessment
   */
  async restore(id: string, consultantId: string): Promise<Assessment> {
    const assessment = await this.findOne(id, consultantId);

    assessment.archivedAt = null;
    return this.assessmentRepository.save(assessment);
  }

  /**
   * Save or update a response to a question
   * Auto-save functionality - creates or updates response
   */
  async saveResponse(
    assessmentId: string,
    saveDto: SaveResponseDto,
    consultantId: string,
  ): Promise<Response> {
    // Verify assessment exists and belongs to consultant
    const assessment = await this.findOne(assessmentId, consultantId);

    // Verify question exists
    const question = await this.questionRepository.findOne({
      where: { id: saveDto.questionId },
    });

    if (!question) {
      throw new NotFoundException(`Question with ID ${saveDto.questionId} not found`);
    }

    // Check if response already exists
    let response = await this.responseRepository.findOne({
      where: {
        assessmentId,
        questionId: saveDto.questionId,
      },
    });

    if (response) {
      // Update existing response
      Object.assign(response, saveDto);
    } else {
      // Create new response
      response = this.responseRepository.create({
        assessmentId,
        ...saveDto,
      });
    }

    const savedResponse = await this.responseRepository.save(response);

    // Update progress percentage
    await this.updateProgress(assessmentId);

    return savedResponse;
  }

  /**
   * Update assessment progress based on answered questions
   */
  private async updateProgress(assessmentId: string): Promise<void> {
    const progressPercentage = await this.calculateProgress(assessmentId);

    await this.assessmentRepository.save({
      id: assessmentId,
      progressPercentage,
    });
  }

  /**
   * Calculate progress percentage
   * Returns percentage (0-100) of questions answered
   */
  private async calculateProgress(assessmentId: string): Promise<number> {
    // Count total questions (excluding conditional questions that aren't triggered)
    // For MVP, we'll count all questions - conditional logic will be Phase 3
    const totalQuestions = await this.questionRepository.count({
      where: { deletedAt: null as any },
    });

    if (totalQuestions === 0) {
      return 0;
    }

    // Count answered questions (responses that have a value or are marked N/A)
    const answeredQuestions = await this.responseRepository.count({
      where: { assessmentId },
    });

    return Math.round((answeredQuestions / totalQuestions) * 100);
  }

  /**
   * Get all responses for an assessment
   */
  async getResponses(assessmentId: string, consultantId: string): Promise<Response[]> {
    // Verify assessment exists and belongs to consultant
    await this.findOne(assessmentId, consultantId);

    return this.responseRepository.find({
      where: { assessmentId },
      relations: ['question'],
      order: { createdAt: 'ASC' },
    });
  }
}
