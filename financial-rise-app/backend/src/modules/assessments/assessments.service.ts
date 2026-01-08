import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, FindOptionsWhere, Like } from 'typeorm';
import { Assessment, AssessmentStatus } from './entities/assessment.entity';
import { AssessmentResponse } from './entities/assessment-response.entity';
import { Question } from '../questions/entities/question.entity';
import { CreateAssessmentDto } from './dto/create-assessment.dto';
import { UpdateAssessmentDto } from './dto/update-assessment.dto';
import { AlgorithmsService } from '../algorithms/algorithms.service';

export interface FindAllFilters {
  page?: number;
  limit?: number;
  status?: AssessmentStatus;
  search?: string;
  sortBy?: string;
  sortOrder?: 'ASC' | 'DESC';
}

@Injectable()
export class AssessmentsService {
  private readonly logger = new Logger(AssessmentsService.name);

  constructor(
    @InjectRepository(Assessment)
    private assessmentRepository: Repository<Assessment>,
    @InjectRepository(AssessmentResponse)
    private responseRepository: Repository<AssessmentResponse>,
    @InjectRepository(Question)
    private questionRepository: Repository<Question>,
    private readonly algorithmsService: AlgorithmsService,
  ) {}

  /**
   * Create a new assessment
   */
  async create(createDto: CreateAssessmentDto, consultantId: string): Promise<Assessment> {
    const assessment = this.assessmentRepository.create({
      client_name: createDto.clientName,
      business_name: createDto.businessName,
      client_email: createDto.clientEmail,
      notes: createDto.notes || null,
      consultant_id: consultantId,
      status: AssessmentStatus.DRAFT,
      progress: 0,
    });

    return this.assessmentRepository.save(assessment);
  }

  /**
   * Find all assessments for a consultant with pagination and filtering
   */
  async findAll(consultantId: string, filters: FindAllFilters = {}) {
    const {
      page = 1,
      limit = 10,
      status,
      search,
      sortBy = 'updated_at',
      sortOrder = 'DESC',
    } = filters;

    // Validate limit
    const maxLimit = Math.min(limit, 100);
    const skip = (page - 1) * maxLimit;

    const queryBuilder = this.assessmentRepository
      .createQueryBuilder('assessment')
      .where('assessment.consultant_id = :consultantId', { consultantId })
      .andWhere('assessment.deleted_at IS NULL');

    // Apply status filter
    if (status) {
      queryBuilder.andWhere('assessment.status = :status', { status });
    }

    // Apply search filter (client name, business name, or email)
    if (search) {
      queryBuilder.andWhere(
        '(assessment.client_name ILIKE :search OR assessment.business_name ILIKE :search OR assessment.client_email ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    // Apply sorting
    queryBuilder.orderBy(`assessment.${sortBy}`, sortOrder);

    // Get total count for pagination
    const total = await queryBuilder.getCount();

    // Apply pagination
    queryBuilder.skip(skip).take(maxLimit);

    // Execute query
    const data = await queryBuilder.getMany();

    return {
      data,
      meta: {
        page,
        limit: maxLimit,
        total,
        totalPages: Math.ceil(total / maxLimit),
      },
    };
  }

  /**
   * Find one assessment by ID
   * Only returns assessment if it belongs to the consultant
   * Loads all relationships (responses, discProfile, phaseResult)
   */
  async findOne(id: string, consultantId: string): Promise<Assessment> {
    const assessment = await this.assessmentRepository.findOne({
      where: { id, consultant_id: consultantId },
      relations: ['responses', 'disc_profiles', 'phase_results'],
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

    // Validate status transitions
    if (updateDto.status) {
      this.validateStatusTransition(assessment.status, updateDto.status);
    }

    // Track status changes
    const oldStatus = assessment.status;
    const newStatus = updateDto.status;

    // Set startedAt when moving to IN_PROGRESS
    if (
      newStatus === AssessmentStatus.IN_PROGRESS &&
      oldStatus === AssessmentStatus.DRAFT &&
      !assessment.started_at
    ) {
      assessment.started_at = new Date();
    }

    // Set completedAt when moving to COMPLETED
    if (newStatus === AssessmentStatus.COMPLETED && !assessment.completed_at) {
      assessment.completed_at = new Date();
    }

    // Map DTO fields to entity fields
    if (updateDto.clientName !== undefined) assessment.client_name = updateDto.clientName;
    if (updateDto.businessName !== undefined) assessment.business_name = updateDto.businessName;
    if (updateDto.clientEmail !== undefined) assessment.client_email = updateDto.clientEmail;
    if (updateDto.notes !== undefined) assessment.notes = updateDto.notes;
    if (updateDto.status !== undefined) assessment.status = updateDto.status;

    return this.assessmentRepository.save(assessment);
  }

  /**
   * Validate status transitions
   */
  private validateStatusTransition(currentStatus: AssessmentStatus, newStatus: AssessmentStatus): void {
    // Cannot move from COMPLETED back to DRAFT
    if (currentStatus === AssessmentStatus.COMPLETED && newStatus === AssessmentStatus.DRAFT) {
      throw new BadRequestException('Cannot revert completed assessment to draft status');
    }
  }

  /**
   * Submit assessment for calculation
   * Marks assessment as complete and triggers DISC/phase calculation
   */
  async submitAssessment(id: string, consultantId: string): Promise<Assessment> {
    // Find assessment
    const assessment = await this.findOne(id, consultantId);

    // Check if already completed
    if (assessment.status === AssessmentStatus.COMPLETED) {
      throw new BadRequestException('Assessment already submitted');
    }

    // Fetch all responses for this assessment
    const responses = await this.responseRepository.find({
      where: { assessment_id: id },
    });

    if (responses.length === 0) {
      throw new BadRequestException('Cannot submit assessment with no responses');
    }

    this.logger.log(`Submitting assessment ${id} with ${responses.length} responses`);

    // Check if results already exist (from previous failed submission attempt)
    const discProfile = await this.algorithmsService.getDISCProfile(id).catch(() => null);
    const phaseResults = await this.algorithmsService.getPhaseResults(id).catch(() => null);
    const resultsExist = discProfile !== null && phaseResults !== null;

    if (resultsExist) {
      // Results already calculated, just update status to completed
      this.logger.log(`Results already exist for assessment ${id}, updating status to completed`);
      assessment.status = AssessmentStatus.COMPLETED;
      assessment.completed_at = new Date();
      return this.assessmentRepository.save(assessment);
    }

    // Results don't exist, calculate them
    try {
      // Transform responses to format expected by AlgorithmsService
      // answer field contains { value: ... } for single/multiple choice, or { values: [...] } for multi-select
      this.logger.log(`Sample responses (first 3): ${JSON.stringify(responses.slice(0, 3).map(r => ({ id: r.question_id, answer: r.answer })))}`);

      const assessmentResponses = responses.map(r => ({
        question_id: r.question_id,
        response_value: r.answer?.value ?? r.answer?.values?.[0] ?? '',
      }));

      this.logger.log(`Transformed responses (first 3): ${JSON.stringify(assessmentResponses.slice(0, 3))}`);

      // Calculate DISC profile and phase results
      const results = await this.algorithmsService.calculateAll(id, assessmentResponses);

      this.logger.log(
        `Calculated results for assessment ${id}: DISC=${results.disc_profile.primary_type}, Phase=${results.phase_results.primary_phase}`,
      );

      // Update status to completed
      assessment.status = AssessmentStatus.COMPLETED;
      assessment.completed_at = new Date();

      return this.assessmentRepository.save(assessment);
    } catch (error) {
      this.logger.error(`Failed to calculate results for assessment ${id}`, error);
      throw new BadRequestException(
        `Failed to calculate assessment results: ${error.message}`,
      );
    }
  }

  /**
   * Soft delete an assessment
   */
  async remove(id: string, consultantId: string): Promise<void> {
    const assessment = await this.findOne(id, consultantId);
    await this.assessmentRepository.softDelete(id);
  }

  /**
   * Calculate and update assessment progress based on answered questions
   */
  async updateProgress(assessmentId: string): Promise<number> {
    // Count total questions
    const totalQuestions = await this.questionRepository.count();

    if (totalQuestions === 0) {
      return 0;
    }

    // Count answered questions
    const answeredQuestions = await this.responseRepository.count({
      where: { assessment_id: assessmentId },
    });

    const progress = Math.round((answeredQuestions / totalQuestions) * 100 * 100) / 100; // Round to 2 decimals

    // Update assessment
    await this.assessmentRepository.update(assessmentId, { progress });

    return progress;
  }
}
