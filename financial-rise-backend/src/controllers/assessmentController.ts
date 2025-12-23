import { Response, NextFunction } from 'express';
import { Assessment, AssessmentResponse } from '../models';
import { AuthenticatedRequest, AssessmentStatus } from '../types';
import { AppError } from '../middleware/errorHandler';
import progressService from '../services/progressService';
import validationService from '../services/validationService';
import { ERROR_CODES } from '../constants';
import type { CreateAssessmentInput, UpdateAssessmentInput, ListAssessmentsQuery, UuidParam } from '../validators/assessment.validators';

/**
 * Assessment Controller
 * Implements Work Stream 6: Assessment API endpoints
 */
class AssessmentController {
  /**
   * POST /api/v1/assessments
   * Create a new assessment
   * REQ-ASSESS-001, REQ-ASSESS-002, REQ-ASSESS-003
   */
  async createAssessment(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // Body is already validated by middleware
      const { clientName, businessName, clientEmail, notes } = req.body as CreateAssessmentInput;

      const assessment = await Assessment.create({
        consultantId: req.consultantId!,
        clientName,
        businessName,
        clientEmail,
        notes: notes || null,
        status: AssessmentStatus.DRAFT,
        progress: 0,
      });

      res.status(201).json({
        assessmentId: assessment.id,
        clientName: assessment.clientName,
        businessName: assessment.businessName,
        clientEmail: assessment.clientEmail,
        status: assessment.status,
        progress: assessment.progress,
        createdAt: assessment.createdAt,
        updatedAt: assessment.updatedAt,
        consultantId: assessment.consultantId,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/v1/assessments
   * List all assessments for authenticated consultant
   * REQ-ASSESS-004
   */
  async listAssessments(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // Query is already validated by middleware - safe from SQL injection
      const { status, limit, offset, sortBy, sortOrder } = req.query as ListAssessmentsQuery;

      const where: any = {
        consultantId: req.consultantId!,
        deletedAt: null,
      };

      if (status) {
        where.status = status;
      }

      const order: any = [[sortBy, sortOrder]];

      const { count, rows } = await Assessment.findAndCountAll({
        where,
        limit,
        offset,
        order,
      });

      res.status(200).json({
        assessments: rows.map((a) => ({
          assessmentId: a.id,
          clientName: a.clientName,
          businessName: a.businessName,
          status: a.status,
          progress: a.progress,
          createdAt: a.createdAt,
          updatedAt: a.updatedAt,
          completedAt: a.completedAt,
        })),
        total: count,
        limit,
        offset,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/v1/assessments/:id
   * Get specific assessment with all responses
   * REQ-ASSESS-010
   */
  async getAssessment(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // Params are already validated by middleware
      const { id } = req.params as UuidParam;

      const assessment = await Assessment.findOne({
        where: {
          id,
          consultantId: req.consultantId!,
          deletedAt: null,
        },
        include: [
          {
            model: AssessmentResponse,
            as: 'responses',
          },
        ],
      });

      if (!assessment) {
        throw new AppError('Assessment not found', 404, ERROR_CODES.ASSESSMENT_NOT_FOUND);
      }

      res.status(200).json({
        assessmentId: assessment.id,
        clientName: assessment.clientName,
        businessName: assessment.businessName,
        clientEmail: assessment.clientEmail,
        status: assessment.status,
        progress: assessment.progress,
        createdAt: assessment.createdAt,
        updatedAt: assessment.updatedAt,
        startedAt: assessment.startedAt,
        completedAt: assessment.completedAt,
        responses: (assessment as any).responses.map((r: any) => ({
          questionId: r.questionId,
          answer: r.answer,
          notApplicable: r.notApplicable,
          consultantNotes: r.consultantNotes,
          answeredAt: r.answeredAt,
        })),
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * PATCH /api/v1/assessments/:id
   * Update assessment responses (auto-save)
   * REQ-ASSESS-005, REQ-ASSESS-006, REQ-ASSESS-007, REQ-ASSESS-009
   */
  async updateAssessment(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // Params and body are already validated by middleware
      const { id } = req.params as UuidParam;
      const { responses, status } = req.body as UpdateAssessmentInput;

      // Find assessment
      const assessment = await Assessment.findOne({
        where: {
          id,
          consultantId: req.consultantId!,
          deletedAt: null,
        },
      });

      if (!assessment) {
        throw new AppError('Assessment not found', 404, ERROR_CODES.ASSESSMENT_NOT_FOUND);
      }

      // Cannot modify completed assessments
      if (assessment.status === AssessmentStatus.COMPLETED) {
        throw new AppError('Cannot modify completed assessment', 409, ERROR_CODES.CANNOT_MODIFY_COMPLETED_ASSESSMENT);
      }

      let savedResponses = 0;

      // Save responses if provided
      if (responses && Array.isArray(responses)) {
        for (const response of responses) {
          // Validate response
          const validation = await validationService.validateResponse(
            response.questionId,
            response.answer,
            response.notApplicable || false
          );

          if (!validation.valid) {
            throw new AppError(
              `Invalid response for question ${response.questionId}`,
              400,
              ERROR_CODES.VALIDATION_ERROR,
              validation.errors
            );
          }

          // Upsert response
          await AssessmentResponse.upsert({
            assessmentId: id,
            questionId: response.questionId,
            answer: response.answer,
            notApplicable: response.notApplicable || false,
            consultantNotes: response.consultantNotes || null,
            answeredAt: response.answer !== null || response.notApplicable ? new Date() : null,
          });

          savedResponses++;
        }
      }

      // Update status if transitioning to in_progress for the first time
      if (assessment.status === AssessmentStatus.DRAFT && savedResponses > 0 && !status) {
        assessment.status = AssessmentStatus.IN_PROGRESS;
        assessment.startedAt = new Date();
      }

      // Handle status update
      if (status) {
        if (status === AssessmentStatus.COMPLETED) {
          // Validate completion
          const completionValidation = await validationService.validateCompletion(id);
          if (!completionValidation.valid) {
            throw new AppError(
              'Cannot complete assessment: required questions not answered',
              409,
              ERROR_CODES.INCOMPLETE_ASSESSMENT,
              {
                missingQuestions: completionValidation.missingQuestions,
              }
            );
          }
          assessment.status = AssessmentStatus.COMPLETED;
          assessment.completedAt = new Date();
        } else {
          assessment.status = status;
        }
      }

      // Recalculate progress
      const progressResult = await progressService.calculateProgress(id);
      assessment.progress = progressResult.progress;

      await assessment.save();

      res.status(200).json({
        assessmentId: assessment.id,
        status: assessment.status,
        progress: assessment.progress,
        updatedAt: assessment.updatedAt,
        savedResponses,
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * DELETE /api/v1/assessments/:id
   * Delete a draft assessment (soft delete)
   */
  async deleteAssessment(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
    try {
      // Params are already validated by middleware
      const { id } = req.params as UuidParam;

      const assessment = await Assessment.findOne({
        where: {
          id,
          consultantId: req.consultantId!,
          deletedAt: null,
        },
      });

      if (!assessment) {
        throw new AppError('Assessment not found', 404, ERROR_CODES.ASSESSMENT_NOT_FOUND);
      }

      // Only allow deletion of draft assessments
      if (assessment.status !== AssessmentStatus.DRAFT) {
        throw new AppError('Can only delete draft assessments', 409, ERROR_CODES.CANNOT_DELETE_NON_DRAFT_ASSESSMENT);
      }

      // Soft delete
      assessment.deletedAt = new Date();
      await assessment.save();

      res.status(204).send();
    } catch (error) {
      next(error);
    }
  }
}

export default new AssessmentController();
