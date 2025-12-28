import { Router } from 'express';
import assessmentController from '../controllers/assessmentController';
import { authenticate } from '../middleware/auth';
import { validateBody, validateQuery, validateParams } from '../middleware/validate';
import {
  createAssessmentSchema,
  updateAssessmentSchema,
  listAssessmentsQuerySchema,
  uuidParamSchema,
} from '../validators/assessment.validators';

const router = Router();

/**
 * Assessment API Routes
 * All routes require authentication
 */

// Create new assessment
router.post(
  '/',
  authenticate,
  validateBody(createAssessmentSchema),
  assessmentController.createAssessment.bind(assessmentController)
);

// List all assessments for consultant
router.get(
  '/',
  authenticate,
  validateQuery(listAssessmentsQuerySchema),
  assessmentController.listAssessments.bind(assessmentController)
);

// Get specific assessment
router.get(
  '/:id',
  authenticate,
  validateParams(uuidParamSchema),
  assessmentController.getAssessment.bind(assessmentController)
);

// Update assessment (auto-save)
router.patch(
  '/:id',
  authenticate,
  validateParams(uuidParamSchema),
  validateBody(updateAssessmentSchema),
  assessmentController.updateAssessment.bind(assessmentController)
);

// Delete draft assessment
router.delete(
  '/:id',
  authenticate,
  validateParams(uuidParamSchema),
  assessmentController.deleteAssessment.bind(assessmentController)
);

export default router;
