import { Router } from 'express';
import assessmentController from '../controllers/assessmentController';
import { authenticate } from '../middleware/auth';
import {
  validateCreateAssessment,
  validateUpdateAssessment,
  validateUUID,
  validateListQuery,
} from '../middleware/validation';

const router = Router();

/**
 * Assessment API Routes
 * All routes require authentication
 */

// Create new assessment
router.post('/', authenticate, validateCreateAssessment, assessmentController.createAssessment.bind(assessmentController));

// List all assessments for consultant
router.get('/', authenticate, validateListQuery, assessmentController.listAssessments.bind(assessmentController));

// Get specific assessment
router.get('/:id', authenticate, validateUUID, assessmentController.getAssessment.bind(assessmentController));

// Update assessment (auto-save)
router.patch(
  '/:id',
  authenticate,
  validateUUID,
  validateUpdateAssessment,
  assessmentController.updateAssessment.bind(assessmentController)
);

// Delete draft assessment
router.delete('/:id', authenticate, validateUUID, assessmentController.deleteAssessment.bind(assessmentController));

export default router;
