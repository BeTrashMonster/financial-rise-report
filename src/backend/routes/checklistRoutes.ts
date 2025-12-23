/**
 * Checklist Routes
 *
 * Defines API routes for checklist operations.
 * All routes require authentication.
 *
 * @module routes/checklistRoutes
 * @version 1.0
 * @date 2025-12-22
 */

import express from 'express';
import { checklistController } from '../controllers/checklistController';
import { authenticate } from '../middleware/auth';
import { validateRequest } from '../middleware/validation';
import { checklistValidation } from '../validators/checklistValidator';

const router = express.Router();

// All routes require authentication
router.use(authenticate);

/**
 * GET /api/v1/assessments/:assessmentId/checklist
 *
 * Retrieve checklist for an assessment
 * Query params: ?phase=Build&completed=true&include_deleted=false
 */
router.get(
  '/assessments/:assessmentId/checklist',
  checklistController.getChecklist
);

/**
 * POST /api/v1/assessments/:assessmentId/checklist
 *
 * Create checklist item or auto-generate from report
 * Body: { auto_generate: true } OR { title, description, phase, priority }
 */
router.post(
  '/assessments/:assessmentId/checklist',
  validateRequest(checklistValidation.create),
  checklistController.createChecklist
);

/**
 * PATCH /api/v1/checklist/:itemId
 *
 * Update a checklist item
 * Body: { title?, description?, priority?, client_notes? }
 */
router.patch(
  '/checklist/:itemId',
  validateRequest(checklistValidation.update),
  checklistController.updateItem
);

/**
 * DELETE /api/v1/checklist/:itemId
 *
 * Soft delete a checklist item (consultant only)
 */
router.delete(
  '/checklist/:itemId',
  checklistController.deleteItem
);

/**
 * POST /api/v1/checklist/:itemId/complete
 *
 * Mark item as complete or incomplete
 * Body: { completed: true/false }
 */
router.post(
  '/checklist/:itemId/complete',
  validateRequest(checklistValidation.toggleComplete),
  checklistController.toggleComplete
);

/**
 * PATCH /api/v1/assessments/:assessmentId/checklist/reorder
 *
 * Reorder checklist items (consultant only)
 * Body: { items: [{ id, sort_order }, ...] }
 */
router.patch(
  '/assessments/:assessmentId/checklist/reorder',
  validateRequest(checklistValidation.reorder),
  checklistController.reorderItems
);

export default router;
