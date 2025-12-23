/**
 * Checklist Controller
 *
 * Handles HTTP requests for checklist operations.
 * Validates input, calls service layer, and formats responses.
 *
 * @module controllers/checklistController
 * @version 1.0
 * @date 2025-12-22
 */

import { Request, Response } from 'express';
import { ChecklistService } from '../services/checklistService';
import { asyncHandler } from '../middleware/asyncHandler';
import { validateChecklistPermission } from '../middleware/permissions';

const checklistService = new ChecklistService();

/**
 * GET /api/v1/assessments/:assessmentId/checklist
 *
 * Retrieve all checklist items for an assessment
 */
export const getChecklist = asyncHandler(async (req: Request, res: Response) => {
  const { assessmentId } = req.params;
  const { phase, completed, include_deleted } = req.query;

  // Verify user has permission to view this assessment's checklist
  await validateChecklistPermission(req.user.id, assessmentId, 'read');

  const checklist = await checklistService.getChecklist(assessmentId, {
    phase: phase as string,
    completed: completed === 'true',
    includeDeleted: include_deleted === 'true'
  });

  res.json({ success: true, data: checklist });
});

/**
 * POST /api/v1/assessments/:assessmentId/checklist
 *
 * Create a new checklist item or auto-generate from report
 */
export const createChecklist = asyncHandler(async (req: Request, res: Response) => {
  const { assessmentId } = req.params;
  const { auto_generate, title, description, phase, priority } = req.body;

  // Verify user has permission to create checklist items
  await validateChecklistPermission(req.user.id, assessmentId, 'write');

  // Only consultants can create checklist items
  if (req.user.role !== 'consultant') {
    return res.status(403).json({
      success: false,
      error: 'Only consultants can create checklist items'
    });
  }

  if (auto_generate) {
    const result = await checklistService.autoGenerateChecklist(
      assessmentId,
      req.user.id
    );
    return res.status(201).json({
      success: true,
      data: result,
      message: 'Checklist auto-generated from report recommendations'
    });
  }

  // Validate required fields for manual creation
  if (!title || !phase) {
    return res.status(400).json({
      success: false,
      error: 'Title and phase are required'
    });
  }

  const item = await checklistService.createItem({
    assessment_id: assessmentId,
    title,
    description,
    phase,
    priority,
    created_by: req.user.id
  });

  res.status(201).json({ success: true, data: item });
});

/**
 * PATCH /api/v1/checklist/:itemId
 *
 * Update a checklist item
 */
export const updateItem = asyncHandler(async (req: Request, res: Response) => {
  const { itemId } = req.params;

  const item = await checklistService.updateItem(
    itemId,
    req.body,
    req.user.id,
    req.user.role
  );

  res.json({ success: true, data: item });
});

/**
 * DELETE /api/v1/checklist/:itemId
 *
 * Soft delete a checklist item
 */
export const deleteItem = asyncHandler(async (req: Request, res: Response) => {
  const { itemId } = req.params;

  // Only consultants can delete items
  if (req.user.role !== 'consultant') {
    return res.status(403).json({
      success: false,
      error: 'Only consultants can delete items'
    });
  }

  await checklistService.deleteItem(itemId, req.user.id);

  res.json({
    success: true,
    message: 'Checklist item deleted successfully'
  });
});

/**
 * POST /api/v1/checklist/:itemId/complete
 *
 * Mark an item as complete or incomplete
 */
export const toggleComplete = asyncHandler(async (req: Request, res: Response) => {
  const { itemId } = req.params;
  const { completed } = req.body;

  if (typeof completed !== 'boolean') {
    return res.status(400).json({
      success: false,
      error: 'Completed field must be a boolean'
    });
  }

  const item = await checklistService.toggleComplete(
    itemId,
    completed,
    req.user.id
  );

  res.json({ success: true, data: item });
});

/**
 * PATCH /api/v1/assessments/:assessmentId/checklist/reorder
 *
 * Reorder multiple checklist items
 */
export const reorderItems = asyncHandler(async (req: Request, res: Response) => {
  const { assessmentId } = req.params;
  const { items } = req.body;

  // Only consultants can reorder items
  if (req.user.role !== 'consultant') {
    return res.status(403).json({
      success: false,
      error: 'Only consultants can reorder items'
    });
  }

  // Validate items array
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Items must be a non-empty array'
    });
  }

  // Validate each item has id and sort_order
  for (const item of items) {
    if (!item.id || typeof item.sort_order !== 'number') {
      return res.status(400).json({
        success: false,
        error: 'Each item must have id and sort_order'
      });
    }
  }

  await checklistService.reorderItems(assessmentId, items);

  res.json({
    success: true,
    message: 'Checklist items reordered successfully'
  });
});

export const checklistController = {
  getChecklist,
  createChecklist,
  updateItem,
  deleteItem,
  toggleComplete,
  reorderItems
};

export default checklistController;
