/**
 * Checklist Validation Schemas
 *
 * Input validation for checklist API endpoints using Joi.
 *
 * @module validators/checklistValidator
 * @version 1.0
 * @date 2025-12-22
 */

import Joi from 'joi';

/**
 * Validation schema for creating checklist items
 */
const create = Joi.object({
  // Auto-generation mode
  auto_generate: Joi.boolean().optional(),

  // Manual creation fields
  title: Joi.string()
    .min(1)
    .max(500)
    .when('auto_generate', {
      is: Joi.exist().valid(false, undefined),
      then: Joi.required(),
      otherwise: Joi.optional()
    }),

  description: Joi.string().max(5000).optional().allow(''),

  phase: Joi.string()
    .valid('Stabilize', 'Organize', 'Build', 'Grow', 'Systemic')
    .when('auto_generate', {
      is: Joi.exist().valid(false, undefined),
      then: Joi.required(),
      otherwise: Joi.optional()
    }),

  priority: Joi.number().integer().min(0).max(3).optional()
}).or('auto_generate', 'title');

/**
 * Validation schema for updating checklist items
 */
const update = Joi.object({
  title: Joi.string().min(1).max(500).optional(),
  description: Joi.string().max(5000).optional().allow(''),
  phase: Joi.string()
    .valid('Stabilize', 'Organize', 'Build', 'Grow', 'Systemic')
    .optional(),
  priority: Joi.number().integer().min(0).max(3).optional(),
  sort_order: Joi.number().integer().min(0).optional(),
  client_notes: Joi.string().max(5000).optional().allow('')
}).min(1); // At least one field must be provided

/**
 * Validation schema for toggling completion status
 */
const toggleComplete = Joi.object({
  completed: Joi.boolean().required()
});

/**
 * Validation schema for reordering items
 */
const reorder = Joi.object({
  items: Joi.array()
    .items(
      Joi.object({
        id: Joi.string().uuid().required(),
        sort_order: Joi.number().integer().min(0).required()
      })
    )
    .min(1)
    .required()
});

export const checklistValidation = {
  create,
  update,
  toggleComplete,
  reorder
};

export default checklistValidation;
