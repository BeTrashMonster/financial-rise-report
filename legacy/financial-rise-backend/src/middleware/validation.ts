import { body, param, query, validationResult } from 'express-validator';
import { Request, Response, NextFunction } from 'express';

export const handleValidationErrors = (req: Request, res: Response, next: NextFunction): void => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const formattedErrors: Record<string, string[]> = {};
    errors.array().forEach((error) => {
      const field = error.type === 'field' ? error.path : 'unknown';
      if (!formattedErrors[field]) {
        formattedErrors[field] = [];
      }
      formattedErrors[field].push(error.msg);
    });

    res.status(400).json({
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Request validation failed',
        details: {
          fields: formattedErrors,
        },
      },
    });
    return;
  }
  next();
};

// Assessment creation validation
export const validateCreateAssessment = [
  body('clientName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Client name must be between 1 and 100 characters'),
  body('businessName')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Business name must be between 1 and 100 characters'),
  body('clientEmail').trim().isEmail().withMessage('Invalid email format'),
  body('notes').optional().isLength({ max: 1000 }).withMessage('Notes must not exceed 1000 characters'),
  handleValidationErrors,
];

// Assessment update validation
export const validateUpdateAssessment = [
  body('responses').optional().isArray().withMessage('Responses must be an array'),
  body('responses.*.questionId').isUUID().withMessage('Invalid question ID'),
  body('responses.*.notApplicable').optional().isBoolean().withMessage('Not applicable must be a boolean'),
  body('responses.*.consultantNotes')
    .optional()
    .isLength({ max: 1000 })
    .withMessage('Consultant notes must not exceed 1000 characters'),
  body('status').optional().isIn(['draft', 'in_progress', 'completed']).withMessage('Invalid status'),
  handleValidationErrors,
];

// UUID parameter validation
export const validateUUID = [param('id').isUUID().withMessage('Invalid assessment ID'), handleValidationErrors];

// Query parameter validation for list endpoint
export const validateListQuery = [
  query('status').optional().isIn(['draft', 'in_progress', 'completed']).withMessage('Invalid status filter'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('Limit must be between 1 and 200'),
  query('offset').optional().isInt({ min: 0 }).withMessage('Offset must be a non-negative integer'),
  query('sortBy')
    .optional()
    .isIn(['createdAt', 'updatedAt', 'clientName'])
    .withMessage('Invalid sort field'),
  query('sortOrder').optional().isIn(['asc', 'desc']).withMessage('Invalid sort order'),
  handleValidationErrors,
];
