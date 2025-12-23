/**
 * Assessment Request Validation Schemas
 * Uses Zod for runtime type-safe validation
 */

import { z } from 'zod';
import { VALIDATION_LIMITS, ALLOWED_SORT_FIELDS, ALLOWED_SORT_ORDERS } from '../constants';
import { AssessmentStatus } from '../types';

/**
 * Create Assessment Request Schema
 */
export const createAssessmentSchema = z.object({
  clientName: z
    .string()
    .trim()
    .min(VALIDATION_LIMITS.CLIENT_NAME_MIN_LENGTH, 'Client name is required')
    .max(VALIDATION_LIMITS.CLIENT_NAME_MAX_LENGTH, `Client name must not exceed ${VALIDATION_LIMITS.CLIENT_NAME_MAX_LENGTH} characters`),

  businessName: z
    .string()
    .trim()
    .min(VALIDATION_LIMITS.BUSINESS_NAME_MIN_LENGTH, 'Business name is required')
    .max(VALIDATION_LIMITS.BUSINESS_NAME_MAX_LENGTH, `Business name must not exceed ${VALIDATION_LIMITS.BUSINESS_NAME_MAX_LENGTH} characters`),

  clientEmail: z
    .string()
    .trim()
    .email('Invalid email format')
    .max(VALIDATION_LIMITS.EMAIL_MAX_LENGTH, `Email must not exceed ${VALIDATION_LIMITS.EMAIL_MAX_LENGTH} characters`),

  notes: z
    .string()
    .max(VALIDATION_LIMITS.CONSULTANT_NOTES_MAX_LENGTH, `Notes must not exceed ${VALIDATION_LIMITS.CONSULTANT_NOTES_MAX_LENGTH} characters`)
    .optional()
    .nullable(),
});

export type CreateAssessmentInput = z.infer<typeof createAssessmentSchema>;

/**
 * Update Assessment Request Schema
 */
export const updateAssessmentSchema = z.object({
  responses: z
    .array(
      z.object({
        questionId: z.string().uuid('Invalid question ID format'),
        answer: z.any(), // Can be string, number, array, or null
        notApplicable: z.boolean().optional().default(false),
        consultantNotes: z
          .string()
          .max(VALIDATION_LIMITS.CONSULTANT_NOTES_MAX_LENGTH, `Notes must not exceed ${VALIDATION_LIMITS.CONSULTANT_NOTES_MAX_LENGTH} characters`)
          .optional()
          .nullable(),
      })
    )
    .optional(),

  status: z
    .enum([AssessmentStatus.DRAFT, AssessmentStatus.IN_PROGRESS, AssessmentStatus.COMPLETED])
    .optional(),
});

export type UpdateAssessmentInput = z.infer<typeof updateAssessmentSchema>;

/**
 * List Assessments Query Parameters Schema
 */
export const listAssessmentsQuerySchema = z.object({
  status: z
    .enum([AssessmentStatus.DRAFT, AssessmentStatus.IN_PROGRESS, AssessmentStatus.COMPLETED])
    .optional(),

  limit: z
    .string()
    .optional()
    .default(String(VALIDATION_LIMITS.PAGINATION_LIMIT_DEFAULT))
    .transform((val) => parseInt(val, 10))
    .refine(
      (val) => val >= VALIDATION_LIMITS.PAGINATION_LIMIT_MIN && val <= VALIDATION_LIMITS.PAGINATION_LIMIT_MAX,
      `Limit must be between ${VALIDATION_LIMITS.PAGINATION_LIMIT_MIN} and ${VALIDATION_LIMITS.PAGINATION_LIMIT_MAX}`
    ),

  offset: z
    .string()
    .optional()
    .default(String(VALIDATION_LIMITS.PAGINATION_OFFSET_DEFAULT))
    .transform((val) => parseInt(val, 10))
    .refine(
      (val) => val >= VALIDATION_LIMITS.PAGINATION_OFFSET_MIN,
      `Offset must be at least ${VALIDATION_LIMITS.PAGINATION_OFFSET_MIN}`
    ),

  sortBy: z
    .enum(ALLOWED_SORT_FIELDS)
    .optional()
    .default('updatedAt'),

  sortOrder: z
    .enum(ALLOWED_SORT_ORDERS)
    .optional()
    .transform((val) => val?.toUpperCase() as typeof ALLOWED_SORT_ORDERS[number])
    .default('DESC'),
});

export type ListAssessmentsQuery = z.infer<typeof listAssessmentsQuerySchema>;

/**
 * UUID Parameter Schema (for :id routes)
 */
export const uuidParamSchema = z.object({
  id: z.string().uuid('Invalid assessment ID format'),
});

export type UuidParam = z.infer<typeof uuidParamSchema>;
