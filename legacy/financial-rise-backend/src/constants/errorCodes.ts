/**
 * Error Codes
 * Centralized error code registry for consistent error handling across the application
 */

export const ERROR_CODES = {
  // ============================================================================
  // Authentication & Authorization (1000-1999)
  // ============================================================================
  UNAUTHORIZED: 'UNAUTHORIZED',
  TOKEN_EXPIRED: 'TOKEN_EXPIRED',
  INVALID_TOKEN: 'INVALID_TOKEN',
  INSUFFICIENT_PERMISSIONS: 'INSUFFICIENT_PERMISSIONS',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',

  // ============================================================================
  // Validation (2000-2999)
  // ============================================================================
  VALIDATION_ERROR: 'VALIDATION_ERROR',
  INVALID_REQUEST: 'INVALID_REQUEST',
  MISSING_REQUIRED_FIELD: 'MISSING_REQUIRED_FIELD',
  INVALID_EMAIL: 'INVALID_EMAIL',
  INVALID_PASSWORD: 'INVALID_PASSWORD',
  INVALID_QUESTION_TYPE: 'INVALID_QUESTION_TYPE',
  INVALID_ASSESSMENT_STATUS: 'INVALID_ASSESSMENT_STATUS',

  // ============================================================================
  // Resource Management (3000-3999)
  // ============================================================================
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  RESOURCE_LOCKED: 'RESOURCE_LOCKED',
  ASSESSMENT_NOT_FOUND: 'ASSESSMENT_NOT_FOUND',
  QUESTION_NOT_FOUND: 'QUESTION_NOT_FOUND',
  USER_NOT_FOUND: 'USER_NOT_FOUND',
  REPORT_NOT_FOUND: 'REPORT_NOT_FOUND',

  // ============================================================================
  // Rate Limiting (4000-4999)
  // ============================================================================
  RATE_LIMIT_EXCEEDED: 'RATE_LIMIT_EXCEEDED',
  TOO_MANY_LOGIN_ATTEMPTS: 'TOO_MANY_LOGIN_ATTEMPTS',
  TOO_MANY_PASSWORD_RESET_ATTEMPTS: 'TOO_MANY_PASSWORD_RESET_ATTEMPTS',

  // ============================================================================
  // Business Logic (5000-5999)
  // ============================================================================
  ASSESSMENT_ALREADY_COMPLETED: 'ASSESSMENT_ALREADY_COMPLETED',
  CANNOT_MODIFY_COMPLETED_ASSESSMENT: 'CANNOT_MODIFY_COMPLETED_ASSESSMENT',
  INCOMPLETE_ASSESSMENT: 'INCOMPLETE_ASSESSMENT',
  CANNOT_DELETE_NON_DRAFT_ASSESSMENT: 'CANNOT_DELETE_NON_DRAFT_ASSESSMENT',
  INSUFFICIENT_DISC_QUESTIONS: 'INSUFFICIENT_DISC_QUESTIONS',
  MISSING_REQUIRED_QUESTIONS: 'MISSING_REQUIRED_QUESTIONS',

  // ============================================================================
  // CSRF Protection (6000-6999)
  // ============================================================================
  CSRF_TOKEN_INVALID: 'CSRF_TOKEN_INVALID',
  CSRF_TOKEN_MISSING: 'CSRF_TOKEN_MISSING',

  // ============================================================================
  // System Errors (9000-9999)
  // ============================================================================
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  DATABASE_ERROR: 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR: 'EXTERNAL_SERVICE_ERROR',
  PDF_GENERATION_ERROR: 'PDF_GENERATION_ERROR',
  EMAIL_SEND_ERROR: 'EMAIL_SEND_ERROR',
} as const;

export type ErrorCode = typeof ERROR_CODES[keyof typeof ERROR_CODES];

/**
 * HTTP status codes mapped to error codes
 */
export const ERROR_STATUS_CODES: Record<ErrorCode, number> = {
  // Authentication & Authorization
  UNAUTHORIZED: 401,
  TOKEN_EXPIRED: 401,
  INVALID_TOKEN: 401,
  INSUFFICIENT_PERMISSIONS: 403,
  ACCOUNT_LOCKED: 423,

  // Validation
  VALIDATION_ERROR: 400,
  INVALID_REQUEST: 400,
  MISSING_REQUIRED_FIELD: 400,
  INVALID_EMAIL: 400,
  INVALID_PASSWORD: 400,
  INVALID_QUESTION_TYPE: 400,
  INVALID_ASSESSMENT_STATUS: 400,

  // Resource Management
  NOT_FOUND: 404,
  CONFLICT: 409,
  RESOURCE_LOCKED: 423,
  ASSESSMENT_NOT_FOUND: 404,
  QUESTION_NOT_FOUND: 404,
  USER_NOT_FOUND: 404,
  REPORT_NOT_FOUND: 404,

  // Rate Limiting
  RATE_LIMIT_EXCEEDED: 429,
  TOO_MANY_LOGIN_ATTEMPTS: 429,
  TOO_MANY_PASSWORD_RESET_ATTEMPTS: 429,

  // Business Logic
  ASSESSMENT_ALREADY_COMPLETED: 409,
  CANNOT_MODIFY_COMPLETED_ASSESSMENT: 409,
  INCOMPLETE_ASSESSMENT: 409,
  CANNOT_DELETE_NON_DRAFT_ASSESSMENT: 409,
  INSUFFICIENT_DISC_QUESTIONS: 400,
  MISSING_REQUIRED_QUESTIONS: 400,

  // CSRF Protection
  CSRF_TOKEN_INVALID: 403,
  CSRF_TOKEN_MISSING: 403,

  // System Errors
  INTERNAL_ERROR: 500,
  DATABASE_ERROR: 500,
  EXTERNAL_SERVICE_ERROR: 502,
  PDF_GENERATION_ERROR: 500,
  EMAIL_SEND_ERROR: 500,
};
