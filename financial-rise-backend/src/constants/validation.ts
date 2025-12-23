/**
 * Validation Constants
 * Centralized validation limits for consistent enforcement across the application
 */

export const VALIDATION_LIMITS = {
  // Text fields
  TEXT_ANSWER_MAX_LENGTH: 1000,
  CONSULTANT_NOTES_MAX_LENGTH: 5000,
  CLIENT_NAME_MIN_LENGTH: 1,
  CLIENT_NAME_MAX_LENGTH: 100,
  BUSINESS_NAME_MIN_LENGTH: 1,
  BUSINESS_NAME_MAX_LENGTH: 200,
  EMAIL_MAX_LENGTH: 255,

  // Ratings
  RATING_MIN: 1,
  RATING_MAX: 5,

  // Confidence ratings
  CONFIDENCE_MIN: 1,
  CONFIDENCE_MAX: 10,

  // Progress
  PROGRESS_MIN: 0,
  PROGRESS_MAX: 100,

  // Pagination
  PAGINATION_LIMIT_MIN: 1,
  PAGINATION_LIMIT_MAX: 100,
  PAGINATION_LIMIT_DEFAULT: 50,
  PAGINATION_OFFSET_MIN: 0,
  PAGINATION_OFFSET_DEFAULT: 0,
} as const;

/**
 * Allowed values for sortable fields
 */
export const ALLOWED_SORT_FIELDS = [
  'updatedAt',
  'createdAt',
  'clientName',
  'businessName',
  'status',
  'progress',
] as const;

export type AllowedSortField = typeof ALLOWED_SORT_FIELDS[number];

/**
 * Allowed sort orders
 */
export const ALLOWED_SORT_ORDERS = ['ASC', 'DESC'] as const;

export type AllowedSortOrder = typeof ALLOWED_SORT_ORDERS[number];
