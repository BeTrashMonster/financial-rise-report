/**
 * Timing Constants
 * Centralized timing configuration for consistent behavior across the application
 */

export const TIMINGS = {
  // Auto-save
  AUTO_SAVE_DELAY_MS: 30 * 1000, // 30 seconds
  AUTO_SAVE_TIMEOUT_MS: 2 * 1000, // 2 seconds max

  // Cache TTL
  PROGRESS_CACHE_TTL_MS: 60 * 60 * 1000, // 1 hour
  QUESTIONNAIRE_CACHE_TTL_MS: 5 * 60 * 1000, // 5 minutes
  QUESTION_COUNT_CACHE_TTL_MS: 60 * 60 * 1000, // 1 hour

  // JWT
  JWT_ACCESS_TOKEN_EXPIRY: '1h', // 1 hour
  JWT_REFRESH_TOKEN_EXPIRY: '7d', // 7 days

  // Password reset
  PASSWORD_RESET_EXPIRY_MS: 24 * 60 * 60 * 1000, // 24 hours
  PASSWORD_RESET_TOKEN_LENGTH: 32, // bytes

  // Session
  SESSION_IDLE_TIMEOUT_MS: 30 * 60 * 1000, // 30 minutes
  SESSION_ABSOLUTE_TIMEOUT_MS: 24 * 60 * 60 * 1000, // 24 hours

  // Database
  DB_QUERY_TIMEOUT_MS: 30 * 1000, // 30 seconds
  DB_IDLE_TRANSACTION_TIMEOUT_MS: 60 * 1000, // 60 seconds
} as const;
