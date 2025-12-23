/**
 * Rate Limiting Constants
 * Centralized configuration for rate limiting across different endpoint types
 */

export const RATE_LIMITS = {
  // General API endpoints
  API_WINDOW_MS: 60 * 1000, // 1 minute
  API_MAX_REQUESTS: 100,

  // Authentication endpoints (login, register)
  AUTH_WINDOW_MS: 15 * 60 * 1000, // 15 minutes
  AUTH_MAX_REQUESTS: 5, // 5 attempts per 15 minutes
  AUTH_SKIP_SUCCESSFUL: true, // Only count failed attempts

  // Password reset endpoints
  PASSWORD_RESET_WINDOW_MS: 60 * 60 * 1000, // 1 hour
  PASSWORD_RESET_MAX_REQUESTS: 3, // 3 attempts per hour

  // Account lockout
  ACCOUNT_LOCKOUT_ATTEMPTS: 5, // Lock after 5 failed attempts
  ACCOUNT_LOCKOUT_DURATION_MS: 30 * 60 * 1000, // 30 minutes
} as const;

/**
 * Rate limit error messages
 */
export const RATE_LIMIT_MESSAGES = {
  API: 'Too many requests, please try again later',
  AUTH: 'Too many login attempts. Please try again in 15 minutes.',
  PASSWORD_RESET: 'Too many password reset requests. Please try again in 1 hour.',
} as const;
