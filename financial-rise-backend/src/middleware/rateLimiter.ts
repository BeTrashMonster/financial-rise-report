import rateLimit from 'express-rate-limit';
import { RATE_LIMITS, RATE_LIMIT_MESSAGES } from '../constants/rateLimits';

/**
 * Rate Limiting Middleware
 * Implements different rate limiting strategies for different endpoint types
 */

/**
 * General API rate limiter
 * Applied to all API endpoints
 */
export const apiLimiter = rateLimit({
  windowMs: RATE_LIMITS.API_WINDOW_MS,
  max: RATE_LIMITS.API_MAX_REQUESTS,
  message: {
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: RATE_LIMIT_MESSAGES.API,
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Authentication rate limiter
 * Stricter limits for login/register endpoints to prevent brute force attacks
 */
export const authLimiter = rateLimit({
  windowMs: RATE_LIMITS.AUTH_WINDOW_MS,
  max: RATE_LIMITS.AUTH_MAX_REQUESTS,
  message: {
    error: {
      code: 'AUTH_RATE_LIMIT_EXCEEDED',
      message: RATE_LIMIT_MESSAGES.AUTH,
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: RATE_LIMITS.AUTH_SKIP_SUCCESSFUL,
  // Use IP + user-agent for more accurate rate limiting
  keyGenerator: (req) => {
    return `${req.ip}-${req.headers['user-agent']}`;
  },
});

/**
 * Password reset rate limiter
 * Prevents abuse of password reset functionality
 */
export const passwordResetLimiter = rateLimit({
  windowMs: RATE_LIMITS.PASSWORD_RESET_WINDOW_MS,
  max: RATE_LIMITS.PASSWORD_RESET_MAX_REQUESTS,
  message: {
    error: {
      code: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
      message: RATE_LIMIT_MESSAGES.PASSWORD_RESET,
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Use email address for password reset rate limiting
  keyGenerator: (req) => {
    const email = req.body?.email || req.query?.email || req.ip;
    return `password-reset-${email}`;
  },
});

/**
 * Report generation rate limiter
 * Prevents resource exhaustion from PDF generation
 */
export const reportGenerationLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 reports per minute per user
  message: {
    error: {
      code: 'REPORT_GENERATION_RATE_LIMIT',
      message: 'Too many report generation requests. Please wait before generating more reports.',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
  // Use user ID for authenticated requests
  keyGenerator: (req) => {
    const userId = (req as any).user?.id || req.ip;
    return `report-gen-${userId}`;
  },
});

/**
 * File upload rate limiter
 * Prevents upload abuse
 */
export const uploadLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 uploads per minute
  message: {
    error: {
      code: 'UPLOAD_RATE_LIMIT_EXCEEDED',
      message: 'Too many upload requests. Please wait before uploading more files.',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});
