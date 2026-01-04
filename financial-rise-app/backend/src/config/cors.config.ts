import { CorsOptions } from '@nestjs/common/interfaces/external/cors-options.interface';
import { Logger } from '@nestjs/common';

/**
 * CORS Configuration Module
 * Work Stream 59 (HIGH-010) - CORS Configuration Hardening
 *
 * Purpose: Implement secure CORS origin validation with whitelist,
 * logging for blocked requests, and explicit method/header configuration.
 *
 * Updated: 2026-01-03 - Added CORS_ORIGINS environment variable support
 *
 * Security Finding: HIGH-010 - CORS misconfiguration risk
 * OWASP: A05:2021 - Security Misconfiguration
 * CWE: CWE-346 - Origin Validation Error
 *
 * Reference: SECURITY-AUDIT-REPORT.md Lines 1255-1309
 */

const logger = new Logger('CORSConfiguration');

/**
 * Build list of allowed origins from environment variables
 * Only includes origins that are defined (filters out undefined values)
 */
function getAllowedOrigins(): string[] {
  const origins = [
    'http://localhost:3001', // Default frontend development server
    'http://localhost:5173', // Vite development server
    process.env.FRONTEND_URL, // Production frontend URL
    process.env.FRONTEND_URL_STAGING, // Staging frontend URL
  ].filter(Boolean) as string[]; // Remove undefined values

  // Add additional origins from CORS_ORIGINS environment variable (comma-separated)
  if (process.env.CORS_ORIGINS) {
    const additionalOrigins = process.env.CORS_ORIGINS
      .split(',')
      .map(origin => origin.trim())
      .filter(Boolean);
    origins.push(...additionalOrigins);
  }

  // Remove duplicates
  const uniqueOrigins = Array.from(new Set(origins));

  logger.log(`CORS: Configured ${uniqueOrigins.length} allowed origins`);
  uniqueOrigins.forEach((origin) => {
    logger.log(`CORS: Whitelisted origin - ${origin}`);
  });

  return uniqueOrigins;
}

/**
 * CORS origin validation callback
 * Implements strict origin validation with logging for security monitoring
 *
 * @param origin - The origin from the request header
 * @param callback - Callback function to allow/deny the request
 */
function validateOrigin(
  origin: string | undefined,
  callback: (err: Error | null, allow?: boolean) => void
) {
  const allowedOrigins = getAllowedOrigins();

  // Allow requests with no origin (mobile apps, Postman, server-to-server)
  // This is a security decision - adjust based on requirements
  if (!origin) {
    logger.debug('CORS: Request with no origin header - allowing');
    return callback(null, true);
  }

  // Check if origin is in whitelist
  if (allowedOrigins.includes(origin)) {
    logger.debug(`CORS: Allowed request from whitelisted origin: ${origin}`);
    return callback(null, true);
  }

  // Block unauthorized origin and log for security monitoring
  logger.warn(
    `🚫 CORS: Blocked request from unauthorized origin: ${origin}`,
    {
      origin,
      timestamp: new Date().toISOString(),
      securityEvent: 'CORS_ORIGIN_BLOCKED',
      severity: 'MEDIUM',
    }
  );

  callback(new Error('Not allowed by CORS'));
}

/**
 * Production-ready CORS configuration
 * Implements all security best practices from security audit
 */
export const corsConfig: CorsOptions = {
  // Origin validation with whitelist
  origin: validateOrigin,

  // Allow credentials (cookies, authorization headers)
  credentials: true,

  // Explicitly define allowed HTTP methods
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],

  // Explicitly define allowed request headers
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-CSRF-Token',
    'X-Requested-With',
    'Accept',
    'Accept-Version',
    'Content-Length',
    'Content-MD5',
    'Date',
    'X-Api-Version',
  ],

  // Expose custom headers to frontend JavaScript
  exposedHeaders: [
    'X-Total-Count', // Pagination total count
    'X-Page-Number', // Current page number
    'X-Page-Size', // Items per page
    'X-RateLimit-Limit', // Rate limit maximum
    'X-RateLimit-Remaining', // Rate limit remaining
    'X-RateLimit-Reset', // Rate limit reset time
  ],

  // Cache preflight requests for 1 hour (3600 seconds)
  // Reduces preflight overhead while maintaining security
  maxAge: 3600,

  // Include status code for successful OPTIONS requests
  optionsSuccessStatus: 200,

  // Do not pass the CORS preflight response to the next handler
  preflightContinue: false,
};

/**
 * Get CORS configuration for application
 * @returns CorsOptions configuration object
 */
export function getCorsConfig(): CorsOptions {
  return corsConfig;
}

/**
 * Security Notes:
 *
 * 1. Origin Validation:
 *    - Uses strict whitelist validation
 *    - Logs all blocked origins for security monitoring
 *    - No wildcard (*) origins allowed
 *
 * 2. Credentials:
 *    - Enabled to allow cookies and authorization headers
 *    - MUST NOT use wildcard origin when credentials are true
 *
 * 3. Methods:
 *    - Explicitly defined to prevent method-based attacks
 *    - Excludes dangerous methods like TRACE, CONNECT
 *
 * 4. Headers:
 *    - Allows only necessary headers
 *    - Includes CSRF token header for CSRF protection
 *    - Exposes pagination and rate limit headers
 *
 * 5. Caching:
 *    - 1-hour preflight cache reduces overhead
 *    - Adjust maxAge if origins change frequently
 *
 * 6. Logging:
 *    - All blocked origins logged with timestamp
 *    - Security event markers for SIEM integration
 *    - Whitelisted origins logged on startup
 */
