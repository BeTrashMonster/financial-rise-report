import { Logger, LoggerService } from '@nestjs/common';
import { LogSanitizer } from './log-sanitizer';

/**
 * PIISafeLogger - Logger wrapper that automatically sanitizes PII before logging
 *
 * SECURITY: Implements HIGH-008 remediation - prevents PII exposure in logs
 * COMPLIANCE: GDPR/CCPA requirement - automatic PII redaction
 *
 * Usage:
 *   Replace: private readonly logger = new Logger('MyService');
 *   With:    private readonly logger = new PIISafeLogger('MyService');
 *
 * Features:
 * - Automatic PII sanitization for all log levels
 * - Supports email, phone, SSN, credit card, IP address masking
 * - Handles nested objects and arrays
 * - Compatible with NestJS Logger interface
 * - Zero PII exposure in production logs
 *
 * Example:
 *   logger.log('User logged in', { email: 'user@example.com' });
 *   // Output: User logged in { email: '***@example.com' }
 */
export class PIISafeLogger implements LoggerService {
  private readonly logger: Logger;

  constructor(context?: string) {
    this.logger = new Logger(context || 'Application');
  }

  /**
   * Write a 'log' level log.
   * Automatically sanitizes all PII in message and context.
   */
  log(message: any, ...optionalParams: any[]) {
    const sanitizedMessage = this.sanitize(message);
    const sanitizedParams = optionalParams.map((param) => this.sanitize(param));
    this.logger.log(sanitizedMessage, ...sanitizedParams);
  }

  /**
   * Write an 'error' level log.
   * Automatically sanitizes all PII in message and context.
   */
  error(message: any, ...optionalParams: any[]) {
    const sanitizedMessage = this.sanitize(message);
    const sanitizedParams = optionalParams.map((param) => this.sanitize(param));
    this.logger.error(sanitizedMessage, ...sanitizedParams);
  }

  /**
   * Write a 'warn' level log.
   * Automatically sanitizes all PII in message and context.
   */
  warn(message: any, ...optionalParams: any[]) {
    const sanitizedMessage = this.sanitize(message);
    const sanitizedParams = optionalParams.map((param) => this.sanitize(param));
    this.logger.warn(sanitizedMessage, ...sanitizedParams);
  }

  /**
   * Write a 'debug' level log.
   * Automatically sanitizes all PII in message and context.
   */
  debug(message: any, ...optionalParams: any[]) {
    const sanitizedMessage = this.sanitize(message);
    const sanitizedParams = optionalParams.map((param) => this.sanitize(param));
    this.logger.debug(sanitizedMessage, ...sanitizedParams);
  }

  /**
   * Write a 'verbose' level log.
   * Automatically sanitizes all PII in message and context.
   */
  verbose(message: any, ...optionalParams: any[]) {
    const sanitizedMessage = this.sanitize(message);
    const sanitizedParams = optionalParams.map((param) => this.sanitize(param));
    this.logger.verbose(sanitizedMessage, ...sanitizedParams);
  }

  /**
   * Set logger context (for grouped logs)
   */
  setContext(context: string) {
    this.logger.setContext(context);
  }

  /**
   * Sanitize a value (string, object, or any type)
   * @param value - Value to sanitize
   * @returns Sanitized value
   */
  private sanitize(value: any): any {
    if (value === null || value === undefined) {
      return value;
    }

    // Handle strings - detect and redact PII patterns
    if (typeof value === 'string') {
      return LogSanitizer.detectAndRedactPII(value);
    }

    // Handle Error objects
    if (value instanceof Error) {
      return {
        message: LogSanitizer.detectAndRedactPII(value.message),
        name: value.name,
        // Only include stack in development
        ...(process.env.NODE_ENV === 'development' && value.stack
          ? { stack: LogSanitizer.detectAndRedactPII(value.stack) }
          : {}),
      };
    }

    // Handle objects and arrays
    if (typeof value === 'object') {
      try {
        return LogSanitizer.sanitizeObject(value);
      } catch (error) {
        // Handle circular references or other serialization errors
        return '[REDACTED - SERIALIZATION_ERROR]';
      }
    }

    // Handle primitive types (numbers, booleans, etc.)
    return value;
  }
}
