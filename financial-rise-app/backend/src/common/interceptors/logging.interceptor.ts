import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { LogSanitizer } from '../utils/log-sanitizer';

/**
 * Global logging interceptor with automatic PII sanitization
 *
 * SECURITY: Implements CRIT-002 and HIGH-008 remediation
 * - Logs all HTTP requests/responses
 * - Automatically sanitizes PII before logging
 * - Tracks request duration for performance monitoring
 *
 * Applied globally in main.ts
 */
@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const { method, url, body, user } = request;

    const startTime = Date.now();
    const controller = context.getClass().name;
    const handler = context.getHandler().name;

    // Log incoming request with sanitized data
    this.logger.log(`Incoming request: ${method} ${url}`, {
      controller,
      handler,
      method,
      url,
      // Sanitize request body to remove PII
      body: body ? LogSanitizer.sanitizeObject(body) : undefined,
      // Sanitize user object
      user: user ? LogSanitizer.sanitizeObject(user) : undefined,
      timestamp: new Date().toISOString(),
    });

    return next.handle().pipe(
      tap({
        next: (data) => {
          const duration = Date.now() - startTime;
          const statusCode = response.statusCode;

          // Log successful response
          this.logger.log(`Request completed: ${method} ${url}`, {
            method,
            url,
            statusCode,
            duration: `${duration}ms`,
            timestamp: new Date().toISOString(),
          });
        },
        error: (error) => {
          const duration = Date.now() - startTime;

          // Log error without exposing sensitive details
          this.logger.error(`Request failed: ${method} ${url}`, {
            method,
            url,
            error: error.message,
            statusCode: error.status || 500,
            duration: `${duration}ms`,
            timestamp: new Date().toISOString(),
            // Don't log the full error stack in production
            ...(process.env.NODE_ENV === 'development' && {
              stack: error.stack,
            }),
          });
        },
      }),
      // Re-throw errors after logging
      catchError((error) => {
        throw error;
      }),
    );
  }
}
