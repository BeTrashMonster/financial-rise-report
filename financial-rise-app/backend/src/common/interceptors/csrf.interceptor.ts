import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Response } from 'express';
import * as crypto from 'crypto';

/**
 * CSRF Token Interceptor
 *
 * Automatically sets a CSRF token cookie on all responses if not already present.
 * This works in conjunction with CsrfGuard to implement double-submit cookie pattern.
 *
 * The token is:
 * - Generated once per session
 * - Stored in a cookie (httpOnly=false so client can read it)
 * - Must be included by client in X-CSRF-Token header for state-changing requests
 */
@Injectable()
export class CsrfInterceptor implements NestInterceptor {
  private static readonly CSRF_COOKIE_NAME = 'XSRF-TOKEN';
  private static readonly TOKEN_LENGTH = 32;

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const response = context.switchToHttp().getResponse<Response>();
    const request = context.switchToHttp().getRequest();

    // Check if CSRF cookie already exists
    const existingToken = request.cookies?.[CsrfInterceptor.CSRF_COOKIE_NAME];

    if (!existingToken) {
      // Generate new CSRF token
      const csrfToken = crypto.randomBytes(CsrfInterceptor.TOKEN_LENGTH).toString('hex');

      // Determine if connection is secure
      const isSecure = request.secure || request.headers['x-forwarded-proto'] === 'https';

      // Set CSRF cookie
      // Note: httpOnly=false allows client JavaScript to read the cookie
      // This is necessary for the double-submit pattern
      response.cookie(CsrfInterceptor.CSRF_COOKIE_NAME, csrfToken, {
        httpOnly: false, // Client needs to read this
        secure: isSecure, // Only require HTTPS when actually using HTTPS
        sameSite: 'lax', // Changed from 'strict' to allow cross-site navigation
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      });
    }

    return next.handle();
  }
}
