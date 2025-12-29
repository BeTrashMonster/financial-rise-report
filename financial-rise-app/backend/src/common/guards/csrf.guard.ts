import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

/**
 * CSRF Protection Guard using Double-Submit Cookie Pattern
 *
 * This guard protects against CSRF attacks for state-changing operations
 * using the double-submit cookie pattern suitable for SPA applications.
 *
 * How it works:
 * 1. Server sets a random CSRF token in a cookie (httpOnly=false for client access)
 * 2. Client reads the cookie and includes the token in a custom header (X-CSRF-Token)
 * 3. Server validates that cookie value matches header value
 *
 * This is secure because:
 * - Attackers can't read cookies from other domains (Same-Origin Policy)
 * - Attackers can't set custom headers on cross-origin requests
 * - Only the legitimate client can read the cookie AND set the header
 *
 * Note: For JWT-based APIs, CSRF protection is less critical since:
 * - JWT tokens are stored in localStorage/sessionStorage (not cookies)
 * - Browsers don't automatically send localStorage data with requests
 * - However, this provides defense-in-depth for cookie-based sessions
 *
 * Usage:
 * - Apply to specific routes using @UseGuards(CsrfGuard)
 * - Or apply globally in main.ts
 * - Exempt specific routes using @Public() decorator
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  private static readonly CSRF_COOKIE_NAME = 'XSRF-TOKEN';
  private static readonly CSRF_HEADER_NAME = 'x-csrf-token';

  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Check if route is marked as public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();

    // Only check CSRF for state-changing methods
    const method = request.method.toUpperCase();
    if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
      return true;
    }

    // Get CSRF token from cookie
    const cookieToken = request.cookies?.[CsrfGuard.CSRF_COOKIE_NAME];

    // Get CSRF token from header
    const headerToken = request.headers[CsrfGuard.CSRF_HEADER_NAME] as string;

    // Both must be present and match
    if (!cookieToken || !headerToken) {
      throw new ForbiddenException('CSRF token missing');
    }

    if (cookieToken !== headerToken) {
      throw new ForbiddenException('CSRF token mismatch');
    }

    return true;
  }
}
