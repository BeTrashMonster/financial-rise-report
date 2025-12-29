import { SetMetadata } from '@nestjs/common';

/**
 * Public Decorator
 *
 * Use this decorator to exempt routes from CSRF protection.
 * This is necessary for routes like login/register that cannot have
 * a CSRF token before authentication.
 *
 * @example
 * @Public()
 * @Post('login')
 * async login() { ... }
 */
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
