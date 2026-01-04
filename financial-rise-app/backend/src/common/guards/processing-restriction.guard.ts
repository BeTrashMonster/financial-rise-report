import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UsersService } from '../../modules/users/users.service';

/**
 * GDPR Article 18 - Processing Restriction Guard
 *
 * This guard blocks users with restricted processing from performing certain actions.
 *
 * When processing is restricted, users CANNOT:
 * - Create new assessments
 * - Update existing assessments
 * - Perform other data processing operations
 *
 * When processing is restricted, users CAN still:
 * - View their data (GDPR Article 15)
 * - Export their data (GDPR Article 20)
 * - Delete their data (GDPR Article 17)
 * - Update their profile information
 * - Lift the processing restriction
 *
 * Usage:
 * @UseGuards(JwtAuthGuard, ProcessingRestrictionGuard)
 * OR
 * @AllowWhenRestricted() // On specific endpoints that should work even when restricted
 */

// Metadata key for marking endpoints that should work when restricted
export const ALLOW_WHEN_RESTRICTED_KEY = 'allowWhenRestricted';

@Injectable()
export class ProcessingRestrictionGuard implements CanActivate {
  constructor(
    private readonly usersService: UsersService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if endpoint is explicitly allowed when restricted
    const allowWhenRestricted = this.reflector.getAllAndOverride<boolean>(
      ALLOW_WHEN_RESTRICTED_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If endpoint allows restricted processing, skip the check
    if (allowWhenRestricted) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // If no user in request, let other guards handle it
    if (!user || !user.id) {
      return true;
    }

    // Check if user's processing is restricted
    const isRestricted = await this.usersService.isProcessingRestricted(user.id);

    if (isRestricted) {
      throw new ForbiddenException(
        'Your account has restricted data processing. You cannot perform this action. ' +
          'You can still view, export, or delete your data. ' +
          'To perform this action, please lift the processing restriction first.',
      );
    }

    return true;
  }
}
