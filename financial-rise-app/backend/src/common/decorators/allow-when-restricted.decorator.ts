import { SetMetadata } from '@nestjs/common';
import { ALLOW_WHEN_RESTRICTED_KEY } from '../guards/processing-restriction.guard';

/**
 * Decorator to mark endpoints that should work even when processing is restricted
 *
 * GDPR Article 18 allows users to restrict processing, but they should still be able to:
 * - View their data (Article 15)
 * - Export their data (Article 20)
 * - Delete their data (Article 17)
 * - Update their profile
 * - Manage processing restrictions
 *
 * Usage:
 * @AllowWhenRestricted()
 * @UseGuards(JwtAuthGuard, ProcessingRestrictionGuard)
 * async getData() { ... }
 */
export const AllowWhenRestricted = () => SetMetadata(ALLOW_WHEN_RESTRICTED_KEY, true);
