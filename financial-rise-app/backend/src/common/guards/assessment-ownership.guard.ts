import { Injectable, CanActivate, ExecutionContext, NotFoundException } from '@nestjs/common';
import { AssessmentsService } from '../../modules/assessments/assessments.service';

/**
 * AssessmentOwnershipGuard
 *
 * Prevents Insecure Direct Object Reference (IDOR) attacks by validating
 * that the authenticated user owns the assessment they're trying to access.
 *
 * This guard implements OWASP A01:2021 - Broken Access Control protection
 * and prevents CWE-639 - Authorization Bypass Through User-Controlled Key.
 *
 * @security IDOR Protection
 * @security Access Control
 *
 * Usage:
 * @UseGuards(JwtAuthGuard, AssessmentOwnershipGuard)
 * @Get(':id')
 * findOne(@Param('id') id: string) { ... }
 *
 * How it works:
 * 1. Extracts assessment ID from route params
 * 2. Extracts user ID from authenticated user (set by JwtAuthGuard)
 * 3. Calls AssessmentsService.findOne(assessmentId, userId)
 * 4. Service validates ownership and throws NotFoundException if not owned
 * 5. Admin users bypass ownership check and can access all assessments
 *
 * @see AssessmentsService.findOne() for service-layer ownership validation
 */
@Injectable()
export class AssessmentOwnershipGuard implements CanActivate {
  constructor(private readonly assessmentsService: AssessmentsService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const assessmentId = request.params.id;

    // Validate required data is present
    if (!user || !user.id) {
      throw new Error('User information is missing. Ensure JwtAuthGuard is applied before this guard.');
    }

    if (!assessmentId) {
      throw new Error('Assessment ID is missing from route parameters.');
    }

    // Admin users can access all assessments
    if (user.role === 'admin') {
      return true;
    }

    // For consultant users, validate ownership through service layer
    // The service's findOne method validates that consultant_id matches user.id
    // and throws NotFoundException if the assessment doesn't exist or isn't owned by the user
    await this.assessmentsService.findOne(assessmentId, user.id);

    // If we reach here, the user owns the assessment
    return true;
  }
}
