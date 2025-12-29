import {
  Injectable,
  CanActivate,
  ExecutionContext,
  NotFoundException,
  ForbiddenException,
} from '@nestjs/common';
import { ReportGenerationService } from '../../reports/services/report-generation.service';

/**
 * ReportOwnershipGuard
 *
 * Prevents Insecure Direct Object Reference (IDOR) attacks by validating
 * that the authenticated user owns the report (through assessment ownership) they're trying to access.
 *
 * This guard implements OWASP A01:2021 - Broken Access Control protection
 * and prevents CWE-639 - Authorization Bypass Through User-Controlled Key.
 *
 * @security IDOR Protection
 * @security Access Control
 *
 * Usage:
 * @UseGuards(JwtAuthGuard, ReportOwnershipGuard)
 * @Get(':id')
 * getReportStatus(@Param('id') id: string) { ... }
 *
 * How it works:
 * 1. Extracts report ID from route params
 * 2. Extracts user ID from authenticated user (set by JwtAuthGuard)
 * 3. Retrieves report from ReportGenerationService
 * 4. Validates that report.consultantId matches user.id
 * 5. Admin users bypass ownership check and can access all reports
 *
 * @see ReportGenerationService.getReportStatus() for report retrieval
 */
@Injectable()
export class ReportOwnershipGuard implements CanActivate {
  constructor(private readonly reportService: ReportGenerationService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const reportId = request.params.id;

    // Validate required data is present
    if (!user || !user.id) {
      throw new Error('User information is missing. Ensure JwtAuthGuard is applied before this guard.');
    }

    if (!reportId) {
      throw new Error('Report ID is missing from route parameters.');
    }

    // Admin users can access all reports
    if (user.role === 'admin') {
      return true;
    }

    // Retrieve report to check ownership
    const report = await this.reportService.getReportStatus(reportId);

    if (!report) {
      throw new NotFoundException(`Report with ID ${reportId} not found`);
    }

    // Validate ownership - report's consultant must match authenticated user
    if (report.consultantId !== user.id) {
      throw new ForbiddenException('You do not have permission to access this report');
    }

    // User owns the report
    return true;
  }
}
