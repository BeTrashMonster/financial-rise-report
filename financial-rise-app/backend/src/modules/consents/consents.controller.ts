import {
  Controller,
  Get,
  Patch,
  Param,
  Body,
  UseGuards,
  Request,
  ForbiddenException,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ConsentsService } from './consents.service';
import { ConsentType, UserConsent } from './entities/user-consent.entity';
import { UpdateConsentDto } from './dto/update-consent.dto';
import { UserRole } from '../users/entities/user.entity';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class ConsentsController {
  constructor(private readonly consentsService: ConsentsService) {}

  /**
   * GET /api/users/:id/consents
   * Get all consent records for a user
   */
  @Get(':id/consents')
  async getConsents(@Param('id') id: string, @Request() req: any): Promise<UserConsent[]> {
    // Users can only access their own consents unless they are admin
    if (req.user.id !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only access your own consent data');
    }

    return this.consentsService.getConsents(id);
  }

  /**
   * PATCH /api/users/:id/consents/:type
   * Update consent for a specific type
   * Records IP address and user agent for audit trail
   */
  @Patch(':id/consents/:type')
  async updateConsent(
    @Param('id') id: string,
    @Param('type') type: ConsentType,
    @Body() updateConsentDto: UpdateConsentDto,
    @Request() req: any,
  ): Promise<UserConsent> {
    // Users can only update their own consents unless they are admin
    if (req.user.id !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only update your own consent data');
    }

    const ipAddress = req.ip || null;
    const userAgent = req.headers['user-agent'] || null;

    return this.consentsService.updateConsent(
      id,
      type,
      updateConsentDto.granted,
      ipAddress,
      userAgent,
    );
  }

  /**
   * GET /api/users/:id/consents/:type/history
   * Get complete consent history for a specific type
   */
  @Get(':id/consents/:type/history')
  async getConsentHistory(
    @Param('id') id: string,
    @Param('type') type: ConsentType,
    @Request() req: any,
  ): Promise<UserConsent[]> {
    // Users can only access their own consent history unless they are admin
    if (req.user.id !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only access your own consent data');
    }

    return this.consentsService.getConsentHistory(id, type);
  }
}
