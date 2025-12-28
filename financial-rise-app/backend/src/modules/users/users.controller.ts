import {
  Controller,
  Get,
  Post,
  Delete,
  UseGuards,
  Request,
  Param,
  Body,
  ForbiddenException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { UserRole } from './entities/user.entity';
import { AllowWhenRestricted } from '../../common/decorators/allow-when-restricted.decorator';
import { CreateObjectionDto } from './dto/create-objection.dto';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  @AllowWhenRestricted()
  async getProfile(@Request() req: any) {
    return this.usersService.findById(req.user.userId);
  }

  /**
   * GDPR Article 15 - Right to Access
   * Export all user data in machine-readable JSON format
   */
  @UseGuards(JwtAuthGuard)
  @Get(':id/data-export')
  @AllowWhenRestricted()
  async exportUserData(@Param('id') id: string, @Request() req: any) {
    // Users can only export their own data unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only export your own data');
    }

    return this.usersService.exportUserData(id);
  }

  /**
   * GDPR Article 18 - Right to Restriction of Processing
   * Restrict data processing for user account
   */
  @UseGuards(JwtAuthGuard)
  @Post(':id/restrict-processing')
  @HttpCode(HttpStatus.OK)
  @AllowWhenRestricted()
  async restrictProcessing(
    @Param('id') id: string,
    @Body() body: { reason?: string },
    @Request() req: any,
  ) {
    // Users can only restrict their own account unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only restrict processing for your own account');
    }

    return this.usersService.restrictProcessing(id, body.reason);
  }

  /**
   * GDPR Article 18 - Right to Restriction of Processing
   * Lift processing restriction from user account
   */
  @UseGuards(JwtAuthGuard)
  @Delete(':id/restrict-processing')
  @HttpCode(HttpStatus.OK)
  @AllowWhenRestricted()
  async liftProcessingRestriction(@Param('id') id: string, @Request() req: any) {
    // Users can only lift restriction on their own account unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException(
        'You can only lift processing restriction for your own account',
      );
    }

    return this.usersService.liftProcessingRestriction(id);
  }

  /**
   * GDPR Article 18 - Right to Restriction of Processing
   * Get processing restriction status
   */
  @UseGuards(JwtAuthGuard)
  @Get(':id/processing-status')
  @AllowWhenRestricted()
  async getProcessingStatus(@Param('id') id: string, @Request() req: any) {
    // Users can only view their own status unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only view processing status for your own account');
    }

    return this.usersService.getProcessingStatus(id);
  }

  /**
   * GDPR Article 17 - Right to Erasure
   * Delete user account and all related data (hard delete)
   */
  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @AllowWhenRestricted()
  async deleteUser(@Param('id') id: string, @Request() req: any) {
    // Users can only delete their own account unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only delete your own account');
    }

    return this.usersService.deleteUserCascade(id);
  }

  /**
   * GDPR Article 21 - Right to Object to Processing
   * Create an objection to specific processing type
   */
  @UseGuards(JwtAuthGuard)
  @Post(':id/object-to-processing')
  @HttpCode(HttpStatus.CREATED)
  @AllowWhenRestricted()
  async objectToProcessing(
    @Param('id') id: string,
    @Body() objectionDto: CreateObjectionDto,
    @Request() req: any,
  ) {
    // Users can only create objections for their own account unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only create objections for your own account');
    }

    return this.usersService.objectToProcessing(
      id,
      objectionDto.objection_type,
      objectionDto.reason,
    );
  }

  /**
   * GDPR Article 21 - Right to Object to Processing
   * Get all objections for a user
   */
  @UseGuards(JwtAuthGuard)
  @Get(':id/objections')
  @AllowWhenRestricted()
  async getObjections(@Param('id') id: string, @Request() req: any) {
    // Users can only view their own objections unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only view your own objections');
    }

    return this.usersService.getObjections(id);
  }

  /**
   * GDPR Article 21 - Right to Object to Processing
   * Withdraw an objection
   */
  @UseGuards(JwtAuthGuard)
  @Delete(':id/objections/:objectionId')
  @HttpCode(HttpStatus.OK)
  @AllowWhenRestricted()
  async withdrawObjection(
    @Param('id') id: string,
    @Param('objectionId') objectionId: string,
    @Request() req: any,
  ) {
    // Users can only withdraw their own objections unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only withdraw your own objections');
    }

    return this.usersService.withdrawObjection(id, objectionId);
  }
}
