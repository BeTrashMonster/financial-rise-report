import {
  Controller,
  Get,
  Delete,
  UseGuards,
  Request,
  Param,
  ForbiddenException,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { UsersService } from './users.service';
import { UserRole } from './entities/user.entity';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@Request() req: any) {
    return this.usersService.findById(req.user.userId);
  }

  /**
   * GDPR Article 15 - Right to Access
   * Export all user data in machine-readable JSON format
   */
  @UseGuards(JwtAuthGuard)
  @Get(':id/data-export')
  async exportUserData(@Param('id') id: string, @Request() req: any) {
    // Users can only export their own data unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only export your own data');
    }

    return this.usersService.exportUserData(id);
  }

  /**
   * GDPR Article 17 - Right to Erasure
   * Delete user account and all related data (hard delete)
   */
  @UseGuards(JwtAuthGuard)
  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteUser(@Param('id') id: string, @Request() req: any) {
    // Users can only delete their own account unless they are admin
    if (req.user.userId !== id && req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('You can only delete your own account');
    }

    return this.usersService.deleteUserCascade(id);
  }
}
