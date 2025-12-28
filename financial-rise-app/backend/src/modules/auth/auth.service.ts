import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { UsersService } from '../users/users.service';
import { User, UserStatus } from '../users/entities/user.entity';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenService } from './refresh-token.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private refreshTokenService: RefreshTokenService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      return null;
    }

    // Check if account is locked
    const isLocked = await this.usersService.isAccountLocked(user);
    if (isLocked) {
      const lockTimeRemaining = user.locked_until
        ? Math.ceil((user.locked_until.getTime() - Date.now()) / 60000)
        : 0;
      throw new UnauthorizedException(
        `Account is locked due to multiple failed login attempts. Please try again in ${lockTimeRemaining} minutes.`,
      );
    }

    // Check if account is inactive
    if (user.status === UserStatus.INACTIVE) {
      throw new UnauthorizedException('Account is inactive. Please contact support.');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      await this.usersService.incrementFailedLoginAttempts(user.id);
      return null;
    }

    // Reset failed login attempts on successful login
    if (user.failed_login_attempts > 0) {
      await this.usersService.resetFailedLoginAttempts(user.id);
    }

    // Update last login timestamp
    await this.usersService.updateLastLogin(user.id);

    const { password_hash, ...result } = user;
    return result;
  }

  async login(user: User, deviceInfo?: string, ipAddress?: string) {
    const payload = { sub: user.id, email: user.email, role: user.role };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION', '7d'),
    });

    // Calculate expiration date for refresh token
    const refreshExpirationDays = parseInt(
      this.configService.get<string>('JWT_REFRESH_EXPIRATION', '7d').replace('d', ''),
      10,
    );
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + refreshExpirationDays);

    // Store refresh token in database (supports multiple devices)
    await this.refreshTokenService.createToken(
      user.id,
      refreshToken,
      expiresAt,
      deviceInfo,
      ipAddress,
    );

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: this.configService.get<number>('JWT_EXPIRATION_SECONDS', 3600),
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        role: user.role,
      },
    };
  }

  /**
   * Validates password complexity requirements
   * @param password - The password to validate
   * @throws BadRequestException if password doesn't meet requirements
   */
  private validatePasswordComplexity(password: string): void {
    const minLength = 8;
    const errors: string[] = [];

    if (password.length < minLength) {
      errors.push(`Password must be at least ${minLength} characters long`);
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)');
    }

    if (errors.length > 0) {
      throw new BadRequestException(errors.join('; '));
    }
  }

  async register(registerDto: RegisterDto) {
    const existingUser = await this.usersService.findByEmail(registerDto.email);

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Validate password complexity
    this.validatePasswordComplexity(registerDto.password);

    // Hash password with bcrypt (salt rounds: 12)
    const hashedPassword = await bcrypt.hash(registerDto.password, 12);

    const user = await this.usersService.create({
      email: registerDto.email.toLowerCase(),
      password_hash: hashedPassword,
      first_name: registerDto.first_name,
      last_name: registerDto.last_name,
      role: registerDto.role,
      status: UserStatus.ACTIVE,
    });

    return this.login(user);
  }

  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      const user = await this.usersService.findById(payload.sub);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Verify the refresh token exists in the database and is valid
      const storedToken = await this.refreshTokenService.findValidToken(user.id, refreshToken);

      if (!storedToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      if (user.status !== UserStatus.ACTIVE) {
        throw new UnauthorizedException('Account is not active');
      }

      // Generate new access token
      const newPayload = { sub: user.id, email: user.email, role: user.role };
      const accessToken = this.jwtService.sign(newPayload);

      return {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: this.configService.get<number>('JWT_EXPIRATION_SECONDS', 3600),
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async logout(userId: string, revokeAllDevices = false) {
    if (revokeAllDevices) {
      // Revoke all refresh tokens for this user (logout from all devices)
      await this.refreshTokenService.revokeAllUserTokens(userId);
    } else {
      // For single device logout, we would need the specific token
      // For now, revoke all tokens (can be enhanced to revoke specific token)
      await this.refreshTokenService.revokeAllUserTokens(userId);
    }

    return { message: 'Logged out successfully' };
  }

  async forgotPassword(email: string) {
    const user = await this.usersService.findByEmail(email);

    if (!user) {
      // Don't reveal if user exists - return success message anyway
      return {
        message: 'If an account with that email exists, a password reset link has been sent.',
      };
    }

    // Generate secure random token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Store hashed token with 1 hour expiration
    await this.usersService.setResetPasswordToken(user.id, hashedToken, 3600000);

    // TODO: Send email with reset link containing the resetToken
    // For now, we'll just return the token (in production, this should be sent via email)
    // Example: await this.emailService.sendPasswordResetEmail(user.email, resetToken);

    console.log(`Password reset token for ${email}: ${resetToken}`);

    return {
      message: 'If an account with that email exists, a password reset link has been sent.',
      // Remove this in production - only for development
      ...(this.configService.get('NODE_ENV') === 'development' && { resetToken }),
    };
  }

  async resetPassword(token: string, newPassword: string) {
    if (!token || !newPassword) {
      throw new BadRequestException('Token and new password are required');
    }

    // Find all users and check their reset tokens (not ideal, but necessary with hashed tokens)
    // In production, consider using a separate tokens table with indexed lookups
    const users = await this.usersService.findByResetToken(token);

    if (!users) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Check if token is expired
    if (!users.reset_password_expires || new Date() > users.reset_password_expires) {
      await this.usersService.clearResetPasswordToken(users.id);
      throw new BadRequestException('Reset token has expired');
    }

    // Check if token has already been used
    if (users.reset_password_used_at) {
      throw new BadRequestException('Reset token has already been used');
    }

    // Validate password complexity
    this.validatePasswordComplexity(newPassword);

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 12);

    // Update password and mark reset token as used
    await this.usersService.update(users.id, {
      password_hash: hashedPassword,
      reset_password_used_at: new Date(),
    });

    await this.usersService.clearResetPasswordToken(users.id);

    // Revoke all refresh tokens to force re-login on all devices
    await this.refreshTokenService.revokeAllUserTokens(users.id);

    return { message: 'Password has been reset successfully' };
  }
}
