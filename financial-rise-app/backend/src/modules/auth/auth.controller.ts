import {
  Controller,
  Post,
  Body,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
  Headers,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { Public } from '../../common/decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  /**
   * POST /auth/register
   * Register a new user account
   * Rate limit: 3 attempts per hour to prevent registration flooding
   */
  @Public() // Exempt from CSRF protection (no token available before registration)
  @Throttle({ default: { ttl: 3600000, limit: 3 } }) // 3 requests per hour
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto) {
    return this.authService.register(registerDto);
  }

  /**
   * POST /auth/login
   * Authenticate user and return JWT tokens
   * Rate limit: 5 attempts per minute to prevent brute force attacks
   */
  @Public() // Exempt from CSRF protection (no token available before authentication)
  @Throttle({ default: { ttl: 60000, limit: 5 } }) // 5 requests per minute
  @UseGuards(LocalAuthGuard)
  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Request() req: any, @Body() loginDto: LoginDto) {
    return this.authService.login(req.user);
  }

  /**
   * POST /auth/logout
   * Invalidate refresh token and blacklist access token (Work Stream 57)
   */
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(@Request() req: any, @Headers('authorization') authHeader: string) {
    // Extract access token from Authorization header for blacklisting
    const accessToken = authHeader?.replace('Bearer ', '') || '';
    return this.authService.logout(req.user.id, accessToken);
  }

  /**
   * POST /auth/refresh
   * Get new access token using refresh token
   */
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto.refresh_token);
  }

  /**
   * POST /auth/forgot-password
   * Request password reset email
   * Rate limit: 3 attempts per 5 minutes to prevent email flooding
   */
  @Throttle({ default: { ttl: 300000, limit: 3 } }) // 3 requests per 5 minutes
  @Post('forgot-password')
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordDto.email);
  }

  /**
   * POST /auth/reset-password
   * Reset password using reset token
   */
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordDto.token,
      resetPasswordDto.new_password,
    );
  }

  /**
   * GET /auth/health-check
   * Health check endpoint for monitoring
   */
  @Post('health-check')
  @HttpCode(HttpStatus.OK)
  healthCheck() {
    return { status: 'ok', service: 'auth', timestamp: new Date().toISOString() };
  }
}
