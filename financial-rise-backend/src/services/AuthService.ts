import { Repository, MoreThan, IsNull } from 'typeorm';
import { User, UserRole } from '../database/entities/User';
import { RefreshToken } from '../database/entities/RefreshToken';
import { PasswordResetToken } from '../database/entities/PasswordResetToken';
import { FailedLoginAttempt } from '../database/entities/FailedLoginAttempt';
import { AuditLog } from '../database/entities/AuditLog';
import { hashPassword, verifyPassword, validatePasswordComplexity } from '../utils/password';
import {
  createAccessToken,
  createRefreshToken,
  verifyRefreshToken,
  getTokenExpirationDate,
  AccessTokenPayload
} from '../utils/jwt';
import { randomBytes } from 'crypto';

export interface RegisterInput {
  email: string;
  password: string;
  role?: UserRole;
}

export interface LoginInput {
  email: string;
  password: string;
  ipAddress: string;
}

export interface LoginResponse {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  user: {
    id: string;
    email: string;
    role: UserRole;
  };
}

export class AuthService {
  constructor(
    private userRepository: Repository<User>,
    private refreshTokenRepository: Repository<RefreshToken>,
    private passwordResetTokenRepository: Repository<PasswordResetToken>,
    private failedLoginAttemptRepository: Repository<FailedLoginAttempt>,
    private auditLogRepository: Repository<AuditLog>
  ) {}

  /**
   * Register a new user
   * REQ-AUTH-001, REQ-AUTH-003, REQ-SEC-003
   */
  async register(input: RegisterInput): Promise<User> {
    // Validate email uniqueness
    const existingUser = await this.userRepository.findOne({
      where: { email: input.email }
    });

    if (existingUser) {
      throw new Error('Email already registered');
    }

    // Validate password complexity (REQ-AUTH-003)
    const passwordValidation = validatePasswordComplexity(input.password);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join('; '));
    }

    // Hash password (REQ-SEC-003)
    const passwordHash = await hashPassword(input.password);

    // Create user
    const user = this.userRepository.create({
      email: input.email,
      passwordHash,
      role: input.role || UserRole.CONSULTANT,
      isActive: true,
      emailVerified: false
    });

    await this.userRepository.save(user);

    // Audit log
    await this.logAudit({
      userId: user.id,
      action: 'user.register',
      resourceType: 'user',
      resourceId: user.id
    });

    return user;
  }

  /**
   * Authenticate user and issue tokens
   * REQ-AUTH-001, REQ-AUTH-004, REQ-SEC-005
   */
  async login(input: LoginInput): Promise<LoginResponse> {
    // Check account lockout (REQ-AUTH-004)
    const isLocked = await this.checkAccountLockout(input.email);
    if (isLocked) {
      throw new Error('Account locked due to too many failed attempts. Try again in 15 minutes.');
    }

    // Find user
    const user = await this.userRepository.findOne({
      where: { email: input.email }
    });

    if (!user) {
      await this.recordFailedAttempt(input.email, input.ipAddress);
      throw new Error('Invalid credentials');
    }

    // Verify password
    const isValid = await verifyPassword(input.password, user.passwordHash);
    if (!isValid) {
      await this.recordFailedAttempt(input.email, input.ipAddress);
      throw new Error('Invalid credentials');
    }

    // Check if user is active
    if (!user.isActive) {
      throw new Error('Account is deactivated');
    }

    // Update last login
    user.lastLoginAt = new Date();
    await this.userRepository.save(user);

    // Create tokens
    const accessToken = createAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    const refreshTokenEntity = await this.createRefreshTokenForUser(user.id);
    const refreshToken = createRefreshToken({
      userId: user.id,
      tokenId: refreshTokenEntity.id
    });

    // Clear failed login attempts on successful login
    await this.clearFailedAttempts(input.email);

    // Audit log
    await this.logAudit({
      userId: user.id,
      action: 'user.login',
      resourceType: 'user',
      resourceId: user.id,
      ipAddress: input.ipAddress
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: 900, // 15 minutes in seconds
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    };
  }

  /**
   * Logout user by revoking refresh token
   */
  async logout(userId: string, refreshToken: string): Promise<void> {
    const tokenEntity = await this.refreshTokenRepository.findOne({
      where: { token: refreshToken, userId }
    });

    if (tokenEntity) {
      tokenEntity.revokedAt = new Date();
      await this.refreshTokenRepository.save(tokenEntity);
    }

    // Audit log
    await this.logAudit({
      userId,
      action: 'user.logout',
      resourceType: 'user',
      resourceId: userId
    });
  }

  /**
   * Refresh access token using refresh token
   * REQ-TECH-011
   */
  async refreshAccessToken(refreshToken: string): Promise<{
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
  }> {
    // Verify JWT refresh token
    let payload;
    try {
      payload = verifyRefreshToken(refreshToken);
    } catch (error) {
      throw new Error('Invalid or expired refresh token');
    }

    // Find token in database
    const tokenEntity = await this.refreshTokenRepository.findOne({
      where: { token: refreshToken, userId: payload.userId },
      relations: ['user']
    });

    if (!tokenEntity) {
      throw new Error('Refresh token not found');
    }

    // Check if revoked
    if (tokenEntity.revokedAt) {
      throw new Error('Refresh token has been revoked');
    }

    // Check if expired
    if (tokenEntity.expiresAt < new Date()) {
      throw new Error('Refresh token has expired');
    }

    const user = tokenEntity.user;

    // Create new access token
    const newAccessToken = createAccessToken({
      userId: user.id,
      email: user.email,
      role: user.role
    });

    // Rotate refresh token (delete old, create new)
    await this.refreshTokenRepository.remove(tokenEntity);
    const newRefreshTokenEntity = await this.createRefreshTokenForUser(user.id);
    const newRefreshToken = createRefreshToken({
      userId: user.id,
      tokenId: newRefreshTokenEntity.id
    });

    // Audit log
    await this.logAudit({
      userId: user.id,
      action: 'user.refresh_token',
      resourceType: 'user',
      resourceId: user.id
    });

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: 900
    };
  }

  /**
   * Initiate password reset
   * REQ-AUTH-005, REQ-SEC-010
   */
  async forgotPassword(email: string): Promise<string> {
    const user = await this.userRepository.findOne({
      where: { email }
    });

    // Always return success to avoid email enumeration
    if (!user) {
      // Return fake token to maintain consistent timing
      return randomBytes(32).toString('base64url');
    }

    // Generate secure random token
    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Save token
    const resetToken = this.passwordResetTokenRepository.create({
      userId: user.id,
      token,
      expiresAt
    });

    await this.passwordResetTokenRepository.save(resetToken);

    // Audit log
    await this.logAudit({
      userId: user.id,
      action: 'user.forgot_password',
      resourceType: 'user',
      resourceId: user.id
    });

    return token;
  }

  /**
   * Reset password using token
   * REQ-AUTH-005, REQ-SEC-010
   */
  async resetPassword(token: string, newPassword: string): Promise<void> {
    // Find token
    const resetToken = await this.passwordResetTokenRepository.findOne({
      where: { token },
      relations: ['user']
    });

    if (!resetToken) {
      throw new Error('Invalid or expired reset token');
    }

    // Check if already used
    if (resetToken.usedAt) {
      throw new Error('Reset token has already been used');
    }

    // Check if expired (REQ-SEC-010: 24 hours)
    if (resetToken.expiresAt < new Date()) {
      throw new Error('Reset token has expired');
    }

    // Validate new password complexity
    const passwordValidation = validatePasswordComplexity(newPassword);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join('; '));
    }

    // Hash new password
    const passwordHash = await hashPassword(newPassword);

    // Update user password
    const user = resetToken.user;
    user.passwordHash = passwordHash;
    await this.userRepository.save(user);

    // Mark token as used
    resetToken.usedAt = new Date();
    await this.passwordResetTokenRepository.save(resetToken);

    // Revoke all refresh tokens for security
    await this.refreshTokenRepository.update(
      { userId: user.id, revokedAt: IsNull() },
      { revokedAt: new Date() }
    );

    // Audit log
    await this.logAudit({
      userId: user.id,
      action: 'user.reset_password',
      resourceType: 'user',
      resourceId: user.id
    });
  }

  /**
   * Check if account is locked due to failed attempts
   * REQ-AUTH-004: Lock after 5 failed attempts within 15 minutes
   */
  private async checkAccountLockout(email: string): Promise<boolean> {
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);

    const failedAttempts = await this.failedLoginAttemptRepository.count({
      where: {
        email,
        attemptedAt: MoreThan(fifteenMinutesAgo)
      }
    });

    return failedAttempts >= 5;
  }

  /**
   * Record a failed login attempt
   * REQ-SEC-005
   */
  private async recordFailedAttempt(email: string, ipAddress: string): Promise<void> {
    const attempt = this.failedLoginAttemptRepository.create({
      email,
      ipAddress
    });

    await this.failedLoginAttemptRepository.save(attempt);
  }

  /**
   * Clear failed login attempts on successful login
   */
  private async clearFailedAttempts(email: string): Promise<void> {
    await this.failedLoginAttemptRepository.delete({ email });
  }

  /**
   * Create a new refresh token for a user
   */
  private async createRefreshTokenForUser(userId: string): Promise<RefreshToken> {
    const token = randomBytes(32).toString('base64url');
    const expiresAt = getTokenExpirationDate(process.env.REFRESH_TOKEN_EXPIRY || '7d');

    const refreshToken = this.refreshTokenRepository.create({
      userId,
      token,
      expiresAt
    });

    return this.refreshTokenRepository.save(refreshToken);
  }

  /**
   * Create audit log entry
   * REQ-SEC-008
   */
  private async logAudit(data: {
    userId?: string;
    action: string;
    resourceType?: string;
    resourceId?: string;
    ipAddress?: string;
    userAgent?: string;
    details?: Record<string, any>;
  }): Promise<void> {
    const log = this.auditLogRepository.create(data);
    await this.auditLogRepository.save(log);
  }
}
