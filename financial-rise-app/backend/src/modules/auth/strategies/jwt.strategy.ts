import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { UsersService } from '../../users/users.service';
import { TokenBlacklistService } from '../services/token-blacklist.service';

export interface JwtPayload {
  sub: string;
  email: string;
  role: string;
}

/**
 * JWT Authentication Strategy
 *
 * Validates JWT tokens and checks them against the blacklist for immediate revocation.
 *
 * SECURITY ENHANCEMENT (HIGH-003):
 * - Integrated with TokenBlacklistService to enable immediate token revocation
 * - Checks blacklist BEFORE validating user (performance optimization)
 * - Supports logout with immediate token invalidation
 *
 * REMEDIATION FOR: SECURITY-AUDIT-REPORT.md HIGH-003
 * - OWASP A07:2021 - Identification and Authentication Failures
 * - CWE-613 - Insufficient Session Expiration
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private usersService: UsersService,
    private tokenBlacklistService: TokenBlacklistService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
      passReqToCallback: true, // Enable request access to extract token
    });
  }

  async validate(req: Request, payload: JwtPayload) {
    // Extract the raw token from the Authorization header
    const token = this.extractTokenFromHeader(req);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    // Check if token has been blacklisted (revoked via logout)
    const isBlacklisted = await this.tokenBlacklistService.isBlacklisted(token);

    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    // Proceed with normal user validation
    const user = await this.usersService.findById(payload.sub);

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    if (user.status !== 'active') {
      throw new UnauthorizedException('Account is not active');
    }

    return {
      userId: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  }

  /**
   * Extract JWT token from Authorization Bearer header
   * @param request - Express request object
   * @returns JWT token string or null
   */
  private extractTokenFromHeader(request: Request): string | null {
    const authHeader = request.headers?.authorization;

    if (!authHeader) {
      return null;
    }

    const parts = authHeader.split(' ');

    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return null;
    }

    return parts[1];
  }
}
