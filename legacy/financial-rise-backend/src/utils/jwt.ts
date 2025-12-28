import jwt from 'jsonwebtoken';
import { UserRole } from '../database/entities/User';

const JWT_SECRET = (process.env.JWT_SECRET || 'test-secret') as string;
const JWT_REFRESH_SECRET = (process.env.JWT_REFRESH_SECRET || 'test-refresh-secret') as string;
const ACCESS_TOKEN_EXPIRY: string | number = process.env.ACCESS_TOKEN_EXPIRY || '15m';
const REFRESH_TOKEN_EXPIRY: string | number = process.env.REFRESH_TOKEN_EXPIRY || '7d';

export interface AccessTokenPayload {
  userId: string;
  email: string;
  role: UserRole;
}

export interface RefreshTokenPayload {
  userId: string;
  tokenId: string;
}

/**
 * Create a new JWT access token
 * @param payload - Token payload
 * @returns Signed JWT token
 */
export function createAccessToken(payload: AccessTokenPayload): string {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY as jwt.SignOptions['expiresIn'],
    algorithm: 'HS256'
  } as jwt.SignOptions);
}

/**
 * Create a new JWT refresh token
 * @param payload - Token payload
 * @returns Signed JWT token
 */
export function createRefreshToken(payload: RefreshTokenPayload): string {
  return jwt.sign(payload, JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_EXPIRY as jwt.SignOptions['expiresIn'],
    algorithm: 'HS256'
  } as jwt.SignOptions);
}

/**
 * Verify and decode an access token
 * @param token - JWT token
 * @returns Decoded payload
 * @throws Error if token is invalid or expired
 */
export function verifyAccessToken(token: string): AccessTokenPayload {
  try {
    return jwt.verify(token, JWT_SECRET) as AccessTokenPayload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Access token has expired');
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid access token');
    }
    throw error;
  }
}

/**
 * Verify and decode a refresh token
 * @param token - JWT token
 * @returns Decoded payload
 * @throws Error if token is invalid or expired
 */
export function verifyRefreshToken(token: string): RefreshTokenPayload {
  try {
    return jwt.verify(token, JWT_REFRESH_SECRET) as RefreshTokenPayload;
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      throw new Error('Refresh token has expired');
    }
    if (error instanceof jwt.JsonWebTokenError) {
      throw new Error('Invalid refresh token');
    }
    throw error;
  }
}

/**
 * Calculate token expiration date
 * @param expiry - Expiry string (e.g., '15m', '7d')
 * @returns Expiration date
 */
export function getTokenExpirationDate(expiry: string): Date {
  const value = parseInt(expiry.slice(0, -1), 10);
  const unit = expiry.slice(-1);

  const now = new Date();

  switch (unit) {
    case 'm': // minutes
      return new Date(now.getTime() + value * 60 * 1000);
    case 'h': // hours
      return new Date(now.getTime() + value * 60 * 60 * 1000);
    case 'd': // days
      return new Date(now.getTime() + value * 24 * 60 * 60 * 1000);
    default:
      throw new Error(`Invalid expiry unit: ${unit}`);
  }
}
