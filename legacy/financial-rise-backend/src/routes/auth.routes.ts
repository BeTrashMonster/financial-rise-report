import { Router, Request, Response } from 'express';
import { AuthController } from '../controllers/AuthController';
import { authenticate } from '../middleware/auth';
import {
  authLimiter,
  registerLimiter,
  passwordResetLimiter
} from '../middleware/rateLimiter';
import {
  registerValidation,
  loginValidation,
  refreshTokenValidation,
  forgotPasswordValidation,
  resetPasswordValidation
} from '../middleware/validator';

export function createAuthRoutes(authController: AuthController): Router {
  const router = Router();

  /**
   * POST /api/v1/auth/register
   * Public endpoint to register a new consultant
   */
  router.post(
    '/register',
    registerLimiter,
    registerValidation,
    (req: Request, res: Response) => authController.register(req, res)
  );

  /**
   * POST /api/v1/auth/login
   * Public endpoint to authenticate and get tokens
   */
  router.post(
    '/login',
    authLimiter,
    loginValidation,
    (req: Request, res: Response) => authController.login(req, res)
  );

  /**
   * POST /api/v1/auth/logout
   * Protected endpoint to revoke refresh token
   */
  router.post(
    '/logout',
    authenticate,
    refreshTokenValidation,
    (req: Request, res: Response) => authController.logout(req, res)
  );

  /**
   * POST /api/v1/auth/refresh
   * Public endpoint to refresh access token
   */
  router.post(
    '/refresh',
    refreshTokenValidation,
    (req: Request, res: Response) => authController.refresh(req, res)
  );

  /**
   * POST /api/v1/auth/forgot-password
   * Public endpoint to initiate password reset
   */
  router.post(
    '/forgot-password',
    passwordResetLimiter,
    forgotPasswordValidation,
    (req: Request, res: Response) => authController.forgotPassword(req, res)
  );

  /**
   * POST /api/v1/auth/reset-password
   * Public endpoint to complete password reset
   */
  router.post(
    '/reset-password',
    resetPasswordValidation,
    (req: Request, res: Response) => authController.resetPassword(req, res)
  );

  return router;
}
