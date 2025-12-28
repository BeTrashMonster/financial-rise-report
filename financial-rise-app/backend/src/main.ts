import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { json, urlencoded } from 'express';
import { AppModule } from './app.module';
import { SecretsValidationService } from './config/secrets-validation.service';
import { getCorsConfig } from './config/cors.config';
import { configureSecurityHeaders } from './config/security-headers.config';
import { CsrfInterceptor } from './common/interceptors/csrf.interceptor';
import { CsrfGuard } from './common/guards/csrf.guard';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CRITICAL: Validate secrets on startup (Work Stream 51 - CRIT-001)
  // This prevents the application from starting with weak or default secrets
  const secretsValidator = app.get(SecretsValidationService);
  secretsValidator.validateSecrets(); // Throws error if validation fails

  // Request Size Limits (Work Stream 64 - MED-003)
  // DoS prevention through payload size restrictions
  // Default limit: 10MB for JSON and URL-encoded payloads
  // Prevents memory exhaustion attacks from oversized requests
  // Note: Apply BEFORE other middleware to reject large payloads early
  app.use(json({ limit: '10mb' }));
  app.use(urlencoded({ extended: true, limit: '10mb' }));

  // Cookie parser middleware (required for CSRF protection)
  app.use(cookieParser());

  // Security Headers (Work Stream 58 - HIGH-009)
  // Comprehensive security headers for XSS, clickjacking, MITM protection
  // Target: A+ grade on securityheaders.com
  configureSecurityHeaders(app);

  // Enable CORS with secure configuration (Work Stream 59 - HIGH-010)
  // Implements origin whitelist, request logging, and explicit method/header configuration
  app.enableCors(getCorsConfig());

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Global CSRF Protection (Work Stream 63 - MED-002)
  // Implements double-submit cookie pattern to prevent CSRF attacks
  // CSRF tokens required for all state-changing requests (POST, PUT, PATCH, DELETE)
  // Safe methods (GET, HEAD, OPTIONS) are exempt from CSRF checks
  const reflector = app.get(Reflector);
  app.useGlobalInterceptors(new CsrfInterceptor());
  app.useGlobalGuards(new CsrfGuard(reflector));

  // API prefix
  app.setGlobalPrefix('api/v1');

  const configService = app.get(ConfigService);
  const port = configService.get('PORT', 3000);

  await app.listen(port);
  console.log(`🚀 Financial RISE API running on port ${port}`);
  console.log(`🛡️  CSRF Protection: ENABLED (double-submit cookie pattern)`);
}

bootstrap();
