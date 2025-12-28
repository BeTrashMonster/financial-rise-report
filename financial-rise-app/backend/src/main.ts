import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { SecretsValidationService } from './config/secrets-validation.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // CRITICAL: Validate secrets on startup (Work Stream 51 - CRIT-001)
  // This prevents the application from starting with weak or default secrets
  const secretsValidator = app.get(SecretsValidationService);
  secretsValidator.validateSecrets(); // Throws error if validation fails

  // Security middleware
  app.use(helmet());

  // Enable CORS
  app.enableCors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3001',
    credentials: true,
  });

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

  // API prefix
  app.setGlobalPrefix('api/v1');

  const configService = app.get(ConfigService);
  const port = configService.get('PORT', 3000);

  await app.listen(port);
  console.log(`🚀 Financial RISE API running on port ${port}`);
}

bootstrap();
