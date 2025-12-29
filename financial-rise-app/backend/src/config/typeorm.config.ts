import { ConfigService } from '@nestjs/config';
import { TypeOrmModuleOptions } from '@nestjs/typeorm';
import { DataSource, DataSourceOptions } from 'typeorm';
import * as fs from 'fs';
import * as path from 'path';
import { User } from '../modules/users/entities/user.entity';
import { UserObjection } from '../modules/users/entities/user-objection.entity';
import { Assessment } from '../modules/assessments/entities/assessment.entity';
import { AssessmentResponse } from '../modules/assessments/entities/assessment-response.entity';
import { Question } from '../modules/questions/entities/question.entity';
import { RefreshToken } from '../modules/auth/entities/refresh-token.entity';
import { PhaseResult } from '../modules/algorithms/entities/phase-result.entity';
import { DISCProfile } from '../modules/algorithms/entities/disc-profile.entity';
import { Report } from '../reports/entities/report.entity';
import { UserConsent } from '../modules/consents/entities/user-consent.entity';

/**
 * Get SSL configuration for database connection
 * Supports production SSL/TLS with CA certificate validation
 *
 * Environment variables:
 * - DATABASE_SSL: 'true' to enable SSL
 * - DATABASE_SSL_REJECT_UNAUTHORIZED: 'true' to enforce certificate validation
 * - DATABASE_SSL_CA: Path to CA certificate file
 */
function getSSLConfig(configService: ConfigService): any {
  const sslEnabled = configService.get('DATABASE_SSL') === 'true';

  if (!sslEnabled) {
    return false;
  }

  const rejectUnauthorized = configService.get('DATABASE_SSL_REJECT_UNAUTHORIZED') === 'true';
  const caPath = configService.get('DATABASE_SSL_CA');

  const sslConfig: any = {
    rejectUnauthorized,
  };

  // Load CA certificate if path is provided
  if (caPath) {
    try {
      // Check if file exists before reading
      if (fs.existsSync(caPath)) {
        sslConfig.ca = fs.readFileSync(caPath).toString();
      } else {
        // Log warning but don't fail - connection attempt will reveal if cert is actually needed
        console.warn(`[TypeORM SSL] CA certificate file not found: ${caPath}`);
      }
    } catch (error) {
      // Log error but don't throw - allow TypeORM to handle connection failure
      console.error(`[TypeORM SSL] Error reading CA certificate from ${caPath}:`, error);
    }
  }

  return sslConfig;
}

export const typeOrmConfig = (
  configService: ConfigService,
): TypeOrmModuleOptions => ({
  type: 'postgres',
  host: configService.get('DATABASE_HOST', 'localhost'),
  port: configService.get('DATABASE_PORT', 5432),
  username: configService.get('DATABASE_USER', 'financial_rise'),
  password: configService.get('DATABASE_PASSWORD'),
  database: configService.get('DATABASE_NAME', 'financial_rise_db'),
  entities: [
    User,
    UserObjection,
    Assessment,
    AssessmentResponse,
    Question,
    RefreshToken,
    PhaseResult,
    DISCProfile,
    Report,
    UserConsent,
  ],
  migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
  synchronize: false, // Never use in production
  logging: configService.get('NODE_ENV') === 'development',
  ssl: getSSLConfig(configService),
});

// DataSource for migrations
const config = new ConfigService();
const dataSourceOptions: DataSourceOptions = {
  type: 'postgres',
  host: config.get('DATABASE_HOST', 'localhost'),
  port: parseInt(config.get('DATABASE_PORT', '5432')),
  username: config.get('DATABASE_USER', 'financial_rise'),
  password: config.get('DATABASE_PASSWORD', 'financial_rise_dev'),
  database: config.get('DATABASE_NAME', 'financial_rise_dev'),
  entities: [
    User,
    UserObjection,
    Assessment,
    AssessmentResponse,
    Question,
    RefreshToken,
    PhaseResult,
    DISCProfile,
    Report,
    UserConsent,
  ],
  migrations: [__dirname + '/../database/migrations/*{.ts,.js}'],
  synchronize: false,
  logging: true,
  ssl: getSSLConfig(config) as any,
};

const dataSource = new DataSource(dataSourceOptions);
export default dataSource;
