import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
import { AssessmentsModule } from './modules/assessments/assessments.module';
import { QuestionsModule } from './modules/questions/questions.module';
import { QuestionnaireModule } from './modules/questionnaire/questionnaire.module';
import { typeOrmConfig } from './config/typeorm.config';
import { AlgorithmsModule } from './modules/algorithms/algorithms.module';
import { ReportsModule } from './reports/reports.module';
import { SecretsModule } from './config/secrets.module';
import { ConsentsModule } from './modules/consents/consents.module';
import { AppController } from './app.controller';
import { DataRetentionService } from './common/services/data-retention.service';
import { Assessment } from './modules/assessments/entities/assessment.entity';
import { Report } from './reports/entities/report.entity';

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
    }),

    // Secrets Management (validates secrets on startup)
    SecretsModule,

    // Database
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: typeOrmConfig,
    }),

    // Rate limiting
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 minute
        limit: 100, // 100 requests per minute
      },
    ]),

    // Scheduled tasks (GDPR data retention)
    ScheduleModule.forRoot(),

    // TypeORM for DataRetentionService
    TypeOrmModule.forFeature([Assessment, Report]),

    // Feature modules
    AuthModule,
    UsersModule,
    AssessmentsModule,
    QuestionsModule,
    QuestionnaireModule,
    AlgorithmsModule,
    ReportsModule,
    ConsentsModule,
  ],
  controllers: [AppController],
  providers: [
    // Apply ThrottlerGuard globally to all routes
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    // GDPR Data Retention Service (HIGH-007)
    DataRetentionService,
  ],
})
export class AppModule {}
