import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './modules/auth/auth.module';
import { UsersModule } from './modules/users/users.module';
// Temporarily disabled until entities are fixed (not part of Work Stream 7)
// import { AssessmentsModule } from './modules/assessments/assessments.module';
// import { QuestionsModule } from './modules/questions/questions.module';
import { typeOrmConfig } from './config/typeorm.config';
import { AlgorithmsModule } from './modules/algorithms/algorithms.module';
// ReportsModule will be added in Work Stream 11

@Module({
  imports: [
    // Configuration
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env.local', '.env'],
    }),

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

    // Feature modules
    AuthModule,
    UsersModule,
    // Temporarily disabled until entities are fixed (not part of Work Stream 7)
    // AssessmentsModule,
    // QuestionsModule,
    AlgorithmsModule,
    // ReportsModule will be added in Work Stream 11
  ],
})
export class AppModule {}
