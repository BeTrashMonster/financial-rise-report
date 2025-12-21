import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AlgorithmsController } from './algorithms.controller';
import { AlgorithmsService } from './algorithms.service';
import { DISCCalculatorService } from './disc/disc-calculator.service';
import { PhaseCalculatorService } from './phase/phase-calculator.service';
import { DISCProfile } from './entities/disc-profile.entity';
import { PhaseResult } from './entities/phase-result.entity';

/**
 * Algorithms Module
 *
 * Provides DISC personality profiling and financial phase determination
 * services for the Financial RISE Report application.
 *
 * Implements Work Stream 7: DISC & Phase Algorithms
 */
@Module({
  imports: [
    TypeOrmModule.forFeature([DISCProfile, PhaseResult]),
  ],
  controllers: [AlgorithmsController],
  providers: [AlgorithmsService, DISCCalculatorService, PhaseCalculatorService],
  exports: [AlgorithmsService, DISCCalculatorService, PhaseCalculatorService],
})
export class AlgorithmsModule {}
