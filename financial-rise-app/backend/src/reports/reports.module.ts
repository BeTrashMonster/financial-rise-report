import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { ReportTemplateService } from './services/report-template.service';
import { ReportGenerationService } from './services/report-generation.service';
import { ReportsController } from './reports.controller';
import { Report } from './entities/report.entity';
import { AlgorithmsModule } from '../modules/algorithms/algorithms.module';
import { AssessmentsModule } from '../modules/assessments/assessments.module';

@Module({
  imports: [TypeOrmModule.forFeature([Report]), ConfigModule, AlgorithmsModule, AssessmentsModule],
  providers: [ReportTemplateService, ReportGenerationService],
  controllers: [ReportsController],
  exports: [ReportTemplateService, ReportGenerationService],
})
export class ReportsModule {}
