import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Assessment } from './Assessment';
import { User } from './User';

export enum ReportType {
  CONSULTANT = 'consultant',
  CLIENT = 'client',
}

@Entity('reports')
@Index(['assessmentId'])
@Index(['reportType'])
@Index(['shareToken'], { unique: true })
@Index(['createdAt'])
export class Report {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assessmentId: string;

  @Column({
    type: 'varchar',
    length: 50,
    enum: ReportType,
  })
  reportType: ReportType;

  @Column({ type: 'text' })
  fileUrl: string;

  @Column({ type: 'bigint', nullable: true })
  fileSizeBytes: number | null;

  @Column({ type: 'integer', nullable: true })
  pageCount: number | null;

  @Column({ type: 'uuid' })
  generatedById: string;

  @Column({ type: 'boolean', default: false })
  isShared: boolean;

  @Column({ type: 'varchar', length: 255, nullable: true, unique: true })
  shareToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  shareExpiresAt: Date | null;

  @Column({ type: 'integer', default: 0 })
  viewCount: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relationships
  @ManyToOne(() => Assessment, (assessment) => assessment.reports, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @ManyToOne(() => User, (user) => user.generatedReports)
  @JoinColumn({ name: 'generated_by_id' })
  generatedBy: User;
}
