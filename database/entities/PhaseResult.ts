import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Assessment } from './Assessment';

export enum FinancialPhase {
  STABILIZE = 'stabilize',
  ORGANIZE = 'organize',
  BUILD = 'build',
  GROW = 'grow',
  SYSTEMIC = 'systemic',
}

@Entity('phase_results')
@Index(['assessmentId'], { unique: true })
@Index(['primaryPhase'])
export class PhaseResult {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  assessmentId: string;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  stabilizeScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  organizeScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  buildScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  growScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  systemicScore: number;

  @Column({
    type: 'varchar',
    length: 50,
    enum: FinancialPhase,
  })
  primaryPhase: FinancialPhase;

  @Column({ type: 'text', array: true, nullable: true })
  secondaryPhases: string[] | null;

  @Column({ type: 'timestamp' })
  calculatedAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relationships
  @OneToOne(() => Assessment, (assessment) => assessment.phaseResult, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;
}
