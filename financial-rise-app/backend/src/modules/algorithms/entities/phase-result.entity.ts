import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Assessment } from '../../assessments/entities/assessment.entity';

export type FinancialPhase = 'stabilize' | 'organize' | 'build' | 'grow' | 'systemic';

@Entity('phase_results')
export class PhaseResult {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assessment_id: string;

  @ManyToOne(() => Assessment, (assessment) => assessment.phase_results, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @Column('float')
  stabilize_score: number;

  @Column('float')
  organize_score: number;

  @Column('float')
  build_score: number;

  @Column('float')
  grow_score: number;

  @Column('float')
  systemic_score: number;

  @Column({
    type: 'varchar',
    length: 10,
  })
  primary_phase: FinancialPhase;

  @Column('simple-json')
  secondary_phases: string[];

  @Column('boolean', { default: false })
  transition_state: boolean;

  @CreateDateColumn()
  calculated_at: Date;
}
