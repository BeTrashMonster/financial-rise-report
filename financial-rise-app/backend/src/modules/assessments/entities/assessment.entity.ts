import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  Index,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { AssessmentResponse } from './assessment-response.entity';
import { DISCProfile } from '../../algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../../algorithms/entities/phase-result.entity';

export enum AssessmentStatus {
  DRAFT = 'draft',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
}

@Entity('assessments')
@Index(['consultant_id'])
@Index(['status'])
@Index(['updated_at'])
@Index(['client_email'])
export class Assessment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  consultant_id: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'consultant_id' })
  consultant: User;

  @Column({ type: 'varchar', length: 100 })
  client_name: string;

  @Column({ type: 'varchar', length: 100 })
  business_name: string;

  @Column({ type: 'varchar', length: 255 })
  client_email: string;

  @Column({
    type: 'enum',
    enum: AssessmentStatus,
    default: AssessmentStatus.DRAFT,
  })
  status: AssessmentStatus;

  @Column({ type: 'decimal', precision: 5, scale: 2, default: 0 })
  progress: number;

  @Column({ type: 'text', nullable: true })
  notes: string | null;

  @OneToMany(() => AssessmentResponse, (response) => response.assessment, {
    cascade: true,
  })
  responses: AssessmentResponse[];

  @OneToMany(() => DISCProfile, (profile) => profile.assessment, {
    cascade: true,
  })
  disc_profiles: DISCProfile[];

  @OneToMany(() => PhaseResult, (result) => result.assessment, {
    cascade: true,
  })
  phase_results: PhaseResult[];

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;

  @Column({ type: 'timestamp', nullable: true })
  started_at: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  completed_at: Date | null;

  @DeleteDateColumn()
  deleted_at: Date | null;
}
