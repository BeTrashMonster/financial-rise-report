import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  ManyToOne,
  OneToMany,
  OneToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from './User';
import { Response } from './Response';
import { DiscProfile } from './DiscProfile';
import { PhaseResult } from './PhaseResult';
import { Report } from './Report';
import { ChecklistItem } from './ChecklistItem';

export enum AssessmentStatus {
  DRAFT = 'draft',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
}

@Entity('assessments')
@Index(['consultantId'])
@Index(['status'])
@Index(['clientEmail'])
@Index(['createdAt'])
export class Assessment {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  consultantId: string;

  @Column({ type: 'varchar', length: 100 })
  clientName: string;

  @Column({ type: 'varchar', length: 200 })
  clientBusinessName: string;

  @Column({ type: 'varchar', length: 255 })
  clientEmail: string;

  @Column({
    type: 'varchar',
    length: 50,
    enum: AssessmentStatus,
    default: AssessmentStatus.DRAFT,
  })
  status: AssessmentStatus;

  @Column({ type: 'varchar', length: 100, nullable: true })
  entityType: string | null;

  @Column({ type: 'boolean', nullable: true })
  isSCorpOnPayroll: boolean | null;

  @Column({ type: 'integer', nullable: true })
  confidenceBefore: number | null;

  @Column({ type: 'integer', nullable: true })
  confidenceAfter: number | null;

  @Column({ type: 'decimal', precision: 5, scale: 2, default: 0 })
  progressPercentage: number;

  @Column({ type: 'timestamp', nullable: true })
  startedAt: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  completedAt: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  archivedAt: Date | null;

  // Relationships
  @ManyToOne(() => User, (user) => user.assessments, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'consultant_id' })
  consultant: User;

  @OneToMany(() => Response, (response) => response.assessment)
  responses: Response[];

  @OneToOne(() => DiscProfile, (profile) => profile.assessment)
  discProfile: DiscProfile;

  @OneToOne(() => PhaseResult, (result) => result.assessment)
  phaseResult: PhaseResult;

  @OneToMany(() => Report, (report) => report.assessment)
  reports: Report[];

  @OneToMany(() => ChecklistItem, (item) => item.assessment)
  checklistItems: ChecklistItem[];
}
