import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Assessment } from './Assessment';
import { User } from './User';
import { FinancialPhase } from './PhaseResult';

export enum CompletedBy {
  CONSULTANT = 'consultant',
  CLIENT = 'client',
}

export enum Priority {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
}

@Entity('checklist_items')
@Index(['assessmentId'])
@Index(['phaseCategory'])
@Index(['isCompleted'])
export class ChecklistItem {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assessmentId: string;

  @Column({ type: 'text' })
  itemText: string;

  @Column({ type: 'integer' })
  itemOrder: number;

  @Column({
    type: 'varchar',
    length: 50,
    enum: FinancialPhase,
    nullable: true,
  })
  phaseCategory: FinancialPhase | null;

  @Column({ type: 'boolean', default: false })
  isCompleted: boolean;

  @Column({ type: 'timestamp', nullable: true })
  completedAt: Date | null;

  @Column({
    type: 'varchar',
    length: 50,
    enum: CompletedBy,
    nullable: true,
  })
  completedBy: CompletedBy | null;

  @Column({
    type: 'varchar',
    length: 20,
    enum: Priority,
    nullable: true,
  })
  priority: Priority | null;

  @Column({ type: 'date', nullable: true })
  dueDate: Date | null;

  @Column({ type: 'uuid' })
  createdById: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date | null;

  // Relationships
  @ManyToOne(() => Assessment, (assessment) => assessment.checklistItems, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @ManyToOne(() => User, (user) => user.checklistItems)
  @JoinColumn({ name: 'created_by_id' })
  createdBy: User;
}
