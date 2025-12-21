import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from './User';

export enum EventCategory {
  AUTH = 'auth',
  ASSESSMENT = 'assessment',
  REPORT = 'report',
  ADMIN = 'admin',
  SYSTEM = 'system',
}

export enum Severity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

@Entity('activity_logs')
@Index(['userId'])
@Index(['eventType'])
@Index(['eventCategory'])
@Index(['severity'])
@Index(['createdAt'])
export class ActivityLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', nullable: true })
  userId: string | null;

  @Column({ type: 'varchar', length: 100 })
  eventType: string;

  @Column({
    type: 'varchar',
    length: 50,
    enum: EventCategory,
  })
  eventCategory: EventCategory;

  @Column({ type: 'text' })
  description: string;

  @Column({ type: 'inet', nullable: true })
  ipAddress: string | null;

  @Column({ type: 'text', nullable: true })
  userAgent: string | null;

  @Column({ type: 'jsonb', nullable: true })
  metadata: Record<string, any> | null;

  @Column({
    type: 'varchar',
    length: 20,
    enum: Severity,
    default: Severity.INFO,
  })
  severity: Severity;

  @CreateDateColumn()
  createdAt: Date;

  // Relationships
  @ManyToOne(() => User, (user) => user.activityLogs, {
    onDelete: 'SET NULL',
    nullable: true,
  })
  @JoinColumn({ name: 'user_id' })
  user: User | null;
}
