import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from './user.entity';

export enum ObjectionType {
  MARKETING = 'marketing',
  ANALYTICS = 'analytics',
  PROFILING = 'profiling',
}

/**
 * GDPR Article 21 - Right to Object to Processing
 *
 * This entity stores user objections to specific types of data processing.
 * Users have the right to object to:
 * - Marketing: Direct marketing communications
 * - Analytics: Use of their data for analytics and statistics
 * - Profiling: Automated decision-making and profiling
 *
 * Note: Users CANNOT object to:
 * - Essential service functions (authentication, core assessment services)
 * - Legal compliance processing (data retention for legal purposes)
 * - Security monitoring (fraud detection, security logging)
 */
@Entity('user_objections')
@Index(['user_id', 'objection_type'], { unique: true }) // Prevent duplicate objections
export class UserObjection {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  user_id: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({
    type: 'enum',
    enum: ObjectionType,
  })
  objection_type: ObjectionType;

  @Column({ type: 'text' })
  reason: string;

  @CreateDateColumn()
  created_at: Date;
}
