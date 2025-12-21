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
import { User } from './User';

@Entity('scheduler_links')
@Index(['consultantId'])
@Index(['isActive'])
export class SchedulerLink {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  consultantId: string;

  @Column({ type: 'varchar', length: 100 })
  meetingTypeLabel: string;

  @Column({ type: 'text' })
  schedulerUrl: string;

  @Column({ type: 'integer', nullable: true })
  durationMinutes: number | null;

  @Column({ type: 'text', array: true, nullable: true })
  recommendedForPhases: string[] | null;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'integer', default: 0 })
  displayOrder: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date | null;

  // Relationships
  @ManyToOne(() => User, (user) => user.schedulerLinks, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'consultant_id' })
  consultant: User;
}
