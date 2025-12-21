import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  OneToMany,
  Index,
} from 'typeorm';
import { Assessment } from './Assessment';
import { Report } from './Report';
import { ChecklistItem } from './ChecklistItem';
import { ConsultantSettings } from './ConsultantSettings';
import { SchedulerLink } from './SchedulerLink';
import { ActivityLog } from './ActivityLog';

export enum UserRole {
  CONSULTANT = 'consultant',
  ADMIN = 'admin',
}

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255, unique: true })
  @Index()
  email: string;

  @Column({ type: 'varchar', length: 255 })
  passwordHash: string;

  @Column({
    type: 'varchar',
    length: 50,
    enum: UserRole,
  })
  role: UserRole;

  @Column({ type: 'varchar', length: 100 })
  firstName: string;

  @Column({ type: 'varchar', length: 100 })
  lastName: string;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'integer', default: 0 })
  failedLoginAttempts: number;

  @Column({ type: 'timestamp', nullable: true })
  accountLockedUntil: Date | null;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  passwordResetToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  passwordResetExpires: Date | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date | null;

  // Relationships
  @OneToMany(() => Assessment, (assessment) => assessment.consultant)
  assessments: Assessment[];

  @OneToMany(() => Report, (report) => report.generatedBy)
  generatedReports: Report[];

  @OneToMany(() => ChecklistItem, (item) => item.createdBy)
  checklistItems: ChecklistItem[];

  @OneToMany(() => ConsultantSettings, (settings) => settings.consultant)
  settings: ConsultantSettings[];

  @OneToMany(() => SchedulerLink, (link) => link.consultant)
  schedulerLinks: SchedulerLink[];

  @OneToMany(() => ActivityLog, (log) => log.user)
  activityLogs: ActivityLog[];
}
