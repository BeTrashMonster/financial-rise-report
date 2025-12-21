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

export enum DiscType {
  D = 'D',
  I = 'I',
  S = 'S',
  C = 'C',
}

@Entity('disc_profiles')
@Index(['assessmentId'], { unique: true })
@Index(['primaryType'])
export class DiscProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  assessmentId: string;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  dominanceScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  influenceScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  steadinessScore: number;

  @Column({ type: 'decimal', precision: 5, scale: 2 })
  complianceScore: number;

  @Column({
    type: 'varchar',
    length: 20,
    enum: DiscType,
  })
  primaryType: DiscType;

  @Column({
    type: 'varchar',
    length: 20,
    enum: DiscType,
    nullable: true,
  })
  secondaryType: DiscType | null;

  @Column({ type: 'timestamp' })
  calculatedAt: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relationships
  @OneToOne(() => Assessment, (assessment) => assessment.discProfile, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;
}
