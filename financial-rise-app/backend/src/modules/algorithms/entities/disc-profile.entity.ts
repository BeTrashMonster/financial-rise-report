import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Assessment } from '../../assessments/entities/assessment.entity';

export type DISCType = 'D' | 'I' | 'S' | 'C';
export type ConfidenceLevel = 'high' | 'moderate' | 'low';

@Entity('disc_profiles')
export class DISCProfile {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assessment_id: string;

  @ManyToOne(() => Assessment, (assessment) => assessment.disc_profiles, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @Column('float')
  d_score: number;

  @Column('float')
  i_score: number;

  @Column('float')
  s_score: number;

  @Column('float')
  c_score: number;

  @Column({
    type: 'varchar',
    length: 1,
  })
  primary_type: DISCType;

  @Column({
    type: 'varchar',
    length: 1,
    nullable: true,
  })
  secondary_type: DISCType | null;

  @Column({
    type: 'varchar',
    length: 10,
  })
  confidence_level: ConfidenceLevel;

  @CreateDateColumn()
  calculated_at: Date;
}
