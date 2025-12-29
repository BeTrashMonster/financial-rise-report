import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  Index,
} from 'typeorm';

export enum QuestionType {
  SINGLE_CHOICE = 'single_choice',
  MULTIPLE_CHOICE = 'multiple_choice',
  RATING = 'rating',
  TEXT = 'text',
}

export enum QuestionSection {
  STABILIZE = 'stabilize',
  ORGANIZE = 'organize',
  BUILD = 'build',
  GROW = 'grow',
  SYSTEMIC = 'systemic',
  DISC = 'disc',
  METADATA = 'metadata',
}

@Entity('questions')
@Index(['question_key'], { unique: true })
@Index(['question_type'])
@Index(['display_order'])
export class Question {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 50, unique: true })
  question_key: string;

  @Column({ type: 'text' })
  question_text: string;

  @Column({
    type: 'enum',
    enum: QuestionType,
  })
  question_type: QuestionType;

  @Column({ type: 'jsonb', nullable: true })
  options: Record<string, any> | null;

  @Column({ type: 'boolean', default: true })
  required: boolean;

  @Column({ type: 'int' })
  display_order: number;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}
