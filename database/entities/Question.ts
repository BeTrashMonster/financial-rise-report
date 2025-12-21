import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
  Index,
} from 'typeorm';
import { Response } from './Response';

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

interface AnswerOption {
  value: string;
  label: string;
}

interface DiscTraitMapping {
  [optionValue: string]: {
    D?: number;
    I?: number;
    S?: number;
    C?: number;
  };
}

interface PhaseWeightMapping {
  [optionValue: string]: {
    stabilize?: number;
    organize?: number;
    build?: number;
    grow?: number;
    systemic?: number;
  };
}

@Entity('questions')
@Index(['section'])
@Index(['orderIndex'])
@Index(['conditionalParentId'])
export class Question {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'text' })
  questionText: string;

  @Column({
    type: 'varchar',
    length: 50,
    enum: QuestionType,
  })
  questionType: QuestionType;

  @Column({
    type: 'varchar',
    length: 100,
    enum: QuestionSection,
  })
  section: QuestionSection;

  @Column({ type: 'integer' })
  orderIndex: number;

  @Column({ type: 'boolean', default: true })
  isRequired: boolean;

  @Column({ type: 'boolean', default: false })
  isConditional: boolean;

  @Column({ type: 'uuid', nullable: true })
  conditionalParentId: string | null;

  @Column({ type: 'text', nullable: true })
  conditionalTriggerValue: string | null;

  @Column({ type: 'jsonb', nullable: true })
  discTraitMapping: DiscTraitMapping | null;

  @Column({ type: 'jsonb', nullable: true })
  phaseWeightMapping: PhaseWeightMapping | null;

  @Column({ type: 'jsonb', nullable: true })
  answerOptions: AnswerOption[] | null;

  @Column({ type: 'text', nullable: true })
  helpText: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @DeleteDateColumn()
  deletedAt: Date | null;

  // Relationships
  @ManyToOne(() => Question, (question) => question.conditionalChildren, {
    nullable: true,
  })
  @JoinColumn({ name: 'conditional_parent_id' })
  conditionalParent: Question | null;

  @OneToMany(() => Question, (question) => question.conditionalParent)
  conditionalChildren: Question[];

  @OneToMany(() => Response, (response) => response.question)
  responses: Response[];
}
