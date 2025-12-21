import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { Assessment } from './Assessment';
import { Question } from './Question';

@Entity('responses')
@Unique(['assessmentId', 'questionId'])
@Index(['assessmentId'])
@Index(['questionId'])
export class Response {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assessmentId: string;

  @Column({ type: 'uuid' })
  questionId: string;

  @Column({ type: 'text', nullable: true })
  answerValue: string | null;

  @Column({ type: 'integer', nullable: true })
  answerNumeric: number | null;

  @Column({ type: 'boolean', default: false })
  isNotApplicable: boolean;

  @Column({ type: 'text', nullable: true })
  consultantNotes: string | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relationships
  @ManyToOne(() => Assessment, (assessment) => assessment.responses, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @ManyToOne(() => Question, (question) => question.responses, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'question_id' })
  question: Question;
}
