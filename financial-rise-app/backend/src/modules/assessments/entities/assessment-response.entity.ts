import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Assessment } from './assessment.entity';
import { Question } from '../../questions/entities/question.entity';

@Entity('assessment_responses')
@Index(['assessment_id'])
@Index(['question_id'])
export class AssessmentResponse {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid' })
  assessment_id: string;

  @ManyToOne(() => Assessment, (assessment) => assessment.responses, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'assessment_id' })
  assessment: Assessment;

  @Column({ type: 'varchar', length: 50 })
  question_id: string;

  @ManyToOne(() => Question, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'question_id', referencedColumnName: 'question_key' })
  question: Question;

  @Column({ type: 'jsonb' })
  answer: Record<string, any>;

  @Column({ type: 'boolean', default: false })
  not_applicable: boolean;

  @Column({ type: 'text', nullable: true })
  consultant_notes: string | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  answered_at: Date;
}
