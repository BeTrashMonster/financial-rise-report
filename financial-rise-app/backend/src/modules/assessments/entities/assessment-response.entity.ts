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
import { EncryptedColumnTransformer } from '../../../common/transformers/encrypted-column.transformer';

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

  /**
   * SECURITY: Financial PII - Encrypted at rest (CRIT-005)
   * Contains client financial data (revenue, expenses, debt, etc.)
   * Encrypted using AES-256-GCM to meet GDPR/CCPA compliance
   */
  @Column({
    type: 'text',
    transformer: new EncryptedColumnTransformer(),
  })
  answer: Record<string, any>;

  @Column({ type: 'boolean', default: false })
  not_applicable: boolean;

  @Column({ type: 'text', nullable: true })
  consultant_notes: string | null;

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  answered_at: Date;
}
