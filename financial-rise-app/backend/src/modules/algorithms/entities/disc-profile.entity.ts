import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { Assessment } from '../../assessments/entities/assessment.entity';
import { EncryptedColumnTransformer } from '../../../common/transformers/encrypted-column.transformer';
import { EncryptionService } from '../../../common/services/encryption.service';
import { ConfigService } from '@nestjs/config';

export type DISCType = 'D' | 'I' | 'S' | 'C';
export type ConfidenceLevel = 'high' | 'moderate' | 'low';

// Create encryption transformer instance
// Note: This will be initialized when the entity is loaded by TypeORM
const createEncryptionTransformer = () => {
  const configService = new ConfigService();
  const encryptionService = new EncryptionService(configService);
  return new EncryptedColumnTransformer(encryptionService);
};

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

  @Column({
    type: 'text',
    transformer: createEncryptionTransformer(),
  })
  d_score: number;

  @Column({
    type: 'text',
    transformer: createEncryptionTransformer(),
  })
  i_score: number;

  @Column({
    type: 'text',
    transformer: createEncryptionTransformer(),
  })
  s_score: number;

  @Column({
    type: 'text',
    transformer: createEncryptionTransformer(),
  })
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
