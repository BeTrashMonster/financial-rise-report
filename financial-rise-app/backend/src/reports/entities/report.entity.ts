import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

export type ReportType = 'consultant' | 'client';
export type ReportStatus = 'generating' | 'completed' | 'failed';

@Entity('reports')
export class Report {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', name: 'assessment_id' })
  assessmentId: string;

  @Column({ type: 'uuid', name: 'consultant_id' })
  consultantId: string;

  @Column({
    type: 'enum',
    enum: ['consultant', 'client'],
    name: 'report_type',
  })
  reportType: ReportType;

  @Column({
    type: 'enum',
    enum: ['generating', 'completed', 'failed'],
    default: 'generating',
  })
  status: ReportStatus;

  @Column({ type: 'text', nullable: true, name: 'file_url' })
  fileUrl: string | null;

  @Column({ type: 'int', nullable: true, name: 'file_size_bytes' })
  fileSizeBytes: number | null;

  @Column({ type: 'timestamp', nullable: true, name: 'generated_at' })
  generatedAt: Date | null;

  @Column({ type: 'timestamp', nullable: true, name: 'expires_at' })
  expiresAt: Date | null;

  @Column({ type: 'text', nullable: true })
  error: string | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
