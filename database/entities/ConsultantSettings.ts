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
import { User } from './User';

interface EmailTemplate {
  subject: string;
  body: string;
  variables: string[];
}

interface EmailTemplates {
  [templateName: string]: EmailTemplate;
}

@Entity('consultant_settings')
@Index(['consultantId'], { unique: true })
export class ConsultantSettings {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', unique: true })
  consultantId: string;

  @Column({ type: 'varchar', length: 200, nullable: true })
  companyName: string | null;

  @Column({ type: 'text', nullable: true })
  logoUrl: string | null;

  @Column({ type: 'varchar', length: 7, nullable: true })
  brandColor: string | null;

  @Column({ type: 'text', nullable: true })
  emailSignature: string | null;

  @Column({ type: 'jsonb', nullable: true })
  emailTemplates: EmailTemplates | null;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  // Relationships
  @OneToOne(() => User, (user) => user.settings, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'consultant_id' })
  consultant: User;
}
