import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  Index,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';

/**
 * RefreshToken Entity
 *
 * Stores refresh tokens in a separate table to support:
 * - Multiple devices per user (user can be logged in on multiple devices)
 * - Token revocation (individual tokens can be revoked)
 * - Session management (view all active sessions, revoke all sessions)
 * - Audit trail (track when and where tokens were created)
 *
 * This is more secure than storing a single refresh_token in the users table.
 */
@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'uuid', name: 'user_id' })
  @Index()  // Create index on this column
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ type: 'varchar', length: 255, unique: true })
  token: string;

  @Column({ type: 'timestamp', name: 'expires_at' })
  expiresAt: Date;

  @Column({ type: 'timestamp', nullable: true, name: 'revoked_at' })
  revokedAt: Date | null;

  @Column({ type: 'varchar', length: 50, nullable: true, name: 'device_info' })
  deviceInfo: string | null;

  @Column({ type: 'varchar', length: 45, nullable: true, name: 'ip_address' })
  ipAddress: string | null;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;
}
