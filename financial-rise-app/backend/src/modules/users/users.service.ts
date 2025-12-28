import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { User, UserStatus } from './entities/user.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { DISCProfile } from '../algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../algorithms/entities/phase-result.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Assessment)
    private readonly assessmentRepository: Repository<Assessment>,
    private readonly dataSource: DataSource,
  ) {}

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findById(id: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }

  async create(userData: Partial<User>): Promise<User> {
    const user = this.userRepository.create(userData);
    return this.userRepository.save(user);
  }

  async update(id: string, userData: Partial<User>): Promise<User> {
    const user = await this.findById(id);
    if (!user) {
      throw new NotFoundException('User not found');
    }
    Object.assign(user, userData);
    return this.userRepository.save(user);
  }

  async incrementFailedLoginAttempts(userId: string): Promise<void> {
    const user = await this.findById(userId);
    if (!user) return;

    user.failed_login_attempts += 1;

    // Lock account after 5 failed attempts for 30 minutes
    if (user.failed_login_attempts >= 5) {
      user.status = UserStatus.LOCKED;
      user.locked_until = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
    }

    await this.userRepository.save(user);
  }

  async resetFailedLoginAttempts(userId: string): Promise<void> {
    await this.userRepository.update(userId, {
      failed_login_attempts: 0,
      status: UserStatus.ACTIVE,
      locked_until: null,
    });
  }

  async isAccountLocked(user: User): Promise<boolean> {
    if (user.status !== UserStatus.LOCKED) {
      return false;
    }

    // Check if lock has expired
    if (user.locked_until && new Date() > user.locked_until) {
      await this.resetFailedLoginAttempts(user.id);
      return false;
    }

    return true;
  }

  async updateLastLogin(userId: string): Promise<void> {
    await this.userRepository.update(userId, {
      last_login_at: new Date(),
    });
  }

  async setResetPasswordToken(
    userId: string,
    token: string,
    expiresIn: number = 3600000, // 1 hour
  ): Promise<void> {
    await this.userRepository.update(userId, {
      reset_password_token: token,
      reset_password_expires: new Date(Date.now() + expiresIn),
    });
  }

  async findByResetToken(token: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { reset_password_token: token },
    });
  }

  async clearResetPasswordToken(userId: string): Promise<void> {
    await this.userRepository.update(userId, {
      reset_password_token: null,
      reset_password_expires: null,
    });
  }

  async updateRefreshToken(userId: string, refreshToken: string | null): Promise<void> {
    await this.userRepository.update(userId, { refresh_token: refreshToken });
  }

  async findByRefreshToken(refreshToken: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { refresh_token: refreshToken } });
  }

  /**
   * GDPR Article 15 - Right to Access
   * Export all user data in machine-readable JSON format
   */
  async exportUserData(userId: string): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: [
        'id',
        'email',
        'first_name',
        'last_name',
        'role',
        'status',
        'failed_login_attempts',
        'created_at',
        'updated_at',
        'last_login_at',
      ],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Fetch all assessments with related data
    const assessments = await this.assessmentRepository.find({
      where: { consultant_id: userId },
      relations: ['responses', 'disc_profiles', 'phase_results'],
    });

    // Remove sensitive fields from user data
    const exportedUser = {
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      role: user.role,
      status: user.status,
      created_at: user.created_at,
      updated_at: user.updated_at,
      last_login_at: user.last_login_at,
    };

    return {
      user: exportedUser,
      assessments: assessments,
      export_metadata: {
        exported_at: new Date().toISOString(),
        export_format: 'JSON',
        gdpr_article: 'Article 15 - Right to Access',
      },
    };
  }

  /**
   * GDPR Article 17 - Right to Erasure
   * Cascade delete user and all related data
   */
  async deleteUserCascade(userId: string): Promise<any> {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const user = await queryRunner.manager.findOne(User, {
        where: { id: userId },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Count data before deletion for audit log
      const assessments = await queryRunner.manager.find(Assessment, {
        where: { consultant_id: userId },
      });
      const assessmentIds = assessments.map((a) => a.id);

      let deletedResponses = 0;
      let deletedDISCProfiles = 0;
      let deletedPhaseResults = 0;

      if (assessmentIds.length > 0) {
        // Count related records
        deletedResponses = await queryRunner.manager.count(AssessmentResponse, {
          where: assessmentIds.map((id) => ({ assessment_id: id })),
        });
        deletedDISCProfiles = await queryRunner.manager.count(DISCProfile, {
          where: assessmentIds.map((id) => ({ assessment_id: id })),
        });
        deletedPhaseResults = await queryRunner.manager.count(PhaseResult, {
          where: assessmentIds.map((id) => ({ assessment_id: id })),
        });

        // Delete assessment-related data (cascade will handle this, but explicit for clarity)
        await queryRunner.manager.delete(
          AssessmentResponse,
          assessmentIds.map((id) => ({ assessment_id: id })),
        );
        await queryRunner.manager.delete(
          DISCProfile,
          assessmentIds.map((id) => ({ assessment_id: id })),
        );
        await queryRunner.manager.delete(
          PhaseResult,
          assessmentIds.map((id) => ({ assessment_id: id })),
        );
        await queryRunner.manager.delete(Assessment, {
          consultant_id: userId,
        });
      }

      // Delete user (hard delete for GDPR compliance)
      await queryRunner.manager.delete(User, { id: userId });

      await queryRunner.commitTransaction();

      const deletedAt = new Date().toISOString();

      return {
        deleted: true,
        deletionType: 'HARD_DELETE',
        deletedAt,
        deletedAssessments: assessments.length,
        deletedResponses,
        deletedDISCProfiles,
        deletedPhaseResults,
        deletedEncryptedData: true,
        auditLog: {
          action: 'USER_DELETED',
          userId: userId,
          timestamp: deletedAt,
          reason: 'GDPR Article 17 - User requested deletion',
        },
        gdpr_article: 'Article 17 - Right to Erasure',
      };
    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }
}
