import { Injectable, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource } from 'typeorm';
import { User, UserStatus } from './entities/user.entity';
import { Assessment } from '../assessments/entities/assessment.entity';
import { AssessmentResponse } from '../assessments/entities/assessment-response.entity';
import { DISCProfile } from '../algorithms/entities/disc-profile.entity';
import { PhaseResult } from '../algorithms/entities/phase-result.entity';
import { UserObjection, ObjectionType } from './entities/user-objection.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(Assessment)
    private readonly assessmentRepository: Repository<Assessment>,
    @InjectRepository(UserObjection)
    private readonly objectionRepository: Repository<UserObjection>,
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
   * GDPR Article 18 - Right to Restriction of Processing
   * Restrict data processing for a user account
   */
  async restrictProcessing(userId: string, reason?: string): Promise<User> {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Truncate very long reasons to 1000 characters
    const truncatedReason = reason && reason.length > 1000
      ? reason.substring(0, 1000)
      : reason;

    user.processing_restricted = true;
    user.restriction_reason = truncatedReason || null;

    return this.userRepository.save(user);
  }

  /**
   * GDPR Article 18 - Right to Restriction of Processing
   * Lift processing restriction from a user account
   */
  async liftProcessingRestriction(userId: string): Promise<User> {
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    user.processing_restricted = false;
    user.restriction_reason = null;

    return this.userRepository.save(user);
  }

  /**
   * GDPR Article 18 - Right to Restriction of Processing
   * Get processing restriction status for a user
   */
  async getProcessingStatus(userId: string): Promise<any> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      select: ['id', 'processing_restricted', 'restriction_reason', 'updated_at'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return {
      userId: user.id,
      processing_restricted: user.processing_restricted,
      restriction_reason: user.restriction_reason,
      last_updated: user.updated_at,
      gdpr_article: 'Article 18 - Right to Restriction of Processing',
    };
  }

  /**
   * GDPR Article 18 - Right to Restriction of Processing
   * Check if processing is restricted for a user
   */
  async isProcessingRestricted(userId: string): Promise<boolean> {
    const user = await this.findById(userId);
    if (!user) {
      return false;
    }
    return user.processing_restricted === true;
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

  /**
   * GDPR Article 21 - Right to Object to Processing
   * Create a new objection to specific processing type
   */
  async objectToProcessing(
    userId: string,
    objectionType: ObjectionType,
    reason: string,
  ): Promise<any> {
    // Verify user exists
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Validate reason is provided
    if (!reason || reason.trim().length === 0) {
      throw new BadRequestException('Reason is required for objection');
    }

    // Validate objection type
    if (!Object.values(ObjectionType).includes(objectionType)) {
      throw new BadRequestException('Invalid objection type');
    }

    // Check for duplicate objections
    const existingObjection = await this.objectionRepository.findOne({
      where: { user_id: userId, objection_type: objectionType },
    });

    if (existingObjection) {
      throw new BadRequestException('Objection of this type already exists');
    }

    // Create the objection
    const objection = this.objectionRepository.create({
      user_id: userId,
      objection_type: objectionType,
      reason: reason.trim(),
    });

    const savedObjection = await this.objectionRepository.save(objection);

    return {
      ...savedObjection,
      gdpr_article: 'Article 21 - Right to Object',
    };
  }

  /**
   * Get all objections for a user
   */
  async getObjections(userId: string): Promise<UserObjection[]> {
    // Verify user exists
    const user = await this.findById(userId);
    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.objectionRepository.find({
      where: { user_id: userId },
      order: { created_at: 'DESC' },
    });
  }

  /**
   * Withdraw (delete) an objection
   */
  async withdrawObjection(userId: string, objectionId: string): Promise<any> {
    // Find the objection
    const objection = await this.objectionRepository.findOne({
      where: { id: objectionId },
    });

    if (!objection) {
      throw new NotFoundException('Objection not found');
    }

    // Verify the objection belongs to the user
    if (objection.user_id !== userId) {
      throw new ForbiddenException('This objection does not belong to you');
    }

    // Delete the objection
    await this.objectionRepository.delete(objectionId);

    const deletedAt = new Date().toISOString();

    return {
      deleted: true,
      objectionId,
      deletedAt,
      gdpr_article: 'Article 21 - Right to Object (Withdrawal)',
    };
  }

  /**
   * Check if user has a specific objection type
   * Used throughout the application to honor objections
   */
  async hasObjection(userId: string, objectionType: ObjectionType): Promise<boolean> {
    const objection = await this.objectionRepository.findOne({
      where: { user_id: userId, objection_type: objectionType },
    });

    return !!objection;
  }
}
