import { Repository, FindOptionsWhere, Like, Between, MoreThan, LessThan, IsNull } from 'typeorm';
import { User, UserRole } from '../database/entities/User';
import { AuditLog } from '../database/entities/AuditLog';
import { RefreshToken } from '../database/entities/RefreshToken';
import { hashPassword, validatePasswordComplexity } from '../utils/password';

export interface ListUsersInput {
  page?: number;
  limit?: number;
  role?: UserRole;
  isActive?: boolean;
  search?: string;
}

export interface CreateUserInput {
  email: string;
  password: string;
  role: UserRole;
}

export interface UpdateUserInput {
  email?: string;
  role?: UserRole;
  isActive?: boolean;
}

export interface ListActivityLogsInput {
  page?: number;
  limit?: number;
  userId?: string;
  action?: string;
  startDate?: Date;
  endDate?: Date;
  resourceType?: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

export class AdminService {
  constructor(
    private userRepository: Repository<User>,
    private auditLogRepository: Repository<AuditLog>,
    private refreshTokenRepository: Repository<RefreshToken>
  ) {}

  /**
   * List all users with pagination and filtering
   * REQ-ADMIN-001
   */
  async listUsers(input: ListUsersInput, adminId: string): Promise<PaginatedResponse<User>> {
    const page = input.page || 1;
    const limit = Math.min(input.limit || 20, 100); // Max 100
    const skip = (page - 1) * limit;

    // Build where clause
    const where: FindOptionsWhere<User> = {};

    if (input.role) {
      where.role = input.role;
    }

    if (input.isActive !== undefined) {
      where.isActive = input.isActive;
    }

    if (input.search) {
      where.email = Like(`%${input.search}%`);
    }

    // Get total count
    const total = await this.userRepository.count({ where });

    // Get paginated results
    const users = await this.userRepository.find({
      where,
      skip,
      take: limit,
      order: {
        createdAt: 'DESC'
      },
      select: {
        id: true,
        email: true,
        role: true,
        isActive: true,
        emailVerified: true,
        createdAt: true,
        updatedAt: true,
        lastLoginAt: true
        // Exclude passwordHash
      }
    });

    // Audit log
    await this.logAudit({
      userId: adminId,
      action: 'admin.users.listed',
      resourceType: 'admin',
      details: {
        filters: input,
        resultCount: users.length
      }
    });

    return {
      data: users,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  }

  /**
   * Create a new user account
   * REQ-ADMIN-002
   */
  async createUser(input: CreateUserInput, adminId: string): Promise<User> {
    // Check if email already exists
    const existingUser = await this.userRepository.findOne({
      where: { email: input.email }
    });

    if (existingUser) {
      throw new Error('Email already registered');
    }

    // Validate password complexity
    const passwordValidation = validatePasswordComplexity(input.password);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join('; '));
    }

    // Hash password
    const passwordHash = await hashPassword(input.password);

    // Create user
    const user = this.userRepository.create({
      email: input.email,
      passwordHash,
      role: input.role,
      isActive: true,
      emailVerified: false
    });

    await this.userRepository.save(user);

    // Audit log
    await this.logAudit({
      userId: adminId,
      action: 'admin.user.created',
      resourceType: 'user',
      resourceId: user.id,
      details: {
        email: user.email,
        role: user.role
      }
    });

    // Remove password hash from response
    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword as User;
  }

  /**
   * Update user account
   * REQ-ADMIN-003
   */
  async updateUser(
    userId: string,
    input: UpdateUserInput,
    adminId: string
  ): Promise<User> {
    // Find user
    const user = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Prevent admin from changing own role
    if (userId === adminId && input.role && input.role !== user.role) {
      throw new Error('Cannot change your own role');
    }

    // If deactivating, ensure not the last admin
    if (input.isActive === false && user.role === UserRole.ADMIN) {
      const activeAdminCount = await this.userRepository.count({
        where: {
          role: UserRole.ADMIN,
          isActive: true
        }
      });

      if (activeAdminCount <= 1) {
        throw new Error('Cannot deactivate the last admin user');
      }
    }

    // If changing email, check uniqueness
    if (input.email && input.email !== user.email) {
      const existingUser = await this.userRepository.findOne({
        where: { email: input.email }
      });

      if (existingUser) {
        throw new Error('Email already in use');
      }
    }

    // Track changes for audit log
    const changes: Record<string, any> = {};

    // Update fields
    if (input.email && input.email !== user.email) {
      changes.email = { from: user.email, to: input.email };
      user.email = input.email;
    }

    if (input.role && input.role !== user.role) {
      changes.role = { from: user.role, to: input.role };
      user.role = input.role;

      // Revoke all refresh tokens when role changes
      await this.refreshTokenRepository.update(
        { userId: user.id, revokedAt: IsNull() },
        { revokedAt: new Date() }
      );
    }

    if (input.isActive !== undefined && input.isActive !== user.isActive) {
      changes.isActive = { from: user.isActive, to: input.isActive };
      user.isActive = input.isActive;

      // If deactivating, revoke all refresh tokens
      if (!input.isActive) {
        await this.refreshTokenRepository.update(
          { userId: user.id, revokedAt: IsNull() },
          { revokedAt: new Date() }
        );
      }
    }

    await this.userRepository.save(user);

    // Audit log
    await this.logAudit({
      userId: adminId,
      action: 'admin.user.updated',
      resourceType: 'user',
      resourceId: user.id,
      details: {
        changes
      }
    });

    // Remove password hash from response
    const { passwordHash: _, ...userWithoutPassword } = user;
    return userWithoutPassword as User;
  }

  /**
   * Delete user account
   */
  async deleteUser(userId: string, adminId: string): Promise<void> {
    // Prevent admin from deleting own account
    if (userId === adminId) {
      throw new Error('Cannot delete your own account');
    }

    // Find user
    const user = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Ensure not deleting the last admin
    if (user.role === UserRole.ADMIN) {
      const adminCount = await this.userRepository.count({
        where: { role: UserRole.ADMIN }
      });

      if (adminCount <= 1) {
        throw new Error('Cannot delete the last admin user');
      }
    }

    // Audit log before deletion
    await this.logAudit({
      userId: adminId,
      action: 'admin.user.deleted',
      resourceType: 'user',
      resourceId: user.id,
      details: {
        email: user.email,
        role: user.role
      }
    });

    // Delete user (cascade will delete refresh tokens and password reset tokens)
    await this.userRepository.remove(user);
  }

  /**
   * Reset user password (admin-initiated)
   * REQ-ADMIN-004
   */
  async resetUserPassword(
    userId: string,
    newPassword: string,
    adminId: string
  ): Promise<void> {
    // Find user
    const user = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!user) {
      throw new Error('User not found');
    }

    // Validate password complexity
    const passwordValidation = validatePasswordComplexity(newPassword);
    if (!passwordValidation.valid) {
      throw new Error(passwordValidation.errors.join('; '));
    }

    // Hash new password
    const passwordHash = await hashPassword(newPassword);

    // Update password
    user.passwordHash = passwordHash;
    await this.userRepository.save(user);

    // Revoke all refresh tokens (force re-login)
    await this.refreshTokenRepository.update(
      { userId: user.id, revokedAt: IsNull() },
      { revokedAt: new Date() }
    );

    // Audit log
    await this.logAudit({
      userId: adminId,
      action: 'admin.user.password_reset',
      resourceType: 'user',
      resourceId: user.id,
      details: {
        targetEmail: user.email
      }
    });
  }

  /**
   * Get activity logs with pagination and filtering
   * REQ-ADMIN-005
   */
  async getActivityLogs(
    input: ListActivityLogsInput,
    adminId: string
  ): Promise<PaginatedResponse<AuditLog & { user?: { email: string } }>> {
    const page = input.page || 1;
    const limit = Math.min(input.limit || 50, 200); // Max 200
    const skip = (page - 1) * limit;

    // Build where clause
    const where: FindOptionsWhere<AuditLog> = {};

    if (input.userId) {
      where.userId = input.userId;
    }

    if (input.action) {
      where.action = Like(`%${input.action}%`);
    }

    if (input.resourceType) {
      where.resourceType = input.resourceType;
    }

    // Handle date range
    if (input.startDate && input.endDate) {
      where.createdAt = Between(input.startDate, input.endDate);
    } else if (input.startDate) {
      where.createdAt = MoreThan(input.startDate);
    } else if (input.endDate) {
      where.createdAt = LessThan(input.endDate);
    } else {
      // Default: last 30 days
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      where.createdAt = MoreThan(thirtyDaysAgo);
    }

    // Get total count
    const total = await this.auditLogRepository.count({ where });

    // Get paginated results with user email
    const logs = await this.auditLogRepository
      .createQueryBuilder('log')
      .leftJoinAndSelect('log.user', 'user')
      .where(where)
      .orderBy('log.createdAt', 'DESC')
      .skip(skip)
      .take(limit)
      .getMany();

    // Transform to include user email
    const logsWithUserEmail = logs.map(log => ({
      ...log,
      user: log.userId ? { email: (log as any).user?.email } : undefined
    }));

    // Audit log
    await this.logAudit({
      userId: adminId,
      action: 'admin.activity_logs.viewed',
      resourceType: 'admin',
      details: {
        filters: input,
        resultCount: logs.length
      }
    });

    return {
      data: logsWithUserEmail,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    };
  }

  /**
   * Create audit log entry
   */
  private async logAudit(data: {
    userId?: string;
    action: string;
    resourceType?: string;
    resourceId?: string;
    ipAddress?: string;
    userAgent?: string;
    details?: Record<string, any>;
  }): Promise<void> {
    const log = this.auditLogRepository.create(data);
    await this.auditLogRepository.save(log);
  }
}
