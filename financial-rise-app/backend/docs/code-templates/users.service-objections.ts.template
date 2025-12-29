// GDPR Article 21 - Right to Object methods
// These methods should be added to users.service.ts

import { Injectable, NotFoundException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { UserObjection, ObjectionType } from './entities/user-objection.entity';

// Add to constructor:
// @InjectRepository(UserObjection)
// private readonly objectionRepository: Repository<UserObjection>,

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
