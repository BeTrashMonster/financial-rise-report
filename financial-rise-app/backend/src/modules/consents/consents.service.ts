import { Injectable, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserConsent, ConsentType } from './entities/user-consent.entity';

@Injectable()
export class ConsentsService {
  constructor(
    @InjectRepository(UserConsent)
    private readonly consentRepository: Repository<UserConsent>,
  ) {}

  /**
   * Log a new consent record
   * Creates an audit trail entry for consent granted or withdrawn
   */
  async logConsent(
    userId: string,
    type: ConsentType,
    granted: boolean,
    ipAddress: string | null = null,
    userAgent: string | null = null,
  ): Promise<UserConsent> {
    const consent = this.consentRepository.create({
      user_id: userId,
      consent_type: type,
      granted,
      ip_address: ipAddress,
      user_agent: userAgent,
    });

    return this.consentRepository.save(consent);
  }

  /**
   * Get all consent records for a user (all types)
   * Ordered by most recent first
   */
  async getConsents(userId: string): Promise<UserConsent[]> {
    return this.consentRepository.find({
      where: { user_id: userId },
      order: { created_at: 'DESC' },
    });
  }

  /**
   * Get the most recent consent record for a specific type
   */
  async getCurrentConsent(userId: string, type: ConsentType): Promise<UserConsent | null> {
    return this.consentRepository.findOne({
      where: { user_id: userId, consent_type: type },
      order: { created_at: 'DESC' },
    });
  }

  /**
   * Update consent by creating a new record (maintains audit trail)
   * Throws error if attempting to revoke essential consent
   */
  async updateConsent(
    userId: string,
    type: ConsentType,
    granted: boolean,
    ipAddress: string | null = null,
    userAgent: string | null = null,
  ): Promise<UserConsent> {
    // Essential consent cannot be revoked
    if (type === ConsentType.ESSENTIAL && !granted) {
      throw new BadRequestException('Essential consent cannot be revoked');
    }

    // Create new record to maintain audit trail
    return this.logConsent(userId, type, granted, ipAddress, userAgent);
  }

  /**
   * Get complete consent history for a specific type
   * Useful for audit and compliance reporting
   */
  async getConsentHistory(userId: string, type: ConsentType): Promise<UserConsent[]> {
    return this.consentRepository.find({
      where: { user_id: userId, consent_type: type },
      order: { created_at: 'DESC' },
    });
  }

  /**
   * Check if user has active consent for a specific type
   * Essential consent is always considered granted by default
   */
  async hasActiveConsent(userId: string, type: ConsentType): Promise<boolean> {
    // Essential consent is always considered granted by default
    if (type === ConsentType.ESSENTIAL) {
      const consent = await this.getCurrentConsent(userId, type);
      // If no record exists for essential, assume granted
      // If record exists, check the granted value
      return consent?.granted !== false;
    }

    const consent = await this.getCurrentConsent(userId, type);
    return consent?.granted === true;
  }
}
