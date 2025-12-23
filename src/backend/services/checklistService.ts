/**
 * ChecklistService
 *
 * Business logic for managing action item checklists.
 * Handles CRUD operations, auto-generation, permissions, and audit trails.
 *
 * @module services/checklistService
 * @version 1.0
 * @date 2025-12-22
 */

import { ChecklistItem } from '../models/ChecklistItem';
import { ChecklistEditHistory } from '../models/ChecklistEditHistory';
import { getReport } from './reportService';
import { extractRecommendations, determinePriority } from './recommendationExtractor';
import { Op } from 'sequelize';

/**
 * Options for retrieving checklist
 */
export interface GetChecklistOptions {
  phase?: string;
  completed?: boolean;
  includeDeleted?: boolean;
}

/**
 * Checklist response structure
 */
export interface ChecklistResponse {
  assessment_id: string;
  total_items: number;
  completed_items: number;
  progress_percentage: number;
  items_by_phase: {
    [phase: string]: {
      total: number;
      completed: number;
      items: any[];
    };
  };
}

/**
 * Custom error classes
 */
export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}

export class ForbiddenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ForbiddenError';
  }
}

/**
 * ChecklistService Class
 *
 * Provides all checklist-related business logic
 */
export class ChecklistService {
  /**
   * Get all checklist items for an assessment
   *
   * @param assessmentId - Assessment UUID
   * @param options - Filtering options
   * @returns Checklist with items grouped by phase
   */
  async getChecklist(
    assessmentId: string,
    options: GetChecklistOptions = {}
  ): Promise<ChecklistResponse> {
    const where: any = { assessment_id: assessmentId };

    if (options.phase) {
      where.phase = options.phase;
    }

    if (options.completed !== undefined) {
      where.is_completed = options.completed;
    }

    const items = await ChecklistItem.findAll({
      where,
      paranoid: !options.includeDeleted,
      order: [['sort_order', 'ASC']],
      include: [
        {
          model: User,
          as: 'completedBy',
          attributes: ['id', 'name', 'role']
        }
      ]
    });

    // Group by phase
    const itemsByPhase = this.groupByPhase(items);

    const totalItems = items.length;
    const completedItems = items.filter(i => i.is_completed).length;

    return {
      assessment_id: assessmentId,
      total_items: totalItems,
      completed_items: completedItems,
      progress_percentage: totalItems > 0
        ? Math.round((completedItems / totalItems) * 100)
        : 0,
      items_by_phase: itemsByPhase
    };
  }

  /**
   * Auto-generate checklist from report recommendations
   *
   * @param assessmentId - Assessment UUID
   * @param consultantId - Consultant UUID
   * @returns Created checklist with item count
   */
  async autoGenerateChecklist(
    assessmentId: string,
    consultantId: string
  ): Promise<{ items_created: number; checklist: ChecklistResponse }> {
    // Check if report exists
    const report = await getReport(assessmentId, 'client');
    if (!report) {
      throw new Error('Report must be generated before creating checklist');
    }

    // Check if checklist already exists
    const existing = await ChecklistItem.count({
      where: { assessment_id: assessmentId }
    });

    if (existing > 0) {
      throw new ConflictError('Checklist already exists');
    }

    // Extract recommendations
    const recommendations = await extractRecommendations(report.data);

    // Create items
    const items = await Promise.all(
      recommendations.map((rec, index) =>
        ChecklistItem.create({
          assessment_id: assessmentId,
          title: rec.title,
          description: rec.description,
          phase: rec.phase as any,
          priority: rec.priority as any,
          sort_order: index,
          auto_generated: true,
          source_recommendation_id: rec.sourceSection,
          created_by: consultantId
        })
      )
    );

    return {
      items_created: items.length,
      checklist: await this.getChecklist(assessmentId)
    };
  }

  /**
   * Create a single checklist item
   *
   * @param data - Item data
   * @returns Created item
   */
  async createItem(data: {
    assessment_id: string;
    title: string;
    description?: string;
    phase: string;
    priority?: number;
    created_by: string;
  }): Promise<ChecklistItem> {
    // Get next sort_order
    const maxSortOrder = await ChecklistItem.max('sort_order', {
      where: { assessment_id: data.assessment_id }
    });

    return await ChecklistItem.create({
      ...data,
      sort_order: (maxSortOrder || 0) + 1
    } as any);
  }

  /**
   * Update checklist item
   *
   * @param itemId - Item UUID
   * @param updates - Fields to update
   * @param userId - User making the update
   * @param userRole - Role of user (consultant or client)
   * @returns Updated item
   */
  async updateItem(
    itemId: string,
    updates: Partial<any>,
    userId: string,
    userRole: string
  ): Promise<ChecklistItem> {
    const item = await ChecklistItem.findByPk(itemId);
    if (!item) {
      throw new NotFoundError('Checklist item not found');
    }

    // Permission check
    if (userRole === 'client') {
      // Clients can only update client_notes
      const allowedFields = ['client_notes'];
      const updateFields = Object.keys(updates);

      if (!updateFields.every(f => allowedFields.includes(f))) {
        throw new ForbiddenError('Clients can only update notes');
      }

      if (updates.client_notes !== undefined) {
        updates.client_notes_updated_at = new Date();
      }
    }

    updates.updated_by = userId;
    updates.updated_at = new Date();

    await item.update(updates);

    return item;
  }

  /**
   * Mark item complete/incomplete
   *
   * @param itemId - Item UUID
   * @param completed - True to mark complete, false for incomplete
   * @param userId - User marking the item
   * @returns Updated item
   */
  async toggleComplete(
    itemId: string,
    completed: boolean,
    userId: string
  ): Promise<ChecklistItem> {
    const item = await ChecklistItem.findByPk(itemId);
    if (!item) {
      throw new NotFoundError('Checklist item not found');
    }

    await item.update({
      is_completed: completed,
      completed_at: completed ? new Date() : null,
      completed_by: completed ? userId : null,
      updated_by: userId,
      updated_at: new Date()
    });

    // Log history
    await this.logHistory(itemId, completed ? 'completed' : 'uncompleted', userId);

    return item;
  }

  /**
   * Soft delete item
   *
   * @param itemId - Item UUID
   * @param userId - User deleting the item
   */
  async deleteItem(itemId: string, userId: string): Promise<void> {
    const item = await ChecklistItem.findByPk(itemId);
    if (!item) {
      throw new NotFoundError('Checklist item not found');
    }

    await item.update({
      deleted_at: new Date(),
      updated_by: userId
    });

    await this.logHistory(itemId, 'deleted', userId);
  }

  /**
   * Reorder items
   *
   * @param assessmentId - Assessment UUID
   * @param items - Array of {id, sort_order} objects
   */
  async reorderItems(
    assessmentId: string,
    items: Array<{ id: string; sort_order: number }>
  ): Promise<void> {
    await Promise.all(
      items.map(({ id, sort_order }) =>
        ChecklistItem.update(
          { sort_order },
          { where: { id, assessment_id: assessmentId } }
        )
      )
    );
  }

  /**
   * Group checklist items by phase
   *
   * @param items - Array of checklist items
   * @returns Items grouped by phase
   * @private
   */
  private groupByPhase(items: ChecklistItem[]): any {
    const phases = ['Stabilize', 'Organize', 'Build', 'Grow', 'Systemic'];
    const grouped: any = {};

    for (const phase of phases) {
      const phaseItems = items.filter(i => i.phase === phase);
      grouped[phase] = {
        total: phaseItems.length,
        completed: phaseItems.filter(i => i.is_completed).length,
        items: phaseItems
      };
    }

    return grouped;
  }

  /**
   * Log history entry for audit trail
   *
   * @param itemId - Checklist item UUID
   * @param action - Action performed
   * @param userId - User who performed action
   * @param fieldName - Optional field name for updates
   * @param oldValue - Optional old value
   * @param newValue - Optional new value
   * @private
   */
  private async logHistory(
    itemId: string,
    action: string,
    userId: string,
    fieldName?: string,
    oldValue?: string,
    newValue?: string
  ): Promise<void> {
    await ChecklistEditHistory.create({
      checklist_item_id: itemId,
      action: action as any,
      field_name: fieldName,
      old_value: oldValue,
      new_value: newValue,
      changed_by: userId,
      changed_at: new Date()
    });
  }
}

// Placeholder for User model (should be imported from actual models)
const User = { name: 'User' };

export default ChecklistService;
