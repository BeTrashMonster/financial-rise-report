/**
 * ChecklistEditHistory Model
 *
 * Tracks all changes made to checklist items for audit and compliance purposes.
 * Provides a complete audit trail of who changed what and when.
 *
 * @module models/ChecklistEditHistory
 * @version 1.0
 * @date 2025-12-22
 */

import { Model, DataTypes, Sequelize, Optional } from 'sequelize';

/**
 * ChecklistEditHistory attributes interface
 */
export interface ChecklistEditHistoryAttributes {
  id: string;
  checklist_item_id: string;

  // Change tracking
  action: 'created' | 'updated' | 'completed' | 'uncompleted' | 'deleted';
  field_name?: string;
  old_value?: string;
  new_value?: string;

  // Audit
  changed_by: string;
  changed_at: Date;
  ip_address?: string;
  user_agent?: string;
}

/**
 * Optional attributes for creation
 */
export interface ChecklistEditHistoryCreationAttributes
  extends Optional<
    ChecklistEditHistoryAttributes,
    'id' | 'field_name' | 'old_value' | 'new_value' | 'changed_at' | 'ip_address' | 'user_agent'
  > {}

/**
 * ChecklistEditHistory Model Class
 *
 * Provides comprehensive audit trail for checklist item changes
 */
export class ChecklistEditHistory extends Model<
  ChecklistEditHistoryAttributes,
  ChecklistEditHistoryCreationAttributes
> implements ChecklistEditHistoryAttributes {
  public id!: string;
  public checklist_item_id!: string;

  // Change tracking
  public action!: 'created' | 'updated' | 'completed' | 'uncompleted' | 'deleted';
  public field_name?: string;
  public old_value?: string;
  public new_value?: string;

  // Audit
  public changed_by!: string;
  public changed_at!: Date;
  public ip_address?: string;
  public user_agent?: string;

  /**
   * Helper method to get a human-readable description of the change
   */
  public getChangeDescription(): string {
    if (this.action === 'created') {
      return 'Item created';
    }
    if (this.action === 'deleted') {
      return 'Item deleted';
    }
    if (this.action === 'completed') {
      return 'Item marked as complete';
    }
    if (this.action === 'uncompleted') {
      return 'Item marked as incomplete';
    }
    if (this.action === 'updated' && this.field_name) {
      return `${this.field_name} updated from "${this.old_value || 'empty'}" to "${this.new_value || 'empty'}"`;
    }
    return 'Item updated';
  }

  /**
   * Helper method to check if this is a completion action
   */
  public isCompletionAction(): boolean {
    return this.action === 'completed' || this.action === 'uncompleted';
  }
}

/**
 * Initialize the ChecklistEditHistory model
 *
 * @param sequelize - Sequelize instance
 * @returns Initialized ChecklistEditHistory model
 */
export function initChecklistEditHistoryModel(sequelize: Sequelize): typeof ChecklistEditHistory {
  ChecklistEditHistory.init(
    {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
        comment: 'Unique identifier for the history entry'
      },
      checklist_item_id: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
          model: 'checklist_items',
          key: 'id'
        },
        onDelete: 'CASCADE',
        comment: 'Foreign key to checklist_items table'
      },
      action: {
        type: DataTypes.STRING(50),
        allowNull: false,
        validate: {
          isIn: {
            args: [['created', 'updated', 'completed', 'uncompleted', 'deleted']],
            msg: 'Action must be one of: created, updated, completed, uncompleted, deleted'
          }
        },
        comment: 'Type of action performed'
      },
      field_name: {
        type: DataTypes.STRING(100),
        allowNull: true,
        comment: 'Name of the field that was changed (for update actions)'
      },
      old_value: {
        type: DataTypes.TEXT,
        allowNull: true,
        comment: 'Previous value before the change'
      },
      new_value: {
        type: DataTypes.TEXT,
        allowNull: true,
        comment: 'New value after the change'
      },
      changed_by: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
          model: 'users',
          key: 'id'
        },
        comment: 'User ID who made the change'
      },
      changed_at: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
        allowNull: false,
        comment: 'Timestamp when the change was made'
      },
      ip_address: {
        type: DataTypes.INET,
        allowNull: true,
        comment: 'IP address from which the change was made'
      },
      user_agent: {
        type: DataTypes.TEXT,
        allowNull: true,
        comment: 'User agent string of the client that made the change'
      }
    },
    {
      sequelize,
      tableName: 'checklist_edit_history',
      timestamps: false, // We manage changed_at manually
      underscored: true,
      indexes: [
        {
          name: 'idx_checklist_history_item_id',
          fields: ['checklist_item_id']
        },
        {
          name: 'idx_checklist_history_changed_at',
          fields: ['changed_at']
        }
      ]
    }
  );

  return ChecklistEditHistory;
}

export default ChecklistEditHistory;
