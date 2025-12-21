import { QueryInterface, DataTypes } from 'sequelize';

export default {
  up: async (queryInterface: QueryInterface): Promise<void> => {
    await queryInterface.createTable('assessments', {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      consultant_id: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      client_name: {
        type: DataTypes.STRING(100),
        allowNull: false,
      },
      business_name: {
        type: DataTypes.STRING(100),
        allowNull: false,
      },
      client_email: {
        type: DataTypes.STRING(255),
        allowNull: false,
      },
      status: {
        type: DataTypes.ENUM('draft', 'in_progress', 'completed'),
        allowNull: false,
        defaultValue: 'draft',
      },
      progress: {
        type: DataTypes.DECIMAL(5, 2),
        allowNull: false,
        defaultValue: 0,
      },
      created_at: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      updated_at: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      started_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      completed_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      deleted_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      notes: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
    });

    // Create indexes
    await queryInterface.addIndex('assessments', ['consultant_id']);
    await queryInterface.addIndex('assessments', ['status']);
    await queryInterface.addIndex('assessments', ['updated_at']);
    await queryInterface.addIndex('assessments', ['client_email']);
  },

  down: async (queryInterface: QueryInterface): Promise<void> => {
    await queryInterface.dropTable('assessments');
  },
};
