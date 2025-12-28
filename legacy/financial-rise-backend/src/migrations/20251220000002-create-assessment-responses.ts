import { QueryInterface, DataTypes } from 'sequelize';

export default {
  up: async (queryInterface: QueryInterface): Promise<void> => {
    await queryInterface.createTable('assessment_responses', {
      id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true,
      },
      assessment_id: {
        type: DataTypes.UUID,
        allowNull: false,
        references: {
          model: 'assessments',
          key: 'id',
        },
        onDelete: 'CASCADE',
      },
      question_id: {
        type: DataTypes.UUID,
        allowNull: false,
      },
      answer: {
        type: DataTypes.JSONB,
        allowNull: true,
      },
      not_applicable: {
        type: DataTypes.BOOLEAN,
        allowNull: false,
        defaultValue: false,
      },
      consultant_notes: {
        type: DataTypes.TEXT,
        allowNull: true,
      },
      answered_at: {
        type: DataTypes.DATE,
        allowNull: true,
      },
      created_at: {
        type: DataTypes.DATE,
        allowNull: false,
      },
      updated_at: {
        type: DataTypes.DATE,
        allowNull: false,
      },
    });

    // Create indexes
    await queryInterface.addIndex('assessment_responses', ['assessment_id', 'question_id'], {
      unique: true,
    });
    await queryInterface.addIndex('assessment_responses', ['assessment_id']);
    await queryInterface.addIndex('assessment_responses', ['question_id']);
  },

  down: async (queryInterface: QueryInterface): Promise<void> => {
    await queryInterface.dropTable('assessment_responses');
  },
};
