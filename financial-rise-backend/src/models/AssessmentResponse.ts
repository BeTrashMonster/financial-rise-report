import { Model, DataTypes, Optional } from 'sequelize';
import sequelize from '../config/database';
import Assessment from './Assessment';

interface AssessmentResponseAttributes {
  id: string;
  assessmentId: string;
  questionId: string;
  answer: any;
  notApplicable: boolean;
  consultantNotes: string | null;
  answeredAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

interface AssessmentResponseCreationAttributes
  extends Optional<
    AssessmentResponseAttributes,
    'id' | 'answer' | 'notApplicable' | 'consultantNotes' | 'answeredAt' | 'createdAt' | 'updatedAt'
  > {}

class AssessmentResponse
  extends Model<AssessmentResponseAttributes, AssessmentResponseCreationAttributes>
  implements AssessmentResponseAttributes
{
  public id!: string;
  public assessmentId!: string;
  public questionId!: string;
  public answer!: any;
  public notApplicable!: boolean;
  public consultantNotes!: string | null;
  public answeredAt!: Date | null;
  public createdAt!: Date;
  public updatedAt!: Date;
}

AssessmentResponse.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    assessmentId: {
      type: DataTypes.UUID,
      allowNull: false,
      field: 'assessment_id',
      references: {
        model: 'assessments',
        key: 'id',
      },
      onDelete: 'CASCADE',
    },
    questionId: {
      type: DataTypes.UUID,
      allowNull: false,
      field: 'question_id',
    },
    answer: {
      type: DataTypes.JSONB,
      allowNull: true,
    },
    notApplicable: {
      type: DataTypes.BOOLEAN,
      allowNull: false,
      defaultValue: false,
      field: 'not_applicable',
    },
    consultantNotes: {
      type: DataTypes.TEXT,
      allowNull: true,
      field: 'consultant_notes',
    },
    answeredAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'answered_at',
    },
    createdAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'created_at',
    },
    updatedAt: {
      type: DataTypes.DATE,
      allowNull: false,
      field: 'updated_at',
    },
  },
  {
    sequelize,
    tableName: 'assessment_responses',
    timestamps: true,
    indexes: [
      {
        unique: true,
        fields: ['assessment_id', 'question_id'],
      },
      { fields: ['assessment_id'] },
      { fields: ['question_id'] },
    ],
  }
);

// Associations
Assessment.hasMany(AssessmentResponse, {
  foreignKey: 'assessmentId',
  as: 'responses',
  onDelete: 'CASCADE',
});

AssessmentResponse.belongsTo(Assessment, {
  foreignKey: 'assessmentId',
  as: 'assessment',
});

export default AssessmentResponse;
