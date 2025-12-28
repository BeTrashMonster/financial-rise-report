import { Model, DataTypes, Optional } from 'sequelize';
import sequelize from '../config/database';
import { AssessmentStatus } from '../types';

interface AssessmentAttributes {
  id: string;
  consultantId: string;
  clientName: string;
  businessName: string;
  clientEmail: string;
  status: AssessmentStatus;
  progress: number;
  createdAt: Date;
  updatedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  deletedAt: Date | null;
  notes: string | null;
}

interface AssessmentCreationAttributes
  extends Optional<
    AssessmentAttributes,
    'id' | 'status' | 'progress' | 'createdAt' | 'updatedAt' | 'startedAt' | 'completedAt' | 'deletedAt' | 'notes'
  > {}

class Assessment extends Model<AssessmentAttributes, AssessmentCreationAttributes> implements AssessmentAttributes {
  public id!: string;
  public consultantId!: string;
  public clientName!: string;
  public businessName!: string;
  public clientEmail!: string;
  public status!: AssessmentStatus;
  public progress!: number;
  public createdAt!: Date;
  public updatedAt!: Date;
  public startedAt!: Date | null;
  public completedAt!: Date | null;
  public deletedAt!: Date | null;
  public notes!: string | null;
}

Assessment.init(
  {
    id: {
      type: DataTypes.UUID,
      defaultValue: DataTypes.UUIDV4,
      primaryKey: true,
    },
    consultantId: {
      type: DataTypes.UUID,
      allowNull: false,
      field: 'consultant_id',
    },
    clientName: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'client_name',
    },
    businessName: {
      type: DataTypes.STRING(100),
      allowNull: false,
      field: 'business_name',
    },
    clientEmail: {
      type: DataTypes.STRING(255),
      allowNull: false,
      field: 'client_email',
      validate: {
        isEmail: true,
      },
    },
    status: {
      type: DataTypes.ENUM(...Object.values(AssessmentStatus)),
      allowNull: false,
      defaultValue: AssessmentStatus.DRAFT,
    },
    progress: {
      type: DataTypes.DECIMAL(5, 2),
      allowNull: false,
      defaultValue: 0,
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
    startedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'started_at',
    },
    completedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'completed_at',
    },
    deletedAt: {
      type: DataTypes.DATE,
      allowNull: true,
      field: 'deleted_at',
    },
    notes: {
      type: DataTypes.TEXT,
      allowNull: true,
    },
  },
  {
    sequelize,
    tableName: 'assessments',
    timestamps: true,
    paranoid: true,
    indexes: [
      { fields: ['consultant_id'] },
      { fields: ['status'] },
      { fields: ['updated_at'] },
      { fields: ['client_email'] },
    ],
  }
);

export default Assessment;
