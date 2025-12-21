// TypeORM Entity Exports
// Financial RISE Report Database Entities

export { User, UserRole } from './User';
export { Assessment, AssessmentStatus } from './Assessment';
export { Question, QuestionType, QuestionSection } from './Question';
export { Response } from './Response';
export { DiscProfile, DiscType } from './DiscProfile';
export { PhaseResult, FinancialPhase } from './PhaseResult';
export { Report, ReportType } from './Report';
export { ActivityLog, EventCategory, Severity } from './ActivityLog';

// Phase 2 Entities
export { ChecklistItem, CompletedBy, Priority } from './ChecklistItem';
export { ConsultantSettings } from './ConsultantSettings';
export { SchedulerLink } from './SchedulerLink';

// All entities array for TypeORM configuration
export const entities = [
  User,
  Assessment,
  Question,
  Response,
  DiscProfile,
  PhaseResult,
  Report,
  ActivityLog,
  ChecklistItem,
  ConsultantSettings,
  SchedulerLink,
];
