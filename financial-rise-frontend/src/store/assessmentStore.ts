import { create } from 'zustand';
import type { Assessment, AssessmentDetail, AssessmentResponse } from '@/types';

interface AssessmentStore {
  // Current assessment being worked on
  currentAssessment: AssessmentDetail | null;
  setCurrentAssessment: (assessment: AssessmentDetail | null) => void;

  // Assessment list
  assessments: Assessment[];
  setAssessments: (assessments: Assessment[]) => void;
  addAssessment: (assessment: Assessment) => void;
  removeAssessment: (assessmentId: string) => void;

  // Current questionnaire state
  currentQuestionIndex: number;
  setCurrentQuestionIndex: (index: number) => void;

  // Responses
  responses: Map<string, AssessmentResponse>;
  setResponse: (questionId: string, response: AssessmentResponse) => void;
  setResponses: (responses: AssessmentResponse[]) => void;
  clearResponses: () => void;

  // Dirty state tracking (for auto-save)
  isDirty: boolean;
  setIsDirty: (isDirty: boolean) => void;

  // Last saved timestamp
  lastSavedAt: Date | null;
  setLastSavedAt: (date: Date | null) => void;

  // Loading states
  isLoading: boolean;
  setIsLoading: (isLoading: boolean) => void;

  // Reset store
  reset: () => void;
}

export const useAssessmentStore = create<AssessmentStore>((set) => ({
  currentAssessment: null,
  setCurrentAssessment: (assessment) => set({ currentAssessment: assessment }),

  assessments: [],
  setAssessments: (assessments) => set({ assessments }),
  addAssessment: (assessment) =>
    set((state) => ({ assessments: [assessment, ...state.assessments] })),
  removeAssessment: (assessmentId) =>
    set((state) => ({
      assessments: state.assessments.filter((a) => a.assessmentId !== assessmentId),
    })),

  currentQuestionIndex: 0,
  setCurrentQuestionIndex: (index) => set({ currentQuestionIndex: index }),

  responses: new Map(),
  setResponse: (questionId, response) =>
    set((state) => {
      const newResponses = new Map(state.responses);
      newResponses.set(questionId, response);
      return { responses: newResponses, isDirty: true };
    }),
  setResponses: (responses) => {
    const responseMap = new Map<string, AssessmentResponse>();
    responses.forEach((r) => responseMap.set(r.questionId, r));
    set({ responses: responseMap, isDirty: false });
  },
  clearResponses: () => set({ responses: new Map(), isDirty: false }),

  isDirty: false,
  setIsDirty: (isDirty) => set({ isDirty }),

  lastSavedAt: null,
  setLastSavedAt: (date) => set({ lastSavedAt: date }),

  isLoading: false,
  setIsLoading: (isLoading) => set({ isLoading }),

  reset: () =>
    set({
      currentAssessment: null,
      currentQuestionIndex: 0,
      responses: new Map(),
      isDirty: false,
      lastSavedAt: null,
      isLoading: false,
    }),
}));

export default useAssessmentStore;
