import { describe, it, expect, beforeEach } from 'vitest';
import { useAssessmentStore } from '../assessmentStore';
import { Assessment, AssessmentDetail, AssessmentStatus, AssessmentResponse } from '@/types';

describe('assessmentStore', () => {
  beforeEach(() => {
    // Reset store before each test
    useAssessmentStore.getState().reset();
    useAssessmentStore.setState({
      assessments: [],
      currentAssessment: null,
      responses: new Map(),
      currentQuestionIndex: 0,
      isDirty: false,
      lastSavedAt: null,
      isLoading: false,
    });
  });

  describe('currentAssessment', () => {
    it('should set current assessment', () => {
      const assessment: AssessmentDetail = {
        assessmentId: 'test-1',
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        status: AssessmentStatus.IN_PROGRESS,
        progress: 50,
        createdAt: '2025-12-20T10:00:00Z',
        updatedAt: '2025-12-20T11:00:00Z',
        responses: [],
      };

      useAssessmentStore.getState().setCurrentAssessment(assessment);
      expect(useAssessmentStore.getState().currentAssessment).toEqual(assessment);
    });

    it('should clear current assessment when set to null', () => {
      const assessment: AssessmentDetail = {
        assessmentId: 'test-1',
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        status: AssessmentStatus.IN_PROGRESS,
        progress: 50,
        createdAt: '2025-12-20T10:00:00Z',
        updatedAt: '2025-12-20T11:00:00Z',
        responses: [],
      };

      useAssessmentStore.getState().setCurrentAssessment(assessment);
      useAssessmentStore.getState().setCurrentAssessment(null);
      expect(useAssessmentStore.getState().currentAssessment).toBeNull();
    });
  });

  describe('assessments list', () => {
    const mockAssessments: Assessment[] = [
      {
        assessmentId: '1',
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        status: AssessmentStatus.DRAFT,
        progress: 0,
        createdAt: '2025-12-20T10:00:00Z',
        updatedAt: '2025-12-20T10:00:00Z',
      },
      {
        assessmentId: '2',
        clientName: 'Jane Smith',
        businessName: 'Smith LLC',
        status: AssessmentStatus.IN_PROGRESS,
        progress: 45,
        createdAt: '2025-12-19T10:00:00Z',
        updatedAt: '2025-12-19T14:00:00Z',
      },
    ];

    it('should set assessments list', () => {
      useAssessmentStore.getState().setAssessments(mockAssessments);
      expect(useAssessmentStore.getState().assessments).toEqual(mockAssessments);
    });

    it('should add assessment to the beginning of list', () => {
      useAssessmentStore.getState().setAssessments(mockAssessments);

      const newAssessment: Assessment = {
        assessmentId: '3',
        clientName: 'Bob Johnson',
        businessName: 'Johnson Industries',
        status: AssessmentStatus.DRAFT,
        progress: 0,
        createdAt: '2025-12-21T10:00:00Z',
        updatedAt: '2025-12-21T10:00:00Z',
      };

      useAssessmentStore.getState().addAssessment(newAssessment);

      const assessments = useAssessmentStore.getState().assessments;
      expect(assessments).toHaveLength(3);
      expect(assessments[0]).toEqual(newAssessment);
    });

    it('should remove assessment by id', () => {
      useAssessmentStore.getState().setAssessments(mockAssessments);
      useAssessmentStore.getState().removeAssessment('1');

      const assessments = useAssessmentStore.getState().assessments;
      expect(assessments).toHaveLength(1);
      expect(assessments[0].assessmentId).toBe('2');
    });

    it('should not error when removing non-existent assessment', () => {
      useAssessmentStore.getState().setAssessments(mockAssessments);
      useAssessmentStore.getState().removeAssessment('non-existent');

      expect(useAssessmentStore.getState().assessments).toHaveLength(2);
    });
  });

  describe('question navigation', () => {
    it('should set current question index', () => {
      useAssessmentStore.getState().setCurrentQuestionIndex(5);
      expect(useAssessmentStore.getState().currentQuestionIndex).toBe(5);
    });

    it('should start at index 0 by default', () => {
      expect(useAssessmentStore.getState().currentQuestionIndex).toBe(0);
    });
  });

  describe('responses', () => {
    it('should set a single response and mark as dirty', () => {
      const response: AssessmentResponse = {
        questionId: 'q1',
        answer: 'opt1',
        notApplicable: false,
      };

      useAssessmentStore.getState().setResponse('q1', response);

      const responses = useAssessmentStore.getState().responses;
      expect(responses.get('q1')).toEqual(response);
      expect(useAssessmentStore.getState().isDirty).toBe(true);
    });

    it('should update existing response', () => {
      const response1: AssessmentResponse = {
        questionId: 'q1',
        answer: 'opt1',
        notApplicable: false,
      };

      const response2: AssessmentResponse = {
        questionId: 'q1',
        answer: 'opt2',
        notApplicable: false,
      };

      useAssessmentStore.getState().setResponse('q1', response1);
      useAssessmentStore.getState().setResponse('q1', response2);

      const responses = useAssessmentStore.getState().responses;
      expect(responses.get('q1')?.answer).toBe('opt2');
    });

    it('should set multiple responses from array', () => {
      const responses: AssessmentResponse[] = [
        { questionId: 'q1', answer: 'opt1', notApplicable: false },
        { questionId: 'q2', answer: 'opt2', notApplicable: false },
        { questionId: 'q3', answer: 'opt3', notApplicable: true },
      ];

      useAssessmentStore.getState().setResponses(responses);

      const responseMap = useAssessmentStore.getState().responses;
      expect(responseMap.size).toBe(3);
      expect(responseMap.get('q1')?.answer).toBe('opt1');
      expect(responseMap.get('q2')?.answer).toBe('opt2');
      expect(responseMap.get('q3')?.notApplicable).toBe(true);
      expect(useAssessmentStore.getState().isDirty).toBe(false);
    });

    it('should clear all responses', () => {
      const responses: AssessmentResponse[] = [
        { questionId: 'q1', answer: 'opt1', notApplicable: false },
        { questionId: 'q2', answer: 'opt2', notApplicable: false },
      ];

      useAssessmentStore.getState().setResponses(responses);
      useAssessmentStore.getState().clearResponses();

      expect(useAssessmentStore.getState().responses.size).toBe(0);
      expect(useAssessmentStore.getState().isDirty).toBe(false);
    });
  });

  describe('dirty state', () => {
    it('should set dirty state', () => {
      useAssessmentStore.getState().setIsDirty(true);
      expect(useAssessmentStore.getState().isDirty).toBe(true);

      useAssessmentStore.getState().setIsDirty(false);
      expect(useAssessmentStore.getState().isDirty).toBe(false);
    });

    it('should mark as dirty when setting response', () => {
      expect(useAssessmentStore.getState().isDirty).toBe(false);

      useAssessmentStore.getState().setResponse('q1', {
        questionId: 'q1',
        answer: 'test',
        notApplicable: false,
      });

      expect(useAssessmentStore.getState().isDirty).toBe(true);
    });

    it('should mark as not dirty when setting responses from array', () => {
      useAssessmentStore.setState({ isDirty: true });

      useAssessmentStore.getState().setResponses([
        { questionId: 'q1', answer: 'opt1', notApplicable: false },
      ]);

      expect(useAssessmentStore.getState().isDirty).toBe(false);
    });
  });

  describe('lastSavedAt', () => {
    it('should set last saved timestamp', () => {
      const now = new Date();
      useAssessmentStore.getState().setLastSavedAt(now);
      expect(useAssessmentStore.getState().lastSavedAt).toEqual(now);
    });

    it('should clear last saved timestamp', () => {
      const now = new Date();
      useAssessmentStore.getState().setLastSavedAt(now);
      useAssessmentStore.getState().setLastSavedAt(null);
      expect(useAssessmentStore.getState().lastSavedAt).toBeNull();
    });

    it('should start with null last saved timestamp', () => {
      expect(useAssessmentStore.getState().lastSavedAt).toBeNull();
    });
  });

  describe('loading state', () => {
    it('should set loading state', () => {
      useAssessmentStore.getState().setIsLoading(true);
      expect(useAssessmentStore.getState().isLoading).toBe(true);

      useAssessmentStore.getState().setIsLoading(false);
      expect(useAssessmentStore.getState().isLoading).toBe(false);
    });

    it('should start with loading false', () => {
      expect(useAssessmentStore.getState().isLoading).toBe(false);
    });
  });

  describe('reset', () => {
    it('should reset all state to defaults', () => {
      // Set up some state
      const assessment: AssessmentDetail = {
        assessmentId: 'test-1',
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        status: AssessmentStatus.IN_PROGRESS,
        progress: 50,
        createdAt: '2025-12-20T10:00:00Z',
        updatedAt: '2025-12-20T11:00:00Z',
        responses: [],
      };

      useAssessmentStore.getState().setCurrentAssessment(assessment);
      useAssessmentStore.getState().setCurrentQuestionIndex(5);
      useAssessmentStore.getState().setResponse('q1', {
        questionId: 'q1',
        answer: 'test',
        notApplicable: false,
      });
      useAssessmentStore.getState().setIsDirty(true);
      useAssessmentStore.getState().setLastSavedAt(new Date());
      useAssessmentStore.getState().setIsLoading(true);

      // Reset
      useAssessmentStore.getState().reset();

      // Verify everything is reset
      const state = useAssessmentStore.getState();
      expect(state.currentAssessment).toBeNull();
      expect(state.currentQuestionIndex).toBe(0);
      expect(state.responses.size).toBe(0);
      expect(state.isDirty).toBe(false);
      expect(state.lastSavedAt).toBeNull();
      expect(state.isLoading).toBe(false);
    });

    it('should not reset assessments list', () => {
      const mockAssessments: Assessment[] = [
        {
          assessmentId: '1',
          clientName: 'John Doe',
          businessName: 'Acme Corp',
          status: AssessmentStatus.DRAFT,
          progress: 0,
          createdAt: '2025-12-20T10:00:00Z',
          updatedAt: '2025-12-20T10:00:00Z',
        },
      ];

      useAssessmentStore.getState().setAssessments(mockAssessments);
      useAssessmentStore.getState().reset();

      // Assessments list should remain
      expect(useAssessmentStore.getState().assessments).toEqual(mockAssessments);
    });
  });

  describe('complex scenarios', () => {
    it('should handle multiple response updates correctly', () => {
      const responses: AssessmentResponse[] = [
        { questionId: 'q1', answer: 'initial1', notApplicable: false },
        { questionId: 'q2', answer: 'initial2', notApplicable: false },
      ];

      useAssessmentStore.getState().setResponses(responses);
      expect(useAssessmentStore.getState().isDirty).toBe(false);

      useAssessmentStore.getState().setResponse('q1', {
        questionId: 'q1',
        answer: 'updated1',
        notApplicable: false,
      });

      expect(useAssessmentStore.getState().isDirty).toBe(true);
      expect(useAssessmentStore.getState().responses.get('q1')?.answer).toBe('updated1');
      expect(useAssessmentStore.getState().responses.get('q2')?.answer).toBe('initial2');
    });

    it('should maintain Map immutability when setting responses', () => {
      const response1: AssessmentResponse = {
        questionId: 'q1',
        answer: 'test1',
        notApplicable: false,
      };

      useAssessmentStore.getState().setResponse('q1', response1);
      const firstMap = useAssessmentStore.getState().responses;

      const response2: AssessmentResponse = {
        questionId: 'q2',
        answer: 'test2',
        notApplicable: false,
      };

      useAssessmentStore.getState().setResponse('q2', response2);
      const secondMap = useAssessmentStore.getState().responses;

      // Maps should be different instances
      expect(firstMap).not.toBe(secondMap);
      // But first map should still have its original data
      expect(firstMap.get('q1')).toEqual(response1);
    });
  });
});
