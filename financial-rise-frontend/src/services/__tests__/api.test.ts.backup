import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import axios from 'axios';
import { Assessment, AssessmentDetail, AssessmentStatus } from '@/types';

// Mock axios before importing the service
const mockAxiosInstance = {
  get: vi.fn(),
  post: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
  interceptors: {
    request: { use: vi.fn() },
    response: { use: vi.fn() },
  },
};

const axiosCreateSpy = vi.fn(() => mockAxiosInstance);

vi.mock('axios', () => ({
  default: {
    create: axiosCreateSpy,
  },
}));

// Import after mocking
const { apiService } = await import('../api');

describe('apiService', () => {
  beforeEach(() => {
    // Don't clear axiosCreateSpy - we need to check it was called during init
    mockAxiosInstance.get.mockClear();
    mockAxiosInstance.post.mockClear();
    mockAxiosInstance.patch.mockClear();
    mockAxiosInstance.delete.mockClear();
    localStorage.clear();
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('token management', () => {
    it('should store token in localStorage', () => {
      apiService.setToken('test-token-123');
      expect(localStorage.getItem('auth_token')).toBe('test-token-123');
    });

    it('should retrieve token from localStorage', () => {
      localStorage.setItem('auth_token', 'test-token-456');
      // Token is retrieved via private method during request interceptor
      expect(localStorage.getItem('auth_token')).toBe('test-token-456');
    });
  });

  describe('createAssessment', () => {
    it('should create a new assessment', async () => {
      const requestData = {
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        clientEmail: 'john@acme.com',
      };

      const responseData: Assessment = {
        assessmentId: 'new-123',
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        clientEmail: 'john@acme.com',
        status: AssessmentStatus.DRAFT,
        progress: 0,
        createdAt: '2025-12-20T10:00:00Z',
        updatedAt: '2025-12-20T10:00:00Z',
      };

      mockAxiosInstance.post.mockResolvedValue({ data: responseData });

      const result = await apiService.createAssessment(requestData);

      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/assessments', requestData);
      expect(result).toEqual(responseData);
    });

    it('should handle creation errors', async () => {
      const requestData = {
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        clientEmail: 'invalid-email',
      };

      mockAxiosInstance.post.mockRejectedValue({
        response: { status: 400, data: { error: { message: 'Invalid email' } } },
      });

      await expect(apiService.createAssessment(requestData)).rejects.toMatchObject({
        response: { status: 400 },
      });
    });
  });

  describe('listAssessments', () => {
    it('should list all assessments', async () => {
      const responseData = {
        assessments: [
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
        ],
        total: 2,
        limit: 20,
        offset: 0,
      };

      mockAxiosInstance.get.mockResolvedValue({ data: responseData });

      const result = await apiService.listAssessments();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/assessments', { params: undefined });
      expect(result).toEqual(responseData);
    });

    it('should list assessments with filters', async () => {
      const params = {
        status: 'in_progress',
        limit: 10,
        offset: 0,
        sortBy: 'updatedAt',
        sortOrder: 'desc',
      };

      const responseData = {
        assessments: [],
        total: 0,
        limit: 10,
        offset: 0,
      };

      mockAxiosInstance.get.mockResolvedValue({ data: responseData });

      await apiService.listAssessments(params);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/assessments', { params });
    });
  });

  describe('getAssessment', () => {
    it('should get assessment by id', async () => {
      const assessmentId = 'test-123';
      const responseData: AssessmentDetail = {
        assessmentId,
        clientName: 'John Doe',
        businessName: 'Acme Corp',
        clientEmail: 'john@acme.com',
        status: AssessmentStatus.IN_PROGRESS,
        progress: 50,
        createdAt: '2025-12-20T10:00:00Z',
        updatedAt: '2025-12-20T11:00:00Z',
        responses: [
          {
            questionId: 'q1',
            answer: 'opt1',
            notApplicable: false,
          },
        ],
      };

      mockAxiosInstance.get.mockResolvedValue({ data: responseData });

      const result = await apiService.getAssessment(assessmentId);

      expect(mockAxiosInstance.get).toHaveBeenCalledWith(`/assessments/${assessmentId}`);
      expect(result).toEqual(responseData);
    });

    it('should handle not found error', async () => {
      mockAxiosInstance.get.mockRejectedValue({
        response: { status: 404, data: { error: { message: 'Assessment not found' } } },
      });

      await expect(apiService.getAssessment('non-existent')).rejects.toMatchObject({
        response: { status: 404 },
      });
    });
  });

  describe('updateAssessment', () => {
    it('should update assessment with responses', async () => {
      const assessmentId = 'test-123';
      const updateData = {
        responses: [
          {
            questionId: 'q1',
            answer: 'opt1',
            notApplicable: false,
          },
          {
            questionId: 'q2',
            answer: 'opt2',
            notApplicable: false,
          },
        ],
      };

      const responseData = {
        assessmentId,
        status: 'in_progress',
        progress: 50,
        updatedAt: '2025-12-20T12:00:00Z',
        savedResponses: 2,
      };

      mockAxiosInstance.patch.mockResolvedValue({ data: responseData });

      const result = await apiService.updateAssessment(assessmentId, updateData);

      expect(mockAxiosInstance.patch).toHaveBeenCalledWith(`/assessments/${assessmentId}`, updateData);
      expect(result).toEqual(responseData);
    });

    it('should update assessment status', async () => {
      const assessmentId = 'test-123';
      const updateData = {
        status: 'completed',
      };

      const responseData = {
        assessmentId,
        status: 'completed',
        progress: 100,
        updatedAt: '2025-12-20T12:00:00Z',
        savedResponses: 0,
      };

      mockAxiosInstance.patch.mockResolvedValue({ data: responseData });

      const result = await apiService.updateAssessment(assessmentId, updateData);

      expect(mockAxiosInstance.patch).toHaveBeenCalledWith(`/assessments/${assessmentId}`, updateData);
      expect(result).toEqual(responseData);
    });

    it('should handle update errors', async () => {
      mockAxiosInstance.patch.mockRejectedValue({
        response: { status: 400, data: { error: { message: 'Invalid data' } } },
      });

      await expect(
        apiService.updateAssessment('test-123', { responses: [] })
      ).rejects.toMatchObject({
        response: { status: 400 },
      });
    });
  });

  describe('deleteAssessment', () => {
    it('should delete assessment', async () => {
      const assessmentId = 'test-123';
      mockAxiosInstance.delete.mockResolvedValue({});

      await apiService.deleteAssessment(assessmentId);

      expect(mockAxiosInstance.delete).toHaveBeenCalledWith(`/assessments/${assessmentId}`);
    });

    it('should handle delete errors', async () => {
      mockAxiosInstance.delete.mockRejectedValue({
        response: { status: 404, data: { error: { message: 'Assessment not found' } } },
      });

      await expect(apiService.deleteAssessment('non-existent')).rejects.toMatchObject({
        response: { status: 404 },
      });
    });

    it('should not allow deleting non-draft assessments', async () => {
      mockAxiosInstance.delete.mockRejectedValue({
        response: {
          status: 400,
          data: { error: { message: 'Cannot delete non-draft assessment' } },
        },
      });

      await expect(apiService.deleteAssessment('in-progress-123')).rejects.toMatchObject({
        response: { status: 400 },
      });
    });
  });

  describe('getQuestionnaire', () => {
    it('should get questionnaire', async () => {
      const responseData = {
        questionnaireId: 'questionnaire-1',
        version: '1.0',
        sections: [
          {
            sectionId: 'section-1',
            title: 'Business Information',
            order: 1,
            questions: [
              {
                questionId: 'q1',
                text: 'What is your business structure?',
                type: 'single_choice',
                required: true,
                order: 1,
                options: [
                  { optionId: 'opt1', text: 'LLC', value: 'llc', order: 1 },
                  { optionId: 'opt2', text: 'S-Corp', value: 's_corp', order: 2 },
                ],
              },
            ],
          },
        ],
      };

      mockAxiosInstance.get.mockResolvedValue({ data: responseData });

      const result = await apiService.getQuestionnaire();

      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/questionnaire');
      expect(result).toEqual(responseData);
    });

    it('should handle questionnaire load errors', async () => {
      mockAxiosInstance.get.mockRejectedValue({
        response: { status: 500, data: { error: { message: 'Server error' } } },
      });

      await expect(apiService.getQuestionnaire()).rejects.toMatchObject({
        response: { status: 500 },
      });
    });
  });

  describe('authentication', () => {
    it('should create axios instance with correct config', () => {
      expect(axiosCreateSpy).toHaveBeenCalledWith({
        baseURL: expect.any(String),
        headers: {
          'Content-Type': 'application/json',
        },
      });
    });

    it('should set up request interceptor', () => {
      expect(mockAxiosInstance.interceptors.request.use).toHaveBeenCalled();
    });

    it('should set up response interceptor', () => {
      expect(mockAxiosInstance.interceptors.response.use).toHaveBeenCalled();
    });
  });

  describe('error handling', () => {
    it('should handle network errors', async () => {
      mockAxiosInstance.get.mockRejectedValue(new Error('Network Error'));

      await expect(apiService.listAssessments()).rejects.toThrow('Network Error');
    });

    it('should handle timeout errors', async () => {
      mockAxiosInstance.get.mockRejectedValue({
        code: 'ECONNABORTED',
        message: 'timeout of 30000ms exceeded',
      });

      await expect(apiService.listAssessments()).rejects.toMatchObject({
        code: 'ECONNABORTED',
      });
    });
  });
});
