import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { Questionnaire } from '../Questionnaire';
import { apiService } from '@/services/api';
import { useAssessmentStore } from '@/store/assessmentStore';
import { useAutoSave } from '@/hooks/useAutoSave';
import { AssessmentDetail, AssessmentStatus, Questionnaire as QuestionnaireType, Question } from '@/types';

// Mock dependencies
vi.mock('@/services/api');
vi.mock('@/store/assessmentStore');
vi.mock('@/hooks/useAutoSave');

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Questionnaire', () => {
  const mockAssessment: AssessmentDetail = {
    assessmentId: 'test-123',
    clientName: 'John Doe',
    businessName: 'Acme Corp',
    clientEmail: 'john@acme.com',
    status: AssessmentStatus.IN_PROGRESS,
    progress: 33,
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

  const mockQuestionnaire: QuestionnaireType = {
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
          {
            questionId: 'q2',
            text: 'Rate your financial confidence',
            type: 'rating',
            required: true,
            order: 2,
          },
          {
            questionId: 'q3',
            text: 'Describe your challenges',
            type: 'text',
            required: false,
            order: 3,
          },
        ],
      },
    ],
  };

  const mockSetCurrentAssessment = vi.fn();
  const mockSetCurrentQuestionIndex = vi.fn();
  const mockSetResponse = vi.fn();
  const mockSetResponses = vi.fn();
  const mockReset = vi.fn();
  const mockSaveNow = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 0,
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map([['q1', { questionId: 'q1', answer: 'opt1', notApplicable: false }]]),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: false,
      lastSavedAt: new Date('2025-12-20T11:00:00Z'),
      reset: mockReset,
    });

    (useAutoSave as any).mockReturnValue({
      saveNow: mockSaveNow,
      isSaving: false,
    });

    (apiService.getAssessment as any).mockResolvedValue(mockAssessment);
    (apiService.getQuestionnaire as any).mockResolvedValue(mockQuestionnaire);
  });

  const renderWithRouter = (assessmentId = 'test-123') => {
    return render(
      <MemoryRouter initialEntries={[`/assessment/${assessmentId}`]}>
        <Routes>
          <Route path="/assessment/:assessmentId" element={<Questionnaire />} />
        </Routes>
      </MemoryRouter>
    );
  };

  it('should show loading state initially', () => {
    renderWithRouter();
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('should load assessment and questionnaire', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(apiService.getAssessment).toHaveBeenCalledWith('test-123');
      expect(apiService.getQuestionnaire).toHaveBeenCalled();
      expect(mockSetCurrentAssessment).toHaveBeenCalledWith(mockAssessment);
      expect(mockSetResponses).toHaveBeenCalledWith(mockAssessment.responses);
    });
  });

  it('should display assessment details', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
      expect(screen.getByText('John Doe')).toBeInTheDocument();
    });
  });

  it('should display error when loading fails', async () => {
    (apiService.getAssessment as any).mockRejectedValue({
      response: { data: { error: { message: 'Failed to load' } } },
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Failed to load')).toBeInTheDocument();
    });
  });

  it('should render current question', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('What is your business structure?')).toBeInTheDocument();
    });
  });

  it('should display question progress indicator', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Question 1 of 3')).toBeInTheDocument();
    });
  });

  it('should display progress bar', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('33%')).toBeInTheDocument();
    });
  });

  it('should display auto-save indicator', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText(/Saved.*ago/)).toBeInTheDocument();
    });
  });

  it('should navigate to next question when Next is clicked', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('What is your business structure?')).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /Next/i }));
    expect(mockSetCurrentQuestionIndex).toHaveBeenCalledWith(1);
  });

  it('should navigate to previous question when Previous is clicked', async () => {
    const user = userEvent.setup();
    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 1,
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map(),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: false,
      lastSavedAt: new Date(),
      reset: mockReset,
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Previous/i })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /Previous/i }));
    expect(mockSetCurrentQuestionIndex).toHaveBeenCalledWith(0);
  });

  it('should disable Previous button on first question', async () => {
    renderWithRouter();

    await waitFor(() => {
      const prevButton = screen.getByRole('button', { name: /Previous/i });
      expect(prevButton).toBeDisabled();
    });
  });

  it('should show Complete button on last question', async () => {
    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 2, // Last question
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map(),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: false,
      lastSavedAt: new Date(),
      reset: mockReset,
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Complete Assessment/i })).toBeInTheDocument();
    });
  });

  it('should handle Not Applicable checkbox', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByLabelText('Mark as Not Applicable')).toBeInTheDocument();
    });

    await user.click(screen.getByLabelText('Mark as Not Applicable'));

    expect(mockSetResponse).toHaveBeenCalledWith('q1', {
      questionId: 'q1',
      answer: null,
      notApplicable: true,
      consultantNotes: undefined,
    });
  });

  it('should handle consultant notes', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByPlaceholderText('Add private notes about this question...')).toBeInTheDocument();
    });

    const notesInput = screen.getByPlaceholderText('Add private notes about this question...');
    await user.type(notesInput, 'Important note');

    expect(mockSetResponse).toHaveBeenCalled();
  });

  it('should complete assessment when Complete button is clicked', async () => {
    const user = userEvent.setup();
    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 2,
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map(),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: false,
      lastSavedAt: new Date(),
      reset: mockReset,
    });

    (apiService.updateAssessment as any).mockResolvedValue({});

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Complete Assessment/i })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /Complete Assessment/i }));

    await waitFor(() => {
      expect(apiService.updateAssessment).toHaveBeenCalledWith('test-123', {
        status: 'completed',
      });
      expect(mockNavigate).toHaveBeenCalledWith('/dashboard');
    });
  });

  it('should save before completing if dirty', async () => {
    const user = userEvent.setup();
    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 2,
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map(),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: true, // Has unsaved changes
      lastSavedAt: new Date(),
      reset: mockReset,
    });

    (apiService.updateAssessment as any).mockResolvedValue({});
    mockSaveNow.mockResolvedValue(undefined);

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Complete Assessment/i })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /Complete Assessment/i }));

    await waitFor(() => {
      expect(mockSaveNow).toHaveBeenCalled();
      expect(apiService.updateAssessment).toHaveBeenCalledWith('test-123', {
        status: 'completed',
      });
    });
  });

  it.skip('should show alert when completion fails', { timeout: 10000 }, async () => {
    const user = userEvent.setup();
    window.alert = vi.fn();
    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 2,
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map(),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: false,
      lastSavedAt: new Date(),
      reset: mockReset,
    });

    (apiService.updateAssessment as any).mockRejectedValue({
      response: { data: { error: { message: 'Completion failed' } } },
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Complete Assessment/i })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /Complete Assessment/i }));

    await waitFor(() => {
      expect(window.alert).toHaveBeenCalledWith('Completion failed');
    });
  });

  it('should disable question when marked as Not Applicable', async () => {
    const user = userEvent.setup();
    (useAssessmentStore as any).mockReturnValue({
      currentAssessment: mockAssessment,
      setCurrentAssessment: mockSetCurrentAssessment,
      currentQuestionIndex: 0,
      setCurrentQuestionIndex: mockSetCurrentQuestionIndex,
      responses: new Map([
        ['q1', { questionId: 'q1', answer: null, notApplicable: true }],
      ]),
      setResponse: mockSetResponse,
      setResponses: mockSetResponses,
      isDirty: false,
      lastSavedAt: new Date(),
      reset: mockReset,
    });

    renderWithRouter();

    await waitFor(() => {
      const radios = screen.getAllByRole('radio');
      radios.forEach((radio) => {
        expect(radio).toBeDisabled();
      });
    });
  });

  it('should call reset on unmount', async () => {
    const { unmount } = renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    unmount();
    expect(mockReset).toHaveBeenCalled();
  });

  it('should have accessible consultant notes field', async () => {
    renderWithRouter();

    await waitFor(() => {
      const notesInput = screen.getByPlaceholderText('Add private notes about this question...');
      expect(notesInput).toHaveAttribute('aria-label', 'Consultant notes');
      expect(notesInput).toHaveAttribute('maxLength', '1000');
    });
  });
});
