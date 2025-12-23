import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BrowserRouter } from 'react-router-dom';
import { Dashboard } from '../Dashboard';
import { apiService } from '@/services/api';
import { useAssessmentStore } from '@/store/assessmentStore';
import { Assessment, AssessmentStatus } from '@/types';

// Mock dependencies
vi.mock('@/services/api');
vi.mock('@/store/assessmentStore');

const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

describe('Dashboard', () => {
  const mockAssessments: Assessment[] = [
    {
      assessmentId: 'draft-1',
      clientName: 'John Doe',
      businessName: 'Acme Corp',
      status: AssessmentStatus.DRAFT,
      progress: 0,
      createdAt: '2025-12-15T10:00:00Z',
      updatedAt: '2025-12-15T10:00:00Z',
    },
    {
      assessmentId: 'in-progress-2',
      clientName: 'Jane Smith',
      businessName: 'Smith LLC',
      status: AssessmentStatus.IN_PROGRESS,
      progress: 45,
      createdAt: '2025-12-10T10:00:00Z',
      updatedAt: '2025-12-18T14:30:00Z',
    },
    {
      assessmentId: 'completed-3',
      clientName: 'Bob Johnson',
      businessName: 'Johnson Industries',
      status: AssessmentStatus.COMPLETED,
      progress: 100,
      createdAt: '2025-12-01T10:00:00Z',
      updatedAt: '2025-12-20T09:15:00Z',
    },
  ];

  const mockSetAssessments = vi.fn();
  const mockRemoveAssessment = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    (useAssessmentStore as any).mockReturnValue({
      assessments: mockAssessments,
      setAssessments: mockSetAssessments,
      removeAssessment: mockRemoveAssessment,
    });

    (apiService.listAssessments as any).mockResolvedValue({
      assessments: mockAssessments,
      total: mockAssessments.length,
    });
  });

  const renderWithRouter = () => {
    return render(
      <BrowserRouter>
        <Dashboard />
      </BrowserRouter>
    );
  };

  it('should render page title', async () => {
    renderWithRouter();
    await waitFor(() => {
      expect(screen.getByText('Assessments')).toBeInTheDocument();
    });
  });

  it('should render New Assessment button', async () => {
    renderWithRouter();
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Create new assessment' })).toBeInTheDocument();
    });
  });

  it('should show loading state initially', () => {
    renderWithRouter();
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('should load and display assessments', async () => {
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
      expect(screen.getByText('Smith LLC')).toBeInTheDocument();
      expect(screen.getByText('Johnson Industries')).toBeInTheDocument();
    });

    expect(apiService.listAssessments).toHaveBeenCalledWith({
      sortBy: 'updatedAt',
      sortOrder: 'desc',
    });
    expect(mockSetAssessments).toHaveBeenCalledWith(mockAssessments);
  });

  it('should display error message on load failure', async () => {
    (apiService.listAssessments as any).mockRejectedValue({
      response: { data: { error: { message: 'Network error' } } },
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  it('should navigate to create page when New Assessment is clicked', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Create new assessment' })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: 'Create new assessment' }));
    expect(mockNavigate).toHaveBeenCalledWith('/assessment/create');
  });

  it('should filter assessments by search query', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Search by client or business name...');
    await user.type(searchInput, 'Smith');

    await waitFor(() => {
      expect(screen.getByText('Smith LLC')).toBeInTheDocument();
      expect(screen.queryByText('Acme Corp')).not.toBeInTheDocument();
      expect(screen.queryByText('Johnson Industries')).not.toBeInTheDocument();
    });
  });

  it.skip('should filter assessments by status', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const statusFilter = screen.getByLabelText('Filter by status');
    await user.click(statusFilter);

    const draftOption = screen.getByRole('option', { name: 'Draft' });
    await user.click(draftOption);

    await waitFor(() => {
      expect(apiService.listAssessments).toHaveBeenCalledWith({
        sortBy: 'updatedAt',
        sortOrder: 'desc',
        status: 'draft',
      });
    });
  });

  it('should show empty state when no assessments exist', async () => {
    (useAssessmentStore as any).mockReturnValue({
      assessments: [],
      setAssessments: mockSetAssessments,
      removeAssessment: mockRemoveAssessment,
    });

    (apiService.listAssessments as any).mockResolvedValue({
      assessments: [],
      total: 0,
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('No assessments yet')).toBeInTheDocument();
      expect(screen.getByText('Get started by creating your first assessment')).toBeInTheDocument();
    });
  });

  it('should show filtered empty state when search returns no results', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const searchInput = screen.getByPlaceholderText('Search by client or business name...');
    await user.type(searchInput, 'NonExistent');

    await waitFor(() => {
      expect(screen.getByText('No assessments found')).toBeInTheDocument();
      expect(screen.getByText('Try adjusting your filters')).toBeInTheDocument();
    });
  });

  it('should navigate to questionnaire when edit is clicked', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const editButtons = screen.getAllByRole('button', { name: /Edit assessment for/i });
    await user.click(editButtons[0]);

    expect(mockNavigate).toHaveBeenCalledWith('/assessment/draft-1');
  });

  it('should delete assessment when delete is confirmed', async () => {
    const user = userEvent.setup();
    window.confirm = vi.fn(() => true);
    (apiService.deleteAssessment as any).mockResolvedValue({});

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const deleteButton = screen.getByRole('button', { name: 'Delete draft assessment for Acme Corp' });
    await user.click(deleteButton);

    await waitFor(() => {
      expect(window.confirm).toHaveBeenCalledWith('Are you sure you want to delete this draft assessment?');
      expect(apiService.deleteAssessment).toHaveBeenCalledWith('draft-1');
      expect(mockRemoveAssessment).toHaveBeenCalledWith('draft-1');
    });
  });

  it('should not delete assessment when delete is cancelled', async () => {
    const user = userEvent.setup();
    window.confirm = vi.fn(() => false);

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const deleteButton = screen.getByRole('button', { name: 'Delete draft assessment for Acme Corp' });
    await user.click(deleteButton);

    expect(window.confirm).toHaveBeenCalled();
    expect(apiService.deleteAssessment).not.toHaveBeenCalled();
    expect(mockRemoveAssessment).not.toHaveBeenCalled();
  });

  it('should show alert when delete fails', async () => {
    const user = userEvent.setup();
    window.confirm = vi.fn(() => true);
    window.alert = vi.fn();
    (apiService.deleteAssessment as any).mockRejectedValue({
      response: { data: { error: { message: 'Delete failed' } } },
    });

    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByText('Acme Corp')).toBeInTheDocument();
    });

    const deleteButton = screen.getByRole('button', { name: 'Delete draft assessment for Acme Corp' });
    await user.click(deleteButton);

    await waitFor(() => {
      expect(window.alert).toHaveBeenCalledWith('Delete failed');
    });
  });

  it('should render search input with correct placeholder', async () => {
    renderWithRouter();
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Search by client or business name...')).toBeInTheDocument();
    });
  });

  it.skip('should render status filter with all options', async () => {
    const user = userEvent.setup();
    renderWithRouter();

    await waitFor(() => {
      expect(screen.getByLabelText('Filter by status')).toBeInTheDocument();
    });

    const statusFilter = screen.getByLabelText('Filter by status');
    await user.click(statusFilter);

    expect(screen.getByRole('option', { name: 'All' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Draft' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'In Progress' })).toBeInTheDocument();
    expect(screen.getByRole('option', { name: 'Completed' })).toBeInTheDocument();
  });
});
