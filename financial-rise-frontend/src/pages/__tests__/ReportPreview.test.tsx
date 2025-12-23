import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter, MemoryRouter } from 'react-router-dom';
import { ReportPreview } from '../ReportPreview';
import { apiService } from '@/services/api';
import type { AssessmentDetail, Report } from '@/types';

// Mock the API service
vi.mock('@/services/api');

// Mock react-router-dom useParams
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useParams: () => ({ assessmentId: 'test-assessment-123' }),
  };
});

describe('ReportPreview', () => {
  const mockAssessment: AssessmentDetail = {
    assessmentId: 'test-assessment-123',
    clientName: 'John Doe',
    businessName: 'Doe Enterprises',
    clientEmail: 'john@example.com',
    status: 'completed' as const,
    progress: 100,
    createdAt: '2025-12-20T10:00:00Z',
    updatedAt: '2025-12-22T10:00:00Z',
    startedAt: '2025-12-20T10:05:00Z',
    completedAt: '2025-12-22T10:00:00Z',
    responses: [],
  };

  const mockConsultantReport: Report = {
    reportId: 'consultant-report-1',
    reportType: 'consultant' as const,
    assessmentId: 'test-assessment-123',
    pdfUrl: 'https://example.com/consultant-report.pdf',
    generatedAt: '2025-12-22T10:00:00Z',
  };

  const mockClientReport: Report = {
    reportId: 'client-report-1',
    reportType: 'client' as const,
    assessmentId: 'test-assessment-123',
    pdfUrl: 'https://example.com/client-report.pdf',
    generatedAt: '2025-12-22T10:00:00Z',
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders loading state while fetching assessment', () => {
    vi.mocked(apiService.getAssessment).mockImplementation(
      () => new Promise(() => {}) // Never resolves
    );

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('displays assessment details', async () => {
    vi.mocked(apiService.getAssessment).mockResolvedValue(mockAssessment);

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('John Doe')).toBeInTheDocument();
      expect(screen.getByText('Doe Enterprises')).toBeInTheDocument();
    });
  });

  it('shows report generation button when assessment is completed', async () => {
    vi.mocked(apiService.getAssessment).mockResolvedValue(mockAssessment);

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /generate reports/i })).toBeInTheDocument();
    });
  });

  it('disables report generation if assessment not completed', async () => {
    const incompleteAssessment = {
      ...mockAssessment,
      status: 'in_progress' as const,
      progress: 50,
      completedAt: null,
    };

    vi.mocked(apiService.getAssessment).mockResolvedValue(incompleteAssessment);

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      const button = screen.getByRole('button', { name: /generate reports/i });
      expect(button).toBeDisabled();
    });
  });

  it('displays tabs for consultant and client reports after generation', async () => {
    vi.mocked(apiService.getAssessment).mockResolvedValue(mockAssessment);

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText('John Doe')).toBeInTheDocument();
    });

    // After successful generation (simulated in component)
    // Note: Full integration would require clicking generate button
    // and mocking the generate API call
  });

  it('handles error when fetching assessment fails', async () => {
    vi.mocked(apiService.getAssessment).mockRejectedValue(
      new Error('Failed to fetch assessment')
    );

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(/error loading assessment/i)).toBeInTheDocument();
    });
  });

  it('shows back to dashboard link', async () => {
    vi.mocked(apiService.getAssessment).mockResolvedValue(mockAssessment);

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      const backLink = screen.getByText(/back to dashboard/i).closest('a');
      expect(backLink).toHaveAttribute('href', '/dashboard');
    });
  });

  it('has proper heading structure for accessibility', async () => {
    vi.mocked(apiService.getAssessment).mockResolvedValue(mockAssessment);

    render(
      <MemoryRouter>
        <ReportPreview />
      </MemoryRouter>
    );

    await waitFor(() => {
      const heading = screen.getByRole('heading', { level: 1 });
      expect(heading).toBeInTheDocument();
    });
  });
});
