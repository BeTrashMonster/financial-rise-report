import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ReportGenerationButton } from '../ReportGenerationButton';
import { apiService } from '@/services/api';
import type { GenerateReportsResponse } from '@/types';

// Mock the API service
vi.mock('@/services/api');

describe('ReportGenerationButton', () => {
  const mockAssessmentId = 'test-assessment-123';
  const mockOnSuccess = vi.fn();
  const mockOnError = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the generate reports button', () => {
    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    expect(screen.getByRole('button', { name: /generate reports/i })).toBeInTheDocument();
  });

  it('shows loading state when generating reports', async () => {
    // Mock API to delay response
    vi.mocked(apiService.generateBothReports).mockImplementation(
      () => new Promise((resolve) => setTimeout(resolve, 1000))
    );

    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    const button = screen.getByRole('button', { name: /generate reports/i });
    fireEvent.click(button);

    // Should show loading state
    await waitFor(() => {
      expect(screen.getByText(/generating/i)).toBeInTheDocument();
    });

    // Button should be disabled during loading
    expect(button).toBeDisabled();
  });

  it('calls API and onSuccess callback when generation succeeds', async () => {
    const mockResponse: GenerateReportsResponse = {
      success: true,
      data: {
        consultantReport: {
          reportId: 'consultant-report-1',
          reportType: 'consultant' as const,
          assessmentId: mockAssessmentId,
          pdfUrl: 'https://example.com/consultant-report.pdf',
          generatedAt: '2025-12-22T10:00:00Z',
        },
        clientReport: {
          reportId: 'client-report-1',
          reportType: 'client' as const,
          assessmentId: mockAssessmentId,
          pdfUrl: 'https://example.com/client-report.pdf',
          generatedAt: '2025-12-22T10:00:00Z',
        },
      },
    };

    vi.mocked(apiService.generateBothReports).mockResolvedValue(mockResponse);

    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    const button = screen.getByRole('button', { name: /generate reports/i });
    fireEvent.click(button);

    await waitFor(() => {
      expect(apiService.generateBothReports).toHaveBeenCalledWith(mockAssessmentId);
      expect(mockOnSuccess).toHaveBeenCalledWith(mockResponse.data);
    });

    // Should show success message
    expect(screen.getByText(/reports generated successfully/i)).toBeInTheDocument();
  });

  it('calls onError callback when generation fails', async () => {
    const mockError = new Error('Generation failed');
    vi.mocked(apiService.generateBothReports).mockRejectedValue(mockError);

    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    const button = screen.getByRole('button', { name: /generate reports/i });
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockOnError).toHaveBeenCalledWith(mockError);
    });

    // Should show error message
    expect(screen.getByText(/failed to generate reports/i)).toBeInTheDocument();
  });

  it('shows download links after successful generation', async () => {
    const mockResponse: GenerateReportsResponse = {
      success: true,
      data: {
        consultantReport: {
          reportId: 'consultant-report-1',
          reportType: 'consultant' as const,
          assessmentId: mockAssessmentId,
          pdfUrl: 'https://example.com/consultant-report.pdf',
          generatedAt: '2025-12-22T10:00:00Z',
        },
        clientReport: {
          reportId: 'client-report-1',
          reportType: 'client' as const,
          assessmentId: mockAssessmentId,
          pdfUrl: 'https://example.com/client-report.pdf',
          generatedAt: '2025-12-22T10:00:00Z',
        },
      },
    };

    vi.mocked(apiService.generateBothReports).mockResolvedValue(mockResponse);

    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    const button = screen.getByRole('button', { name: /generate reports/i });
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText(/download consultant report/i)).toBeInTheDocument();
      expect(screen.getByText(/download client report/i)).toBeInTheDocument();
    });

    // Links should have correct href
    const consultantLink = screen.getByText(/download consultant report/i).closest('a');
    const clientLink = screen.getByText(/download client report/i).closest('a');

    expect(consultantLink).toHaveAttribute('href', mockResponse.data.consultantReport.pdfUrl);
    expect(clientLink).toHaveAttribute('href', mockResponse.data.clientReport.pdfUrl);
  });

  it('can be disabled via prop', () => {
    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
        disabled
      />
    );

    const button = screen.getByRole('button', { name: /generate reports/i });
    expect(button).toBeDisabled();
  });

  it('allows regenerating reports after successful generation', async () => {
    const mockResponse: GenerateReportsResponse = {
      success: true,
      data: {
        consultantReport: {
          reportId: 'consultant-report-1',
          reportType: 'consultant' as const,
          assessmentId: mockAssessmentId,
          pdfUrl: 'https://example.com/consultant-report.pdf',
          generatedAt: '2025-12-22T10:00:00Z',
        },
        clientReport: {
          reportId: 'client-report-1',
          reportType: 'client' as const,
          assessmentId: mockAssessmentId,
          pdfUrl: 'https://example.com/client-report.pdf',
          generatedAt: '2025-12-22T10:00:00Z',
        },
      },
    };

    vi.mocked(apiService.generateBothReports).mockResolvedValue(mockResponse);

    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    // First generation
    const button = screen.getByRole('button', { name: /generate reports/i });
    fireEvent.click(button);

    await waitFor(() => {
      expect(screen.getByText(/reports generated successfully/i)).toBeInTheDocument();
    });

    // Should show regenerate button
    const regenerateButton = screen.getByRole('button', { name: /regenerate reports/i });
    expect(regenerateButton).toBeInTheDocument();

    // Click regenerate
    fireEvent.click(regenerateButton);

    await waitFor(() => {
      expect(apiService.generateBothReports).toHaveBeenCalledTimes(2);
    });
  });

  it('has accessible ARIA labels', () => {
    render(
      <ReportGenerationButton
        assessmentId={mockAssessmentId}
        onSuccess={mockOnSuccess}
        onError={mockOnError}
      />
    );

    const button = screen.getByRole('button', { name: /generate reports/i });
    expect(button).toHaveAccessibleName();
  });
});
