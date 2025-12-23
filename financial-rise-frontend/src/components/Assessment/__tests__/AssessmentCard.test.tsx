import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { AssessmentCard } from '../AssessmentCard';
import { Assessment, AssessmentStatus } from '@/types';

describe('AssessmentCard', () => {
  const mockDraftAssessment: Assessment = {
    assessmentId: 'draft-123',
    clientName: 'John Doe',
    businessName: 'Acme Corp',
    clientEmail: 'john@acme.com',
    status: AssessmentStatus.DRAFT,
    progress: 0,
    createdAt: '2025-12-15T10:00:00Z',
    updatedAt: '2025-12-15T10:00:00Z',
  };

  const mockInProgressAssessment: Assessment = {
    assessmentId: 'in-progress-456',
    clientName: 'Jane Smith',
    businessName: 'Smith LLC',
    clientEmail: 'jane@smithllc.com',
    status: AssessmentStatus.IN_PROGRESS,
    progress: 45,
    createdAt: '2025-12-10T10:00:00Z',
    updatedAt: '2025-12-18T14:30:00Z',
  };

  const mockCompletedAssessment: Assessment = {
    assessmentId: 'completed-789',
    clientName: 'Bob Johnson',
    businessName: 'Johnson Industries',
    clientEmail: 'bob@johnson.com',
    status: AssessmentStatus.COMPLETED,
    progress: 100,
    createdAt: '2025-12-01T10:00:00Z',
    updatedAt: '2025-12-20T09:15:00Z',
  };

  it('should render business name', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('Acme Corp')).toBeInTheDocument();
  });

  it('should render client name', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('John Doe')).toBeInTheDocument();
  });

  it('should render formatted updated date', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText(/Updated Dec 15, 2025/)).toBeInTheDocument();
  });

  it('should render draft status chip', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('Draft')).toBeInTheDocument();
  });

  it('should render in progress status chip', () => {
    render(<AssessmentCard assessment={mockInProgressAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('In Progress')).toBeInTheDocument();
  });

  it('should render completed status chip', () => {
    render(<AssessmentCard assessment={mockCompletedAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('Completed')).toBeInTheDocument();
  });

  it('should render progress indicator', () => {
    render(<AssessmentCard assessment={mockInProgressAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
  });

  it('should show "Continue" button for draft assessment', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: /Continue/i })).toBeInTheDocument();
  });

  it('should show "Continue" button for in progress assessment', () => {
    render(<AssessmentCard assessment={mockInProgressAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: /Continue/i })).toBeInTheDocument();
  });

  it('should show "View" button for completed assessment', () => {
    render(<AssessmentCard assessment={mockCompletedAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: /View/i })).toBeInTheDocument();
  });

  it('should show delete button only for draft assessments', () => {
    const { rerender } = render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: /Delete draft assessment/i })).toBeInTheDocument();

    rerender(<AssessmentCard assessment={mockInProgressAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.queryByRole('button', { name: /Delete/i })).not.toBeInTheDocument();

    rerender(<AssessmentCard assessment={mockCompletedAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.queryByRole('button', { name: /Delete/i })).not.toBeInTheDocument();
  });

  it('should call onEdit when Continue button is clicked', async () => {
    const user = userEvent.setup();
    const handleEdit = vi.fn();
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={handleEdit} onDelete={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: /Continue/i }));
    expect(handleEdit).toHaveBeenCalledWith('draft-123');
  });

  it('should call onEdit when View button is clicked', async () => {
    const user = userEvent.setup();
    const handleEdit = vi.fn();
    render(<AssessmentCard assessment={mockCompletedAssessment} onEdit={handleEdit} onDelete={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: /View/i }));
    expect(handleEdit).toHaveBeenCalledWith('completed-789');
  });

  it('should call onDelete when delete button is clicked', async () => {
    const user = userEvent.setup();
    const handleDelete = vi.fn();
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={handleDelete} />);

    await user.click(screen.getByRole('button', { name: /Delete draft assessment/i }));
    expect(handleDelete).toHaveBeenCalledWith('draft-123');
  });

  it('should have accessible aria labels for edit button', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Edit assessment for Acme Corp' })).toBeInTheDocument();
  });

  it('should have accessible aria labels for delete button', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByRole('button', { name: 'Delete draft assessment for Acme Corp' })).toBeInTheDocument();
  });

  it('should render with proper card structure', () => {
    const { container } = render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    const card = container.querySelector('.MuiCard-root');
    expect(card).toBeInTheDocument();
  });

  it('should display correct progress value', () => {
    render(<AssessmentCard assessment={mockInProgressAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('45%')).toBeInTheDocument();
  });

  it('should display 100% progress for completed assessment', () => {
    render(<AssessmentCard assessment={mockCompletedAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('100%')).toBeInTheDocument();
  });

  it('should display 0% progress for draft assessment', () => {
    render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    expect(screen.getByText('0%')).toBeInTheDocument();
  });

  it('should render edit icon in button', () => {
    const { container } = render(<AssessmentCard assessment={mockDraftAssessment} onEdit={vi.fn()} onDelete={vi.fn()} />);
    const editIcon = container.querySelector('[data-testid="EditIcon"]');
    expect(editIcon).toBeInTheDocument();
  });
});
