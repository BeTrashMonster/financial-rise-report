import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { RatingQuestion } from '../RatingQuestion';
import type { Question } from '@/types';

describe('RatingQuestion', () => {
  const mockQuestion: Question = {
    questionId: 'q3',
    text: 'How confident are you in your current financial reporting?',
    type: 'rating',
    required: true,
    order: 1,
  };

  it('should render question text', () => {
    render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('How confident are you in your current financial reporting?')).toBeInTheDocument();
  });

  it('should render rating component with 5 stars', () => {
    render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    // Material-UI Rating renders buttons for each star + empty state (0-5 = 6 buttons)
    const ratingButtons = screen.getAllByRole('radio');
    expect(ratingButtons).toHaveLength(6);
  });

  it('should show required helper text when required', () => {
    render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('* Required')).toBeInTheDocument();
  });

  it('should not show required helper text when not required', () => {
    const optionalQuestion = { ...mockQuestion, required: false };
    render(<RatingQuestion question={optionalQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.queryByText('* Required')).not.toBeInTheDocument();
  });

  it('should call onChange when star is clicked', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<RatingQuestion question={mockQuestion} value={null} onChange={handleChange} />);

    const threeStarButton = screen.getByLabelText('3 Stars');
    await user.click(threeStarButton);
    expect(handleChange).toHaveBeenCalledWith(3);
  });

  it('should display current rating value', () => {
    render(<RatingQuestion question={mockQuestion} value={4} onChange={vi.fn()} />);
    expect(screen.getByText('4 / 5')).toBeInTheDocument();
  });

  it('should not display rating text when value is null', () => {
    render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.queryByText(/\/ 5/)).not.toBeInTheDocument();
  });

  it('should not display rating text when value is 0', () => {
    render(<RatingQuestion question={mockQuestion} value={0} onChange={vi.fn()} />);
    expect(screen.queryByText(/\/ 5/)).not.toBeInTheDocument();
  });

  it('should allow changing rating', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<RatingQuestion question={mockQuestion} value={3} onChange={handleChange} />);

    const fiveStarButton = screen.getByLabelText('5 Stars');
    await user.click(fiveStarButton);
    expect(handleChange).toHaveBeenCalledWith(5);
  });

  it('should be disabled when disabled prop is true', () => {
    render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} disabled />);
    const ratingButtons = screen.getAllByRole('radio');
    ratingButtons.forEach((button) => {
      expect(button).toBeDisabled();
    });
  });

  it('should have accessible ARIA label', () => {
    render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const ratingGroup = screen.getByLabelText('How confident are you in your current financial reporting?');
    expect(ratingGroup).toBeInTheDocument();
  });

  it('should display all rating values correctly', () => {
    const { rerender } = render(<RatingQuestion question={mockQuestion} value={1} onChange={vi.fn()} />);
    expect(screen.getByText('1 / 5')).toBeInTheDocument();

    rerender(<RatingQuestion question={mockQuestion} value={2} onChange={vi.fn()} />);
    expect(screen.getByText('2 / 5')).toBeInTheDocument();

    rerender(<RatingQuestion question={mockQuestion} value={3} onChange={vi.fn()} />);
    expect(screen.getByText('3 / 5')).toBeInTheDocument();

    rerender(<RatingQuestion question={mockQuestion} value={4} onChange={vi.fn()} />);
    expect(screen.getByText('4 / 5')).toBeInTheDocument();

    rerender(<RatingQuestion question={mockQuestion} value={5} onChange={vi.fn()} />);
    expect(screen.getByText('5 / 5')).toBeInTheDocument();
  });

  it('should not call onChange when clicking current value and result is null', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<RatingQuestion question={mockQuestion} value={3} onChange={handleChange} />);

    // Material-UI Rating component might not call onChange with null when clicking the same value
    // This test ensures we handle the null check in our onChange handler
    const threeStarButton = screen.getByLabelText('3 Stars');
    await user.click(threeStarButton);

    // We expect it to either be called with 3 again, or not called at all, but never with null
    if (handleChange.mock.calls.length > 0) {
      expect(handleChange).not.toHaveBeenCalledWith(null);
    }
  });

  it('should render with size large', () => {
    const { container } = render(<RatingQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    // Material-UI Rating with size="large" adds specific CSS classes
    const rating = container.querySelector('.MuiRating-sizeLarge');
    expect(rating).toBeInTheDocument();
  });
});
