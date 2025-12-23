import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { SingleChoiceQuestion } from '../SingleChoiceQuestion';
import type { Question } from '@/types';

describe('SingleChoiceQuestion', () => {
  const mockQuestion: Question = {
    questionId: 'q1',
    text: 'What is your business structure?',
    type: 'single_choice',
    required: true,
    order: 1,
    options: [
      { optionId: 'opt1', text: 'Sole Proprietorship', value: 'sole_proprietorship', order: 1 },
      { optionId: 'opt2', text: 'LLC', value: 'llc', order: 2 },
      { optionId: 'opt3', text: 'S-Corp', value: 's_corp', order: 3 },
      { optionId: 'opt4', text: 'C-Corp', value: 'c_corp', order: 4 },
    ],
  };

  it('should render question text', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('What is your business structure?')).toBeInTheDocument();
  });

  it('should render all options', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByLabelText('Sole Proprietorship')).toBeInTheDocument();
    expect(screen.getByLabelText('LLC')).toBeInTheDocument();
    expect(screen.getByLabelText('S-Corp')).toBeInTheDocument();
    expect(screen.getByLabelText('C-Corp')).toBeInTheDocument();
  });

  it('should show required indicator when required', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('* Required')).toBeInTheDocument();
  });

  it('should not show required indicator when not required', () => {
    const optionalQuestion = { ...mockQuestion, required: false };
    render(<SingleChoiceQuestion question={optionalQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.queryByText('* Required')).not.toBeInTheDocument();
  });

  it('should call onChange when option is selected', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={handleChange} />);

    await user.click(screen.getByLabelText('LLC'));
    expect(handleChange).toHaveBeenCalledWith('opt2');
  });

  it('should display selected value', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value="opt3" onChange={vi.fn()} />);
    const scorp = screen.getByLabelText('S-Corp') as HTMLInputElement;
    expect(scorp.checked).toBe(true);
  });

  it('should allow changing selection', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<SingleChoiceQuestion question={mockQuestion} value="opt1" onChange={handleChange} />);

    // Change from Sole Proprietorship to LLC
    await user.click(screen.getByLabelText('LLC'));
    expect(handleChange).toHaveBeenCalledWith('opt2');
  });

  it('should be disabled when disabled prop is true', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} disabled />);
    const radio = screen.getByLabelText('LLC') as HTMLInputElement;
    expect(radio.disabled).toBe(true);
  });

  it('should have accessible ARIA labels', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByRole('radiogroup')).toHaveAttribute(
      'aria-label',
      'What is your business structure?'
    );
  });

  it('should handle empty options array', () => {
    const questionWithoutOptions = { ...mockQuestion, options: [] };
    render(<SingleChoiceQuestion question={questionWithoutOptions} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('What is your business structure?')).toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });

  it('should handle null value gracefully', () => {
    render(<SingleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const radios = screen.getAllByRole('radio') as HTMLInputElement[];
    radios.forEach((radio) => {
      expect(radio.checked).toBe(false);
    });
  });
});
