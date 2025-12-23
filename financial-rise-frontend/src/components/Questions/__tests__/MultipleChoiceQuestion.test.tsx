import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { MultipleChoiceQuestion } from '../MultipleChoiceQuestion';
import type { Question } from '@/types';

describe('MultipleChoiceQuestion', () => {
  const mockQuestion: Question = {
    questionId: 'q2',
    text: 'Which financial systems do you use? (Select all that apply)',
    type: 'multiple_choice',
    required: true,
    order: 1,
    options: [
      { optionId: 'opt1', text: 'QuickBooks', value: 'quickbooks', order: 1 },
      { optionId: 'opt2', text: 'Xero', value: 'xero', order: 2 },
      { optionId: 'opt3', text: 'FreshBooks', value: 'freshbooks', order: 3 },
      { optionId: 'opt4', text: 'Wave', value: 'wave', order: 4 },
    ],
  };

  it('should render question text', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('Which financial systems do you use? (Select all that apply)')).toBeInTheDocument();
  });

  it('should render all options as checkboxes', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByLabelText('QuickBooks')).toBeInTheDocument();
    expect(screen.getByLabelText('Xero')).toBeInTheDocument();
    expect(screen.getByLabelText('FreshBooks')).toBeInTheDocument();
    expect(screen.getByLabelText('Wave')).toBeInTheDocument();
  });

  it('should show required helper text when required', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('* Required - Select at least one option')).toBeInTheDocument();
  });

  it('should not show required helper text when not required', () => {
    const optionalQuestion = { ...mockQuestion, required: false };
    render(<MultipleChoiceQuestion question={optionalQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.queryByText('* Required - Select at least one option')).not.toBeInTheDocument();
  });

  it('should call onChange with new selection when checkbox is checked', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<MultipleChoiceQuestion question={mockQuestion} value={[]} onChange={handleChange} />);

    await user.click(screen.getByLabelText('QuickBooks'));
    expect(handleChange).toHaveBeenCalledWith(['opt1']);
  });

  it('should call onChange with updated array when adding to existing selection', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<MultipleChoiceQuestion question={mockQuestion} value={['opt1']} onChange={handleChange} />);

    await user.click(screen.getByLabelText('Xero'));
    expect(handleChange).toHaveBeenCalledWith(['opt1', 'opt2']);
  });

  it('should call onChange with filtered array when unchecking', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<MultipleChoiceQuestion question={mockQuestion} value={['opt1', 'opt2', 'opt3']} onChange={handleChange} />);

    await user.click(screen.getByLabelText('Xero'));
    expect(handleChange).toHaveBeenCalledWith(['opt1', 'opt3']);
  });

  it('should display selected values as checked', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={['opt1', 'opt3']} onChange={vi.fn()} />);

    const quickbooks = screen.getByLabelText('QuickBooks') as HTMLInputElement;
    const xero = screen.getByLabelText('Xero') as HTMLInputElement;
    const freshbooks = screen.getByLabelText('FreshBooks') as HTMLInputElement;
    const wave = screen.getByLabelText('Wave') as HTMLInputElement;

    expect(quickbooks.checked).toBe(true);
    expect(xero.checked).toBe(false);
    expect(freshbooks.checked).toBe(true);
    expect(wave.checked).toBe(false);
  });

  it('should handle selecting all options', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<MultipleChoiceQuestion question={mockQuestion} value={[]} onChange={handleChange} />);

    await user.click(screen.getByLabelText('QuickBooks'));
    expect(handleChange).toHaveBeenNthCalledWith(1, ['opt1']);

    await user.click(screen.getByLabelText('Xero'));
    expect(handleChange).toHaveBeenNthCalledWith(2, ['opt2']);
  });

  it('should be disabled when disabled prop is true', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} disabled />);
    const checkbox = screen.getByLabelText('QuickBooks') as HTMLInputElement;
    expect(checkbox.disabled).toBe(true);
  });

  it('should handle null value as empty array', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
    checkboxes.forEach((checkbox) => {
      expect(checkbox.checked).toBe(false);
    });
  });

  it('should handle empty value array', () => {
    render(<MultipleChoiceQuestion question={mockQuestion} value={[]} onChange={vi.fn()} />);
    const checkboxes = screen.getAllByRole('checkbox') as HTMLInputElement[];
    checkboxes.forEach((checkbox) => {
      expect(checkbox.checked).toBe(false);
    });
  });

  it('should handle unchecking the only selected item', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<MultipleChoiceQuestion question={mockQuestion} value={['opt2']} onChange={handleChange} />);

    await user.click(screen.getByLabelText('Xero'));
    expect(handleChange).toHaveBeenCalledWith([]);
  });

  it('should handle empty options array', () => {
    const questionWithoutOptions = { ...mockQuestion, options: [] };
    render(<MultipleChoiceQuestion question={questionWithoutOptions} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('Which financial systems do you use? (Select all that apply)')).toBeInTheDocument();
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
  });
});
