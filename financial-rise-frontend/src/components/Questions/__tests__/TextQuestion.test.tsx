import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { TextQuestion } from '../TextQuestion';
import type { Question } from '@/types';

describe('TextQuestion', () => {
  const mockQuestion: Question = {
    questionId: 'q4',
    text: 'Describe your current financial challenges',
    type: 'text',
    required: true,
    order: 1,
  };

  it('should render question text', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('Describe your current financial challenges')).toBeInTheDocument();
  });

  it('should render multiline text field', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const textField = screen.getByPlaceholderText('Enter your response...') as HTMLTextAreaElement;
    expect(textField).toBeInTheDocument();
    expect(textField.tagName).toBe('TEXTAREA');
  });

  it('should show character limit helper text for required question', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('* Required - Maximum 1000 characters')).toBeInTheDocument();
  });

  it('should show character limit helper text for optional question', () => {
    const optionalQuestion = { ...mockQuestion, required: false };
    render(<TextQuestion question={optionalQuestion} value={null} onChange={vi.fn()} />);
    expect(screen.getByText('Maximum 1000 characters')).toBeInTheDocument();
  });

  it('should call onChange when text is entered', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<TextQuestion question={mockQuestion} value={null} onChange={handleChange} />);

    const textField = screen.getByPlaceholderText('Enter your response...');
    await user.type(textField, 'Cash flow is inconsistent');

    expect(handleChange).toHaveBeenCalled();
    // Check the last call
    const lastCall = handleChange.mock.calls[handleChange.mock.calls.length - 1];
    expect(lastCall[0]).toBe('Cash flow is inconsistent');
  });

  it('should display current value', () => {
    const existingText = 'We struggle with timely invoicing and collections';
    render(<TextQuestion question={mockQuestion} value={existingText} onChange={vi.fn()} />);

    const textField = screen.getByPlaceholderText('Enter your response...') as HTMLTextAreaElement;
    expect(textField.value).toBe(existingText);
  });

  it('should handle null value gracefully', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const textField = screen.getByPlaceholderText('Enter your response...') as HTMLTextAreaElement;
    expect(textField.value).toBe('');
  });

  it('should handle empty string value', () => {
    render(<TextQuestion question={mockQuestion} value="" onChange={vi.fn()} />);
    const textField = screen.getByPlaceholderText('Enter your response...') as HTMLTextAreaElement;
    expect(textField.value).toBe('');
  });

  it('should be disabled when disabled prop is true', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} disabled />);
    const textField = screen.getByPlaceholderText('Enter your response...') as HTMLTextAreaElement;
    expect(textField.disabled).toBe(true);
  });

  it('should have maxLength attribute of 1000', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const textField = screen.getByPlaceholderText('Enter your response...') as HTMLTextAreaElement;
    expect(textField.maxLength).toBe(1000);
  });

  it('should have accessible ARIA labels', () => {
    render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const textField = screen.getByPlaceholderText('Enter your response...');
    expect(textField).toHaveAttribute('aria-label', 'Describe your current financial challenges');
    expect(textField).toHaveAttribute('aria-required', 'true');
  });

  it('should not have aria-required when not required', () => {
    const optionalQuestion = { ...mockQuestion, required: false };
    render(<TextQuestion question={optionalQuestion} value={null} onChange={vi.fn()} />);
    const textField = screen.getByPlaceholderText('Enter your response...');
    expect(textField).toHaveAttribute('aria-required', 'false');
  });

  it('should allow multiline input', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<TextQuestion question={mockQuestion} value={null} onChange={handleChange} />);

    const textField = screen.getByPlaceholderText('Enter your response...');
    await user.type(textField, 'Line 1{Enter}Line 2{Enter}Line 3');

    expect(handleChange).toHaveBeenCalled();
    const lastCall = handleChange.mock.calls[handleChange.mock.calls.length - 1];
    expect(lastCall[0]).toContain('\n');
  });

  it('should update value when typing', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<TextQuestion question={mockQuestion} value="" onChange={handleChange} />);

    const textField = screen.getByPlaceholderText('Enter your response...');
    await user.type(textField, 'Test');

    expect(handleChange).toHaveBeenCalledTimes(4); // Once for each character
  });

  it('should clear value when emptied', async () => {
    const user = userEvent.setup();
    const handleChange = vi.fn();
    render(<TextQuestion question={mockQuestion} value="Initial text" onChange={handleChange} />);

    const textField = screen.getByPlaceholderText('Enter your response...');
    await user.clear(textField);

    expect(handleChange).toHaveBeenCalledWith('');
  });

  it('should have 4 rows by default', () => {
    const { container } = render(<TextQuestion question={mockQuestion} value={null} onChange={vi.fn()} />);
    const textField = container.querySelector('textarea');
    expect(textField).toHaveAttribute('rows', '4');
  });
});
