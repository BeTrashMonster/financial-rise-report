import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { ProgressIndicator } from '../ProgressIndicator';

describe('ProgressIndicator', () => {
  it('should render progress percentage', () => {
    render(<ProgressIndicator progress={50} />);
    expect(screen.getByText('50%')).toBeInTheDocument();
  });

  it('should render without label when showLabel is false', () => {
    render(<ProgressIndicator progress={75} showLabel={false} />);
    expect(screen.queryByText('75%')).not.toBeInTheDocument();
  });

  it('should have accessible label', () => {
    render(<ProgressIndicator progress={33} />);
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-label', 'Assessment 33% complete');
  });

  it('should round progress to nearest integer', () => {
    render(<ProgressIndicator progress={45.7} />);
    expect(screen.getByText('46%')).toBeInTheDocument();
  });

  it('should display 100% for complete assessment', () => {
    render(<ProgressIndicator progress={100} />);
    expect(screen.getByText('100%')).toBeInTheDocument();
  });
});
